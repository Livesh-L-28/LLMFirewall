"""Schema validation and size limits for agent tool arguments."""

import json
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity, ThreatType

DEFAULT_MAX_STRING_LENGTH: int = 100_000       # 100 KB max string
DEFAULT_MAX_OBJECT_DEPTH: int = 10             # Depth limit against recursion/DoS
DEFAULT_MAX_ARRAY_LENGTH: int = 1_000          # 1000 items in list
DEFAULT_MAX_TOTAL_SERIALIZED_BYTES: int = 1_000_000  # 1 MB serialized payload


class ArgumentLimits(BaseModel):
    """Configurable boundaries for tool argument size and complexity."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_string_length: int = Field(default=DEFAULT_MAX_STRING_LENGTH, ge=1)
    max_object_depth: int = Field(default=DEFAULT_MAX_OBJECT_DEPTH, ge=1)
    max_array_length: int = Field(default=DEFAULT_MAX_ARRAY_LENGTH, ge=1)
    max_total_bytes: int = Field(default=DEFAULT_MAX_TOTAL_SERIALIZED_BYTES, ge=1)


def check_argument_depth(val: Any, current_depth: int = 0) -> int:
    """Calculate maximum nesting depth of an object."""
    if isinstance(val, dict):
        if not val:
            return current_depth + 1
        return max(check_argument_depth(v, current_depth + 1) for v in val.values())
    elif isinstance(val, (list, tuple, set)):
        if not val:
            return current_depth + 1
        return max(check_argument_depth(item, current_depth + 1) for item in val)
    return current_depth


def validate_argument_limits(
    arguments: Dict[str, Any],
    limits: Optional[ArgumentLimits] = None,
) -> Optional[Finding]:
    """Inspect arguments against configured size and depth boundaries."""
    eff_limits = limits or ArgumentLimits()

    # 1. Total serialized payload size
    try:
        serialized = json.dumps(arguments, ensure_ascii=False)
        byte_len = len(serialized.encode("utf-8"))
        if byte_len > eff_limits.max_total_bytes:
            return Finding(
                detector_name="argument_validator",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=(
                    f"Tool arguments size ({byte_len} bytes) exceeds maximum "
                    f"allowed limit ({eff_limits.max_total_bytes} bytes)."
                ),
                severity=Severity.HIGH,
                confidence=1.0,
                metadata={"byte_len": byte_len, "max_bytes": eff_limits.max_total_bytes},
            )
    except Exception:
        pass

    # 2. Nesting depth limit
    depth = check_argument_depth(arguments)
    if depth > eff_limits.max_object_depth:
        return Finding(
            detector_name="argument_validator",
            threat_type=ThreatType.POLICY_VIOLATION,
            description=(
                f"Tool arguments nesting depth ({depth}) exceeds maximum "
                f"allowed depth ({eff_limits.max_object_depth})."
            ),
            severity=Severity.HIGH,
            confidence=1.0,
            metadata={"depth": depth, "max_depth": eff_limits.max_object_depth},
        )

    # 3. Individual string length and array length traversal
    def _traverse(item: Any, path: str = "") -> Optional[Finding]:
        if isinstance(item, str):
            if len(item) > eff_limits.max_string_length:
                return Finding(
                    detector_name="argument_validator",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=(
                        f"Argument '{path}' string length ({len(item)}) exceeds "
                        f"limit ({eff_limits.max_string_length})."
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"path": path, "length": len(item), "max_length": eff_limits.max_string_length},
                )
        elif isinstance(item, (list, tuple)):
            if len(item) > eff_limits.max_array_length:
                return Finding(
                    detector_name="argument_validator",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=(
                        f"Argument array '{path}' length ({len(item)}) exceeds "
                        f"limit ({eff_limits.max_array_length})."
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"path": path, "length": len(item), "max_length": eff_limits.max_array_length},
                )
            for idx, elem in enumerate(item):
                res = _traverse(elem, f"{path}[{idx}]")
                if res:
                    return res
        elif isinstance(item, dict):
            for k, v in item.items():
                res = _traverse(v, f"{path}.{k}" if path else str(k))
                if res:
                    return res
        return None

    return _traverse(arguments)


def validate_json_schema(
    arguments: Dict[str, Any],
    schema: Dict[str, Any],
) -> Optional[Finding]:
    """Validate tool arguments against a standard JSON Schema if jsonschema is available.
    
    If jsonschema is not installed, performs basic required-property validation.
    """
    if not schema or not isinstance(schema, dict):
        return None

    try:
        import jsonschema  # type: ignore
        try:
            jsonschema.validate(instance=arguments, schema=schema)
            return None
        except jsonschema.ValidationError as err:
            return Finding(
                detector_name="schema_validator",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Tool arguments failed schema validation: {err.message}",
                severity=Severity.HIGH,
                confidence=1.0,
                metadata={"schema_error": str(err.message), "path": list(err.path)},
            )
    except ImportError:
        # Fallback: Basic top-level required properties check
        required_fields: List[str] = schema.get("required", [])
        for req in required_fields:
            if req not in arguments:
                return Finding(
                    detector_name="schema_validator",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Missing required argument: '{req}'.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"missing_field": req},
                )
    return None
