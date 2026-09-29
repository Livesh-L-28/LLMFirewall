"""CLI command handlers and execution logic for LLMFirewall."""

import json
import os
import sys
from typing import Any, Optional

from llmfirewall.cli.errors import (
    EXIT_ALLOWED,
    EXIT_BLOCKED,
    EXIT_SYSTEM_ERROR,
    EXIT_USAGE_ERROR,
)
from llmfirewall.cli.formatting import format_human_output, format_json_output
from llmfirewall.config.models import (
    AuditConfig,
    DetectorConfig,
    FirewallConfig,
    PIIConfig,
    PromptInjectionConfig,
    SecretConfig,
)
from llmfirewall.core.models import Action
from llmfirewall.firewall import Firewall
from llmfirewall.policy.config import Policy, PolicyValidationError

# Maximum allowed file/stdin inspection size: 5MB default
MAX_FILE_BYTES = 5 * 1024 * 1024


def handle_policy_validate(policy_file: str, json_mode: bool = False) -> int:
    """Validate a Policy-as-Code document (.json or .yaml)."""
    try:
        policy = Policy.from_file(policy_file)
        enabled_count = sum(1 for r in policy.rules if r.enabled)
        disabled_count = len(policy.rules) - enabled_count

        if json_mode:
            payload = {
                "valid": True,
                "policy": policy.name,
                "version": policy.version,
                "description": policy.description,
                "rules_count": len(policy.rules),
                "enabled_rules": enabled_count,
                "disabled_rules": disabled_count,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"Policy: {policy.name}")
            print(f"Version: {policy.version}")
            print("Status: VALID")
            print(f"Rules: {len(policy.rules)} (Enabled: {enabled_count}, Disabled: {disabled_count})")
        return EXIT_ALLOWED
    except PolicyValidationError as exc:
        if json_mode:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        else:
            print(f"Status: INVALID\nError: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except Exception as exc:
        print(f"Error reading policy file: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_policy_show(policy_file: str, json_mode: bool = False) -> int:
    """Display rules and details of a Policy-as-Code document."""
    try:
        policy = Policy.from_file(policy_file)
        if json_mode:
            print(policy.to_json())
        else:
            print(f"Policy: {policy.name} (v{policy.version})")
            if policy.description:
                print(f"Description: {policy.description}")
            print(f"Default Action: {policy.default_action.value.upper()}")
            print("\nRules:")
            for r in policy.rules:
                status = "ACTIVE" if r.enabled else "DISABLED"
                print(f"  • [{r.action.value.upper():<6}] {r.id:<24} priority={r.priority:<4} ({status})")
                if r.description:
                    print(f"             {r.description}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error showing policy file: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR


def handle_tool_check(
    name: str,
    arguments_input: str = "{}",
    policy_file: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Inspect and evaluate an agent tool call against security policy."""
    # 1. Parse arguments input (either raw JSON string or path to JSON file)
    args_dict = {}
    if arguments_input:
        if os.path.isfile(arguments_input):
            try:
                with open(arguments_input, "r", encoding="utf-8") as f:
                    args_dict = json.load(f)
            except Exception as exc:
                print(f"Error reading tool arguments file '{arguments_input}': {exc}", file=sys.stderr)
                return EXIT_USAGE_ERROR
        else:
            try:
                args_dict = json.loads(arguments_input)
            except Exception as exc:
                print(f"Error parsing tool arguments as JSON: {exc}", file=sys.stderr)
                return EXIT_USAGE_ERROR

    # 2. Load policy if specified
    explicit_policy = None
    if policy_file:
        try:
            explicit_policy = Policy.from_file(policy_file)
        except Exception as exc:
            print(f"Error loading policy file '{policy_file}': {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    # 3. Execute tool security evaluation
    try:
        firewall = Firewall(policy=explicit_policy)
        decision = firewall.check_tool_call(tool_call_or_name=name, arguments=args_dict)

        if json_mode:
            print(json.dumps(decision.safe_dict(), indent=2, sort_keys=True))
        else:
            print(f"Tool Call: {decision.tool_name}")
            print(f"Decision:  {decision.action.value.upper()}")
            print(f"Reason:    {decision.reason}")
            if decision.require_approval:
                print("Notice:    Requires human-in-the-loop approval before execution.")
            if decision.findings:
                print(f"Findings:  {len(decision.findings)} security finding(s)")
                for f in decision.findings:
                    print(f"  • [{f.severity.value.upper()}] ({f.detector_name}) {f.description}")
            if decision.triggered_rules:
                print(f"Matched Rules: {', '.join(decision.triggered_rules)}")

        if decision.action == Action.BLOCK:
            return EXIT_BLOCKED
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error inspecting tool call: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_eval_run(
    policy_file: Optional[str] = None,
    baseline_file: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    tag: Optional[str] = None,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Execute AI Security Evaluation suite and output formatted results."""
    from llmfirewall.eval import (
        AttackCategory,
        SecurityEvaluationEngine,
        format_human_report,
        format_json_report,
        format_junit_report,
        format_sarif_report,
    )
    from llmfirewall.core.models import Severity

    # Load custom policy if specified
    explicit_policy = None
    if policy_file:
        try:
            explicit_policy = Policy.from_file(policy_file)
        except Exception as exc:
            print(f"Error loading policy file '{policy_file}': {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    # Parse filters
    cat_filter = None
    if category:
        try:
            cat_filter = {AttackCategory(category.strip().lower())}
        except ValueError:
            valid_cats = [c.value for c in AttackCategory]
            print(f"Error: Unknown category '{category}'. Valid categories: {valid_cats}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    sev_filter = None
    if severity:
        try:
            sev_filter = {Severity(severity.strip().lower())}
        except ValueError:
            valid_sevs = [s.value for s in Severity]
            print(f"Error: Unknown severity '{severity}'. Valid severities: {valid_sevs}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    tag_filter = {tag.strip()} if tag else None

    # Run evaluation
    try:
        engine = SecurityEvaluationEngine(policy=explicit_policy)
        report = engine.run_suite(
            baseline_file=baseline_file,
            category_filter=cat_filter,
            severity_filter=sev_filter,
            tag_filter=tag_filter,
        )

        # Format output
        fmt = (format_type or "human").lower()
        if fmt == "json":
            out_str = format_json_report(report)
        elif fmt == "sarif":
            out_str = format_sarif_report(report)
        elif fmt == "junit":
            out_str = format_junit_report(report)
        else:
            out_str = format_human_report(report)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(out_str + "\n")
        else:
            print(out_str)

        # Exit code: 1 if failures or regressions detected, 0 if clean
        if report.metrics.failed_tests > 0 or report.regressions_detected:
            return EXIT_BLOCKED
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error executing security evaluation: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_eval_baseline(
    output_path: str = "baseline.json",
    policy_file: Optional[str] = None,
) -> int:
    """Generate and record a baseline JSON evaluation snapshot."""
    from llmfirewall.eval import SecurityEvaluationEngine, format_json_report

    explicit_policy = None
    if policy_file:
        try:
            explicit_policy = Policy.from_file(policy_file)
        except Exception as exc:
            print(f"Error loading policy file '{policy_file}': {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    try:
        engine = SecurityEvaluationEngine(policy=explicit_policy)
        report = engine.run_suite()
        json_content = format_json_report(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_content + "\n")
        print(f"Security baseline saved to '{output_path}' ({report.metrics.total_tests} tests recorded).")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error creating evaluation baseline: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_scan(
    text: Optional[str] = None,
    file_path: Optional[str] = None,
    use_stdin: bool = False,
    direction: str = "input",
    json_mode: bool = False,
    config_file: Optional[str] = None,
    policy_file: Optional[str] = None,
    dry_run: bool = False,
    disable_injection: bool = False,
    disable_pii: bool = False,
    disable_secrets: bool = False,
) -> int:
    """Execute the scan subcommand, returning standard exit code.
    
    Exit Code Contract:
      0 -> ALLOW, WARN, or REDACT (passed security guardrails)
      1 -> BLOCK (rejected by security policy)
      2 -> Usage / Input error (invalid options, file not found, mutually exclusive inputs)
      3 -> System / I/O error
    """
    # 1. Validate mutually exclusive input sources
    inputs_count = sum([bool(text), bool(file_path), bool(use_stdin)])
    if inputs_count == 0:
        print("Error: No input provided. Supply text, --file <path>, or --stdin.", file=sys.stderr)
        return EXIT_USAGE_ERROR
    if inputs_count > 1:
        print("Error: Ambiguous input. Choose exactly one of direct text, --file, or --stdin.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    # 2. Extract content from selected source
    content_to_scan: str = ""
    if text:
        content_to_scan = text
    elif file_path:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' does not exist.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        if os.path.isdir(file_path):
            print(f"Error: Path '{file_path}' is a directory, not a file.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_BYTES:
                print(f"Error: File size ({file_size} bytes) exceeds maximum limit ({MAX_FILE_BYTES} bytes).", file=sys.stderr)
                return EXIT_USAGE_ERROR
            with open(file_path, "r", encoding="utf-8") as f:
                content_to_scan = f.read()
        except UnicodeDecodeError:
            print(f"Error: File '{file_path}' contains non-UTF-8 binary or invalid encoding.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        except PermissionError:
            print(f"Error: Permission denied reading file '{file_path}'.", file=sys.stderr)
            return EXIT_SYSTEM_ERROR
        except Exception as exc:
            print(f"Error reading file '{file_path}': {exc}", file=sys.stderr)
            return EXIT_SYSTEM_ERROR
    elif use_stdin:
        if sys.stdin.isatty():
            print("Error: --stdin specified but no piped data detected on standard input.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        try:
            content_to_scan = sys.stdin.read(MAX_FILE_BYTES + 1)
            if len(content_to_scan) > MAX_FILE_BYTES:
                print(f"Error: Standard input exceeds maximum limit ({MAX_FILE_BYTES} bytes).", file=sys.stderr)
                return EXIT_USAGE_ERROR
        except Exception as exc:
            print(f"Error reading standard input: {exc}", file=sys.stderr)
            return EXIT_SYSTEM_ERROR

    # 3. Build or load FirewallConfig / Policy
    config = FirewallConfig()
    if config_file:
        if not os.path.exists(config_file):
            print(f"Error: Configuration file '{config_file}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        try:
            with open(config_file, "r", encoding="utf-8") as cf:
                data = json.load(cf)
            config = FirewallConfig(**data)
        except Exception as exc:
            print(f"Error parsing configuration file '{config_file}': {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    explicit_policy = None
    if policy_file:
        try:
            explicit_policy = Policy.from_file(policy_file)
        except Exception as exc:
            print(f"Error loading policy file '{policy_file}': {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    # Apply CLI detector overrides (CLI flags take precedence over config)
    if disable_injection or disable_pii or disable_secrets:
        updated_detectors = config.detectors.model_copy(
            update={
                "prompt_injection": PromptInjectionConfig(
                    enabled=False if disable_injection else config.detectors.prompt_injection.enabled
                ),
                "pii": PIIConfig(
                    enabled=False if disable_pii else config.detectors.pii.enabled
                ),
                "secrets": SecretConfig(
                    enabled=False if disable_secrets else config.detectors.secrets.enabled
                ),
            }
        )
        config = config.model_copy(update={"detectors": updated_detectors})

    # 4. Execute scan via Firewall orchestrator
    try:
        firewall = Firewall(config=config, policy=explicit_policy)
        scan_context = {"dry_run": dry_run}
        scan_result = firewall.check(
            text_or_request=content_to_scan,
            direction=direction,
            context=scan_context,
        )
    except Exception as exc:
        print(f"Error during firewall inspection: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    # 5. Output Formatting
    if json_mode:
        print(format_json_output(scan_result))
    else:
        print(format_human_output(scan_result))

    # 6. Exit code according to policy
    if scan_result.decision.action == Action.BLOCK:
        return EXIT_BLOCKED

    return EXIT_ALLOWED


def _get_configured_store(backend: str, storage_path: Optional[str]):
    from llmfirewall.observability.store import InMemoryEventStore, JSONLEventStore, SQLiteEventStore
    if backend == "sqlite":
        return SQLiteEventStore(db_path=storage_path or ".llmfirewall/events.db")
    elif backend == "jsonl":
        return JSONLEventStore(file_path=storage_path or ".llmfirewall/events.jsonl")
    return InMemoryEventStore()


def handle_observe_summary(
    backend: str = "sqlite",
    storage_path: Optional[str] = None,
    json_mode: bool = False,
    prometheus_mode: bool = False,
) -> int:
    """Display operational security telemetry and summary intelligence."""
    from llmfirewall.observability.exporters import export_prometheus_metrics
    from llmfirewall.observability.intelligence import SecurityIntelligenceEngine

    try:
        store = _get_configured_store(backend, storage_path)
        intel = SecurityIntelligenceEngine(store=store)
        summ = intel.summary()

        if prometheus_mode:
            print(export_prometheus_metrics(summ), end="")
        elif json_mode:
            print(json.dumps(summ, indent=2))
        else:
            print("========================================")
            print("    LLMFirewall Security Intelligence   ")
            print("========================================")
            print(f"Total Requests : {summ['total_requests']}")
            print(f"Allowed        : {summ['allows']}")
            print(f"Warned         : {summ['warns']}")
            print(f"Redacted       : {summ['redactions']}")
            print(f"Blocked        : {summ['blocks']} ({summ['block_rate_percent']}%)")
            print("----------------------------------------")
            print("Risk Distribution:")
            for k, v in summ["risk_distribution_percent"].items():
                print(f"  {k:<8}: {v}%")
            print("----------------------------------------")
            print(f"Latency P50    : {summ['latency'].get('p50_ms', 0.0)} ms")
            print(f"Latency P95    : {summ['latency'].get('p95_ms', 0.0)} ms")
            print(f"Latency Avg    : {summ['latency'].get('average_ms', 0.0)} ms")
            if summ["top_detectors"]:
                print("----------------------------------------")
                print("Top Triggered Detectors:")
                for det, count in summ["top_detectors"].items():
                    print(f"  {det}: {count}")
            if summ["top_tools"]:
                print("----------------------------------------")
                print("Top Invocations by Tool:")
                for tool, count in summ["top_tools"].items():
                    print(f"  {tool}: {count}")
            print("========================================")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error retrieving observability summary: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_observe_events(
    backend: str = "sqlite",
    storage_path: Optional[str] = None,
    action: Optional[str] = None,
    severity: Optional[str] = None,
    detector: Optional[str] = None,
    tool_name: Optional[str] = None,
    limit: int = 50,
    json_mode: bool = False,
) -> int:
    """List stored security events matching specified criteria."""
    from llmfirewall.core.models import Action as CoreAction
    from llmfirewall.observability.models import EventSeverity
    from llmfirewall.observability.store import EventFilter

    try:
        store = _get_configured_store(backend, storage_path)
        actions = [CoreAction(action.upper())] if action else None
        severities = [EventSeverity(severity.upper())] if severity else None

        flt = EventFilter(
            actions=actions,
            severities=severities,
            detector_name=detector,
            tool_name=tool_name,
            limit=limit,
        )
        events = store.query(flt)

        if json_mode:
            print(json.dumps([e.model_dump(mode="json") for e in events], indent=2))
        else:
            if not events:
                print("No security events found matching criteria.")
                return EXIT_ALLOWED

            print(f"{'TIMESTAMP (UTC)':<24} {'SEVERITY':<8} {'ACTION':<7} {'DETECTOR / TOOL':<22} {'REQUEST ID':<36}")
            print("-" * 105)
            for e in events:
                act = e.action.value if e.action else "-"
                det_or_tool = e.tool_name or e.detector_name or e.component
                ts_str = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                print(f"{ts_str:<24} {e.severity.value:<8} {act:<7} {det_or_tool:<22} {e.request_id:<36}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error querying security events: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_observe_trends(
    backend: str = "sqlite",
    storage_path: Optional[str] = None,
    window_hours: int = 24,
    json_mode: bool = False,
) -> int:
    """Display period-over-period trend analysis and observed changes."""
    from llmfirewall.observability.intelligence import SecurityIntelligenceEngine

    try:
        store = _get_configured_store(backend, storage_path)
        intel = SecurityIntelligenceEngine(store=store)
        trends = intel.trend_analysis(window_hours=window_hours)
        anomalies = intel.detect_anomalies()

        if json_mode:
            payload = {
                "trends": trends,
                "anomalies": [a.model_dump(mode="json") for a in anomalies],
            }
            print(json.dumps(payload, indent=2))
        else:
            print("========================================")
            print(f"   Security Trends ({window_hours}h vs previous {window_hours}h)   ")
            print("========================================")
            curr = trends["current_period"]
            prev = trends["previous_period"]
            deltas = trends["deltas_percent"]
            print(f"Total Requests : {curr['total']} vs {prev['total']} ({deltas['total_requests']:+}%)")
            print(f"Blocks         : {curr['blocks']} vs {prev['blocks']} ({deltas['blocks']:+}%)")
            print(f"Tool Blocks    : {curr['tool_blocks']} vs {prev['tool_blocks']} ({deltas['tool_blocks']:+}%)")
            print(f"Warnings       : {curr['warns']} vs {prev['warns']} ({deltas['warns']:+}%)")
            if anomalies:
                print("----------------------------------------")
                print("Observed Anomaly Signals:")
                for a in anomalies:
                    print(f"  [{a.severity.value}] {a.description}")
            else:
                print("----------------------------------------")
                print("Anomaly Signals: None (all metrics within normal baseline)")
            print("========================================")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error computing trends: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_observe_export(
    backend: str = "sqlite",
    storage_path: Optional[str] = None,
    output_path: Optional[str] = None,
    format_type: str = "json",
) -> int:
    """Export security events in structured JSON, JSONL, or CSV format."""
    from llmfirewall.observability.exporters import export_events_csv, export_events_json, export_events_jsonl
    from llmfirewall.observability.store import EventFilter

    try:
        store = _get_configured_store(backend, storage_path)
        events = store.query(EventFilter(limit=100000))

        if format_type == "csv":
            content = export_events_csv(events)
        elif format_type == "jsonl":
            content = export_events_jsonl(events)
        else:
            content = export_events_json(events, indent=2)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Successfully exported {len(events)} security events to '{output_path}'.")
        else:
            print(content)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error exporting events: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Runtime Command Handlers (Phase 26)
# -----------------------------------------------------------------------------

def handle_runtime_inspect(
    trace_id: Optional[str] = None,
    runtime_id: Optional[str] = None,
    backend: str = "sqlite",
    storage_path: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Inspect stored security events and decisions for an agent runtime session."""
    from llmfirewall.observability.store import EventFilter

    try:
        store = _get_configured_store(backend, storage_path)
        events = store.query(EventFilter(trace_id=trace_id, request_id=runtime_id, limit=500))

        if not events:
            if json_mode:
                print(json.dumps({"events": [], "count": 0, "message": "No events found for given filter"}, indent=2))
            else:
                print("No runtime events found matching query.")
            return EXIT_ALLOWED

        total_findings = sum(1 for e in events if e.threat_types or e.action == Action.BLOCK)
        blocked = any(e.action == Action.BLOCK for e in events)

        if json_mode:
            payload = {
                "trace_id": trace_id,
                "runtime_id": runtime_id,
                "events_count": len(events),
                "security_findings": total_findings,
                "final_action": Action.BLOCK.value if blocked else Action.ALLOW.value,
                "events": [e.model_dump(mode="json") for e in events],
            }
            print(json.dumps(payload, indent=2))
        else:
            print("========================================")
            print("Agent Runtime Session Inspection")
            print("========================================")
            print(f"Trace ID         : {trace_id or 'N/A'}")
            print(f"Runtime ID       : {runtime_id or 'N/A'}")
            print(f"Total Events     : {len(events)}")
            print(f"Security Findings: {total_findings}")
            print(f"Final Outcome    : {'BLOCKED' if blocked else 'ALLOWED'}")
            print("----------------------------------------")
            print("Event Sequence:")
            for ev in events:
                desc = ev.metadata.get("description", ev.event_type.value)
                act = ev.action.value.upper()
                print(f"  [{ev.timestamp.strftime('%H:%M:%S')}] {ev.event_type.value:25} | {act:7} | {desc}")
            print("========================================")

        return EXIT_BLOCKED if blocked else EXIT_ALLOWED
    except Exception as exc:
        print(f"Error inspecting runtime: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_runtime_simulate(
    user_input: str = "What is 2 + 2?",
    tool_name: Optional[str] = None,
    tool_args: str = "{}",
    policy_file: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Simulate complete agent runtime flow against active firewall and policy."""
    try:
        policy = Policy.from_file(policy_file) if policy_file else None
        fw = Firewall(policy=policy)
        session = fw.runtime_session(raise_on_block=False)

        # 1. User input
        in_dec = session.check_user_input(user_input)

        # 2. Tool call if requested
        tool_dec = None
        if tool_name and not in_dec.is_blocked:
            parsed_args = json.loads(tool_args) if tool_args else {}
            session.step_iteration()
            tool_dec = session.check_tool_call(tool_name, parsed_args)

        # 3. Final response
        final_dec = None
        if not (in_dec.is_blocked or (tool_dec and tool_dec.is_blocked)):
            final_dec = session.finalize("Simulated benign answer.")
        else:
            session.finalize()

        blocked = any(d.is_blocked for d in session.decisions) or (tool_dec and tool_dec.is_blocked)
        final_action = Action.BLOCK if blocked else Action.ALLOW

        if json_mode:
            payload = {
                "runtime_id": session.runtime_id,
                "trace_id": session.trace_id,
                "final_action": final_action.value,
                "decisions": [d.model_dump(mode="json") for d in session.decisions],
            }
            print(json.dumps(payload, indent=2))
        else:
            print("========================================")
            print("Runtime Guardrail Simulation")
            print("========================================")
            print(f"Runtime ID   : {session.runtime_id}")
            print(f"Final Action : {final_action.value.upper()}")
            print(f"User Input   : {in_dec.action.value.upper()} ({in_dec.reason})")
            if tool_dec:
                print(f"Tool Call    : {tool_dec.action.value.upper()} ({tool_dec.reason})")
            print("========================================")

        return EXIT_BLOCKED if blocked else EXIT_ALLOWED
    except Exception as exc:
        print(f"Error simulating runtime: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# RAG Command Handlers (Phase 27)
# -----------------------------------------------------------------------------

def handle_rag_scan(
    document_path: str,
    doc_id: Optional[str] = None,
    policy_file: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Scan a document file for security issues prior to knowledge ingestion."""
    from pathlib import Path
    from llmfirewall.rag.models import DocumentSecurityStatus

    path_obj = Path(document_path)
    if not path_obj.exists():
        print(f"Error: Document file not found: '{document_path}'", file=sys.stderr)
        return EXIT_USAGE_ERROR

    try:
        content = path_obj.read_text(encoding="utf-8")
        policy = Policy.from_file(policy_file) if policy_file else None
        fw = Firewall(policy=policy)

        effective_id = doc_id or path_obj.name
        scan_res = fw.ingestion_scanner.scan_document(content=content, document_id=effective_id)

        blocked = scan_res.status in (DocumentSecurityStatus.QUARANTINED, DocumentSecurityStatus.BLOCKED)

        if json_mode:
            print(json.dumps(scan_res.model_dump(mode="json"), indent=2))
        else:
            print("========================================")
            print("Document Security Ingestion Report")
            print("========================================")
            print(f"Document ID : {scan_res.document_id}")
            print(f"Status      : {scan_res.status.value.upper()}")
            print(f"Action      : {scan_res.action.value.upper()}")
            print(f"Findings    : {len(scan_res.findings)}")
            if scan_res.quarantine_reason:
                print(f"Quarantine  : {scan_res.quarantine_reason}")
            if scan_res.findings:
                print("----------------------------------------")
                print("Detected Findings:")
                for f in scan_res.findings:
                    print(f"  - [{f.severity.value.upper()}] {f.threat_type.value}: {f.description}")
            print("========================================")

        return EXIT_BLOCKED if blocked else EXIT_ALLOWED
    except Exception as exc:
        print(f"Error scanning document: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_rag_inspect_context(
    context_file: str,
    policy_file: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Inspect and filter a JSON list of retrieved context items."""
    from pathlib import Path

    path_obj = Path(context_file)
    if not path_obj.exists():
        print(f"Error: Context file not found: '{context_file}'", file=sys.stderr)
        return EXIT_USAGE_ERROR

    try:
        raw_data = json.loads(path_obj.read_text(encoding="utf-8"))
        if not isinstance(raw_data, list):
            print("Error: Context file must contain a JSON array of chunk objects or strings", file=sys.stderr)
            return EXIT_USAGE_ERROR

        policy = Policy.from_file(policy_file) if policy_file else None
        fw = Firewall(policy=policy)

        decision = fw.context_orchestrator.filter_and_secure(raw_data)
        blocked = decision.is_blocked

        if json_mode:
            print(json.dumps(decision.model_dump(mode="json"), indent=2))
        else:
            print("========================================")
            print("RAG Context Security Inspection")
            print("========================================")
            print(f"Total Items   : {len(raw_data)}")
            print(f"Approved      : {len(decision.approved_items)}")
            print(f"Filtered      : {len(decision.filtered_items)}")
            print(f"Quarantined   : {len(decision.quarantined_items)}")
            print(f"Final Action  : {decision.action.value.upper()}")
            print(f"Conflict      : {'YES' if decision.conflict_detected else 'NO'}")
            print(f"Budget Exceed : {'YES' if decision.budget_exceeded else 'NO'}")
            print("========================================")

        return EXIT_BLOCKED if blocked else EXIT_ALLOWED
    except Exception as exc:
        print(f"Error inspecting context: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Supply-Chain & Model Security CLI Handlers (Phase 28)
# -----------------------------------------------------------------------------

def handle_model_verify(
    file_path: str,
    sha256: Optional[str] = None,
    sha512: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Verify cryptographic hash and format of a model file."""
    from llmfirewall.supply_chain.verifier import ModelVerifier, detect_model_format
    from pathlib import Path

    p = Path(file_path)
    if not p.exists():
        print(f"Error: Model file '{file_path}' not found.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    algo = "sha512" if sha512 else "sha256"
    expected = sha512 if sha512 else sha256

    verifier = ModelVerifier()
    res = verifier.verify_artifact(path=p, expected_hash=expected, algorithm=algo)
    fmt = detect_model_format(p)

    passed = (res.status.value == "MATCH") or (expected is None and res.status.value == "UNAVAILABLE")

    if json_mode:
        payload = {
            "file": str(p),
            "format": fmt.value,
            "status": res.status.value,
            "algorithm": res.algorithm,
            "expected_hash": res.expected_hash,
            "actual_hash": res.actual_hash,
            "passed": passed,
            "details": res.details,
        }
        print(json.dumps(payload, indent=2))
    else:
        status_label = "PASS" if res.status.value == "MATCH" else ("FAIL" if res.status.value == "MISMATCH" else res.status.value)
        print("========================================")
        print("Model Artifact Verification")
        print("========================================")
        print(f"File      : {p.name}")
        print(f"Format    : {fmt.value}")
        print(f"Algorithm : {res.algorithm.upper()}")
        print(f"Status    : {status_label}")
        if res.expected_hash:
            print(f"Expected  : {res.expected_hash}")
        if res.actual_hash:
            print(f"Actual    : {res.actual_hash}")
        if res.details:
            print(f"Details   : {res.details}")
        print("========================================")

    return EXIT_ALLOWED if (passed and res.status.value != "MISMATCH") else EXIT_BLOCKED


def handle_supply_chain_scan(
    policy_file: Optional[str] = None,
    manifest_file: Optional[str] = None,
    offline: bool = True,
    json_mode: bool = False,
) -> int:
    """Perform dependency inventory, manifest validation, and policy checks."""
    from llmfirewall.supply_chain.dependencies import DependencyScanner
    from llmfirewall.supply_chain.manifest import ModelManifest
    from llmfirewall.supply_chain.verifier import ModelVerifier

    scanner = DependencyScanner()
    deps = scanner.scan_environment()
    dep_findings = scanner.evaluate_dependencies(deps)

    manifest_models = []
    manifest_findings = []
    if manifest_file:
        try:
            manifest = ModelManifest.load_from_file(manifest_file)
            verifier = ModelVerifier()
            for m in manifest.models.values():
                manifest_models.append(m)
                dec = verifier.evaluate_model(m)
                manifest_findings.extend(dec.findings)
        except Exception as exc:
            print(f"Error loading manifest: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    all_findings = dep_findings + manifest_findings
    has_block = any(f.severity.value in ("critical", "high") for f in all_findings)

    if json_mode:
        payload = {
            "mode": "offline" if offline else "online",
            "dependencies_count": len(deps),
            "manifest_models_count": len(manifest_models),
            "findings_count": len(all_findings),
            "findings": [f.model_dump(mode="json") for f in all_findings],
            "action": "BLOCK" if has_block else "ALLOW",
        }
        print(json.dumps(payload, indent=2))
    else:
        print("========================================")
        print("AI Supply-Chain Security Scan")
        print("========================================")
        print(f"Mode                : {'Offline' if offline else 'Online'}")
        print(f"Packages Scanned    : {len(deps)}")
        print(f"Models in Manifest  : {len(manifest_models)}")
        print(f"Total Findings      : {len(all_findings)}")
        print(f"Overall Decision    : {'BLOCK' if has_block else 'ALLOW'}")
        if all_findings:
            print("----------------------------------------")
            for f in all_findings:
                print(f"  - [{f.severity.value.upper()}] {f.description}")
        print("========================================")

    return EXIT_BLOCKED if has_block else EXIT_ALLOWED


def handle_supply_chain_dependencies(
    format_type: str = "json",
    json_mode: bool = False,
) -> int:
    """List normalized dependency inventory."""
    from llmfirewall.supply_chain.dependencies import DependencyScanner
    scanner = DependencyScanner()
    deps = scanner.scan_environment()

    payload = [d.model_dump(mode="json") for d in deps]
    if json_mode or format_type == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"{'Package':<30} {'Version':<15} {'Scope':<12} {'Source':<15}")
        print("-" * 75)
        for d in deps:
            print(f"{d.name:<30} {d.version:<15} {d.scope.value:<12} {d.source.value:<15}")

    return EXIT_ALLOWED


def handle_supply_chain_sbom(
    format_type: str = "cyclonedx",
    output_path: Optional[str] = None,
) -> int:
    """Generate CycloneDX or normalized SBOM."""
    from llmfirewall.supply_chain.dependencies import DependencyScanner
    scanner = DependencyScanner()
    sbom = scanner.generate_sbom(format_type=format_type)

    serialized = json.dumps(sbom, indent=2)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"SBOM written successfully to {output_path}")
    else:
        print(serialized)

    return EXIT_ALLOWED


def handle_supply_chain_snapshot(
    output_path: Optional[str] = None,
    json_mode: bool = True,
) -> int:
    """Generate an AI Security Snapshot."""
    fw = Firewall()
    snapshot = fw.create_security_snapshot()
    serialized = json.dumps(snapshot.model_dump(mode="json"), indent=2)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"Security snapshot written to {output_path}")
    else:
        print(serialized)

    return EXIT_ALLOWED


def handle_supply_chain_diff(
    snapshot_a_path: str,
    snapshot_b_path: str,
    json_mode: bool = False,
) -> int:
    """Diff two SecuritySnapshot files to detect drift."""
    from llmfirewall.supply_chain.models import SecuritySnapshot
    from pathlib import Path

    pa = Path(snapshot_a_path)
    pb = Path(snapshot_b_path)
    if not pa.exists() or not pb.exists():
        print("Error: One or both snapshot files could not be found.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    snap_a = SecuritySnapshot.model_validate_json(pa.read_text(encoding="utf-8"))
    snap_b = SecuritySnapshot.model_validate_json(pb.read_text(encoding="utf-8"))

    diff = snap_a.diff(snap_b)

    if json_mode:
        print(json.dumps(diff.model_dump(mode="json"), indent=2))
    else:
        print("========================================")
        print("Security Snapshot Comparison")
        print("========================================")
        print(f"Identical           : {'YES' if diff.is_identical else 'NO'}")
        print(f"Models Added        : {len(diff.models_added)} ({', '.join(diff.models_added) or 'none'})")
        print(f"Models Removed      : {len(diff.models_removed)} ({', '.join(diff.models_removed) or 'none'})")
        print(f"Models Changed      : {len(diff.models_changed)} ({', '.join(diff.models_changed) or 'none'})")
        print(f"Dependencies Added  : {len(diff.dependencies_added)}")
        print(f"Dependencies Removed: {len(diff.dependencies_removed)}")
        print(f"Dependencies Changed: {len(diff.dependencies_changed)}")
        print(f"Configs Changed     : {len(diff.configs_changed)} ({', '.join(diff.configs_changed) or 'none'})")
        print(f"Policies Changed    : {len(diff.policies_changed)} ({', '.join(diff.policies_changed) or 'none'})")
        print(f"Prompts Changed     : {len(diff.prompts_changed)} ({', '.join(diff.prompts_changed) or 'none'})")
        print("========================================")

    return EXIT_ALLOWED


# -----------------------------------------------------------------------------
# Agent Capability Security & Action Control CLI Handlers (Phase 29)
# -----------------------------------------------------------------------------

def handle_agent_capabilities(
    json_mode: bool = False,
) -> int:
    """List standard capabilities and action classifications."""
    from llmfirewall.capabilities.engine import DEFAULT_CAPABILITIES

    if json_mode:
        payload = [c.model_dump(mode="json") for c in DEFAULT_CAPABILITIES.values()]
        print(json.dumps(payload, indent=2))
    else:
        print("========================================")
        print("Standard Agent Security Capabilities")
        print("========================================")
        print(f"{'Capability':<22} {'Action':<12} {'Risk':<10} {'Approval':<10} {'Description'}")
        print("-" * 80)
        for c in DEFAULT_CAPABILITIES.values():
            appr = "Required" if c.requires_approval else "Auto"
            print(f"{c.name:<22} {c.action.value:<12} {c.risk_class.value:<10} {appr:<10} {c.description}")
        print("========================================")

    return EXIT_ALLOWED


def handle_agent_policy_check(
    capability_name: str,
    agent_id: str = "default_agent",
    resource: Optional[str] = None,
    tool_name: str = "custom_tool",
    grant_capability: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Simulate capability authorization check for an agent action request."""
    from llmfirewall.firewall import Firewall
    from llmfirewall.capabilities.models import ActionDecisionStatus

    fw = Firewall()
    if grant_capability:
        fw.capability_engine.grant_capability(agent_id, grant_capability)

    decision = fw.authorize_action(
        capability_name=capability_name,
        agent_id=agent_id,
        tool_name=tool_name,
        resource=resource,
    )

    if json_mode:
        print(json.dumps(decision.model_dump(mode="json"), indent=2))
    else:
        print("========================================")
        print("Agent Capability Authorization Check")
        print("========================================")
        print(f"Agent ID    : {decision.agent_id}")
        print(f"Capability  : {decision.capability_name}")
        print(f"Resource    : {decision.resource or 'N/A'}")
        print(f"Decision    : {decision.decision.value}")
        print(f"Reason      : {decision.reason}")
        if decision.findings:
            print("----------------------------------------")
            print("Findings:")
            for f in decision.findings:
                print(f"  - [{f.severity.value.upper()}] {f.description}")
        print("========================================")

    return EXIT_ALLOWED if decision.decision == ActionDecisionStatus.ALLOW else EXIT_BLOCKED


# =====================================================================
# Phase 30: Continuous AI Security Testing CLI Handlers
# =====================================================================

def handle_test_security(
    suite: str = "core",
    ci: bool = False,
    format_type: str = "human",
    output_file: Optional[str] = None,
    workers: int = 1,
    seed: Optional[int] = None,
    baseline_file: Optional[str] = None,
    target_type: str = "firewall",
    endpoint: Optional[str] = None,
    policy_file: Optional[str] = None,
) -> int:
    """Execute AI security test suite and red-team engine."""
    from llmfirewall.eval import (
        BUILTIN_SUITES,
        FirewallAdapter,
        HTTPTargetAdapter,
        MockAdapter,
        TestOrchestrator,
        format_html_report,
        format_human_report,
        format_json_report,
        format_junit_report,
        format_sarif_report,
        get_core_firewall_suite,
    )
    from llmfirewall.firewall import Firewall
    from llmfirewall.policy.config import Policy

    # 1. Resolve Policy
    explicit_policy = None
    if policy_file:
        try:
            explicit_policy = Policy.from_file(policy_file)
        except Exception as exc:
            print(f"Error loading policy file '{policy_file}': {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    # 2. Resolve Target
    ttype = (target_type or "firewall").lower()
    if ttype == "mock":
        target = MockAdapter()
    elif ttype == "http":
        if not endpoint:
            print("Error: --endpoint URL required when target is 'http'", file=sys.stderr)
            return EXIT_USAGE_ERROR
        target = HTTPTargetAdapter(endpoint=endpoint)
    else:
        fw = Firewall(policy=explicit_policy)
        target = FirewallAdapter(fw)

    # 3. Resolve Suite
    suite_key = (suite or "core").lower().replace("_", "-")
    if suite_key in BUILTIN_SUITES:
        selected_suite = BUILTIN_SUITES[suite_key]()
    else:
        selected_suite = get_core_firewall_suite()

    try:
        orchestrator = TestOrchestrator(target=target)
        report = orchestrator.run_suite(
            suite=selected_suite,
            workers=workers,
            seed=seed,
            baseline_file=baseline_file,
        )

        fmt = (format_type or "human").lower()
        if fmt == "json":
            out_str = format_json_report(report)
        elif fmt == "sarif":
            out_str = format_sarif_report(report)
        elif fmt == "junit":
            out_str = format_junit_report(report)
        elif fmt == "html":
            out_str = format_html_report(report)
        else:
            out_str = format_human_report(report)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(out_str + "\n")
            print(f"Security test report written to: {output_file}")
        else:
            print(out_str)

        # CI Exit Code Contract:
        # 0 = All passed, 1 = Security test failure or regression detected
        if report.metrics.failed_tests > 0 or report.regressions_detected:
            return EXIT_BLOCKED
        return EXIT_ALLOWED

    except Exception as exc:
        print(f"Error executing security test suite: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_test_list(
    suite_name: Optional[str] = None,
    category: Optional[str] = None,
    tag: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Discover and list security test definitions."""
    from llmfirewall.eval import BUILTIN_SUITES, get_full_red_team_suite

    suite_key = (suite_name or "all").lower().replace("_", "-")
    if suite_key in BUILTIN_SUITES:
        suite = BUILTIN_SUITES[suite_key]()
    else:
        suite = get_full_red_team_suite()

    tests = suite.tests
    if category:
        cat_clean = category.lower().replace("-", "_")
        tests = [t for t in tests if t.category.value == cat_clean]
    if tag:
        tests = [t for t in tests if tag in t.tags]

    if json_mode:
        data = [
            {
                "id": t.id,
                "name": t.name,
                "category": t.category.value,
                "target_type": t.target_type.value,
                "severity": t.severity.value,
                "tags": t.tags,
                "description": t.description,
                "requires_network": t.requires_network,
            }
            for t in tests
        ]
        print(json.dumps(data, indent=2))
    else:
        print("=" * 72)
        print(f" LLMFirewall Security Tests ({len(tests)} available)")
        print("=" * 72)
        print(f"{'Test ID':<12} {'Category':<22} {'Severity':<10} {'Name':<26}")
        print("-" * 72)
        for t in tests:
            print(f"{t.id:<12} {t.category.value:<22} {t.severity.value.upper():<10} {t.name[:25]:<26}")
        print("=" * 72)

    return EXIT_ALLOWED


def handle_test_suites(json_mode: bool = False) -> int:
    """List available pre-built security test suites."""
    from llmfirewall.eval import BUILTIN_SUITES

    suites_info = []
    for key, factory in BUILTIN_SUITES.items():
        s = factory()
        suites_info.append({
            "name": s.name,
            "version": s.version,
            "tests_count": len(s.tests),
            "description": s.description,
        })

    if json_mode:
        print(json.dumps(suites_info, indent=2))
    else:
        print("=" * 72)
        print(" LLMFirewall Pre-Built Security Test Suites")
        print("=" * 72)
        print(f"{'Suite Name':<24} {'Tests':<8} {'Description'}")
        print("-" * 72)
        for info in suites_info:
            print(f"{info['name']:<24} {info['tests_count']:<8} {info['description']}")
        print("=" * 72)

    return EXIT_ALLOWED


def handle_test_run(
    test_id: Optional[str] = None,
    category: Optional[str] = None,
    tag: Optional[str] = None,
    workers: int = 1,
    format_type: str = "human",
    target_type: str = "firewall",
    endpoint: Optional[str] = None,
    policy_file: Optional[str] = None,
) -> int:
    """Execute a single test or filtered subset of security tests."""
    from llmfirewall.eval import (
        FirewallAdapter,
        HTTPTargetAdapter,
        MockAdapter,
        TestOrchestrator,
        format_html_report,
        format_human_report,
        format_json_report,
        get_full_red_team_suite,
    )
    from llmfirewall.firewall import Firewall
    from llmfirewall.policy.config import Policy

    # 1. Resolve Target
    ttype = (target_type or "firewall").lower()
    if ttype == "mock":
        target = MockAdapter()
    elif ttype == "http":
        if not endpoint:
            print("Error: --endpoint URL required when target is 'http'", file=sys.stderr)
            return EXIT_USAGE_ERROR
        target = HTTPTargetAdapter(endpoint=endpoint)
    else:
        explicit_policy = Policy.from_file(policy_file) if policy_file else None
        target = FirewallAdapter(Firewall(policy=explicit_policy))

    # 2. Resolve Tests
    full_suite = get_full_red_team_suite()
    selected_tests = full_suite.tests

    if test_id:
        selected_tests = [t for t in selected_tests if t.id == test_id]
        if not selected_tests:
            print(f"Error: Test ID '{test_id}' not found in registered test suites.", file=sys.stderr)
            return EXIT_USAGE_ERROR

    if category:
        cat_clean = category.lower().replace("-", "_")
        selected_tests = [t for t in selected_tests if t.category.value == cat_clean]

    if tag:
        selected_tests = [t for t in selected_tests if tag in t.tags]

    try:
        orchestrator = TestOrchestrator(target=target)
        report = orchestrator.run_suite(
            test_cases=selected_tests,
            suite_name=f"targeted-run-{test_id or 'filtered'}",
            workers=workers,
        )

        fmt = (format_type or "human").lower()
        if fmt == "json":
            print(format_json_report(report))
        elif fmt == "html":
            print(format_html_report(report))
        else:
            print(format_human_report(report))

        if report.metrics.failed_tests > 0:
            return EXIT_BLOCKED
        return EXIT_ALLOWED

    except Exception as exc:
        print(f"Error running test: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_governance_gate(
    policy_file: Optional[str] = None,
    ci: bool = False,
    baseline_file: Optional[str] = None,
    results_file: Optional[str] = None,
    snapshot_file: Optional[str] = None,
    changed: bool = False,
    offline: bool = False,
    format_type: str = "human",
    output_file: Optional[str] = None,
    override_reason: Optional[str] = None,
    override_owner: Optional[str] = None,
) -> int:
    """Evaluate a release candidate against security governance policy and release gates."""
    from pathlib import Path
    import time
    from llmfirewall.governance.decisions import GovernanceDecision
    from llmfirewall.governance.engine import GovernanceEngine, GovernanceOverride
    from llmfirewall.governance.evidence import SecurityEvidence
    from llmfirewall.governance.baseline import SecurityBaseline
    from llmfirewall.governance.policy import GovernancePolicy
    from llmfirewall.governance.reporting import (
        format_governance_human,
        format_governance_json,
        format_governance_sarif,
    )
    from llmfirewall.eval.models import SecurityEvaluationReport, SecurityTestResult
    from llmfirewall.supply_chain.models import SecuritySnapshot

    try:
        # 1. Load Policy
        if policy_file:
            p_path = Path(policy_file).resolve()
            if not p_path.exists():
                print(f"Error: Policy file not found: {policy_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR
            policy = GovernancePolicy.from_file(str(p_path))
        else:
            policy = GovernancePolicy.default_production_policy()

        # 2. Load Baseline if provided
        baseline: Optional[SecurityBaseline] = None
        if baseline_file:
            b_path = Path(baseline_file).resolve()
            if not b_path.exists():
                print(f"Error: Baseline file not found: {baseline_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR
            baseline = SecurityBaseline.from_json(b_path.read_text(encoding="utf-8"))

        # 3. Load Evidence components
        eval_report: Optional[SecurityEvaluationReport] = None
        test_results: list[SecurityTestResult] = []
        if results_file:
            r_path = Path(results_file).resolve()
            if not r_path.exists():
                print(f"Error: Results file not found: {results_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR
            data = json.loads(r_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "suite_name" in data:
                eval_report = SecurityEvaluationReport(**data)
            elif isinstance(data, list):
                test_results = [SecurityTestResult(**t) for t in data]

        snapshot: Optional[SecuritySnapshot] = None
        if snapshot_file:
            s_path = Path(snapshot_file).resolve()
            if not s_path.exists():
                print(f"Error: Snapshot file not found: {snapshot_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR
            snapshot = SecuritySnapshot(**json.loads(s_path.read_text(encoding="utf-8")))

        evidence = SecurityEvidence(
            release_id=f"REL-{int(time.time())}",
            evaluation_report=eval_report,
            test_results=test_results,
            snapshot=snapshot,
            policy_version=policy.version,
            configuration_hash=snapshot.configurations[0].sha256 if (snapshot and snapshot.configurations) else None,
            dependency_hash=snapshot.snapshot_hash if snapshot else None,
        )

        # 4. Handle Override
        override: Optional[GovernanceOverride] = None
        if override_reason and override_owner:
            override = GovernanceOverride(
                owner=override_owner,
                reason=override_reason,
                emergency=True,
            )

        # 5. Evaluate
        engine = GovernanceEngine()
        result = engine.evaluate(
            evidence=evidence,
            policy=policy,
            baseline=baseline,
            override=override,
        )

        # 6. Format Output
        fmt = (format_type or "human").lower()
        if fmt == "json":
            output_content = format_governance_json(result)
        elif fmt == "sarif":
            output_content = json.dumps(format_governance_sarif(result), indent=2)
        else:
            output_content = format_governance_human(result)

        if output_file:
            Path(output_file).resolve().write_text(output_content, encoding="utf-8")
        else:
            print(output_content)

        # 7. Exit Code Determination
        if result.passed:
            return EXIT_ALLOWED
        if ci:
            return EXIT_BLOCKED
        if result.decision in (GovernanceDecision.BLOCK, GovernanceDecision.FAIL):
            return EXIT_BLOCKED
        return EXIT_ALLOWED

    except Exception as exc:
        print(f"Error evaluating governance gate: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_baseline_create(
    output_path: str,
    baseline_id: Optional[str] = None,
    results_file: Optional[str] = None,
    snapshot_file: Optional[str] = None,
    policy_file: Optional[str] = None,
    json_mode: bool = False,
) -> int:
    """Create a cryptographically anchored security baseline."""
    from pathlib import Path
    from llmfirewall.governance.baseline import SecurityBaseline
    from llmfirewall.governance.findings import GovernanceFinding
    from llmfirewall.supply_chain.models import SecuritySnapshot

    try:
        findings: list[GovernanceFinding] = []
        test_cfg: dict = {}

        if results_file:
            r_path = Path(results_file).resolve()
            if not r_path.exists():
                print(f"Error: Results file not found: {results_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR
            raw_res = json.loads(r_path.read_text(encoding="utf-8"))
            if isinstance(raw_res, dict) and "findings" in raw_res:
                for f in raw_res["findings"]:
                    findings.append(GovernanceFinding.from_test_finding(
                        category=f.get("category", "general"),
                        description=f.get("description", ""),
                        severity=f.get("severity", "medium"),
                        test_id=f.get("test_id"),
                    ))
                test_cfg = {
                    "suite_name": raw_res.get("suite_name", ""),
                    "suite_version": raw_res.get("suite_version", ""),
                    "pass_rate": raw_res.get("metrics", {}).get("pass_rate", 1.0),
                }

        cfg_hash = ""
        dep_state = {}
        if snapshot_file:
            s_path = Path(snapshot_file).resolve()
            if not s_path.exists():
                print(f"Error: Snapshot file not found: {snapshot_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR
            snap = SecuritySnapshot(**json.loads(s_path.read_text(encoding="utf-8")))
            dep_state = {"hash": snap.snapshot_hash, "dependency_count": len(snap.dependencies)}
            if snap.configurations:
                cfg_hash = snap.configurations[0].sha256

        pol_ver = "1.0"
        if policy_file:
            p_path = Path(policy_file).resolve()
            if p_path.exists():
                pol_raw = json.loads(p_path.read_text(encoding="utf-8")) if p_path.suffix == ".json" else {}
                pol_ver = pol_raw.get("version", "1.0")

        baseline = SecurityBaseline.create(
            baseline_id=baseline_id,
            test_configuration=test_cfg,
            policy_version=pol_ver,
            configuration_hash=cfg_hash,
            dependency_state=dep_state,
            findings=findings,
        )

        out_file = Path(output_path).resolve()
        out_file.write_text(baseline.to_json(), encoding="utf-8")

        if json_mode:
            print(json.dumps({
                "status": "created",
                "baseline_id": baseline.baseline_id,
                "output": str(out_file),
                "integrity_hash": baseline.integrity_hash,
                "findings_count": len(findings),
            }, indent=2))
        else:
            print("Security baseline created successfully:")
            print(f"  ID: {baseline.baseline_id}")
            print(f"  Output: {out_file}")
            print(f"  SHA-256 Integrity Digest: {baseline.integrity_hash}")
            print(f"  Findings Indexed: {len(findings)}")

        return EXIT_ALLOWED

    except Exception as exc:
        print(f"Error creating security baseline: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_baseline_compare(
    current_file: str,
    baseline_file: str,
    json_mode: bool = False,
) -> int:
    """Compare current evaluation or findings against a security baseline."""
    from pathlib import Path
    from llmfirewall.governance.baseline import SecurityBaseline
    from llmfirewall.governance.findings import GovernanceFinding

    try:
        b_path = Path(baseline_file).resolve()
        if not b_path.exists():
            print(f"Error: Baseline file not found: {baseline_file}", file=sys.stderr)
            return EXIT_USAGE_ERROR

        baseline = SecurityBaseline.from_json(b_path.read_text(encoding="utf-8"))
        if not baseline.verify_integrity():
            print("CRITICAL: Security baseline failed SHA-256 integrity verification (tampered).", file=sys.stderr)
            return EXIT_BLOCKED

        c_path = Path(current_file).resolve()
        if not c_path.exists():
            print(f"Error: Current file not found: {current_file}", file=sys.stderr)
            return EXIT_USAGE_ERROR

        raw_curr = json.loads(c_path.read_text(encoding="utf-8"))
        curr_findings: list[GovernanceFinding] = []
        if isinstance(raw_curr, dict) and "findings" in raw_curr:
            for f in raw_curr["findings"]:
                curr_findings.append(GovernanceFinding.from_test_finding(
                    category=f.get("category", "general"),
                    description=f.get("description", ""),
                    severity=f.get("severity", "medium"),
                    test_id=f.get("test_id"),
                ))
        elif isinstance(raw_curr, list):
            for f in raw_curr:
                curr_findings.append(GovernanceFinding.from_test_finding(
                    category=f.get("category", "general"),
                    description=f.get("description", ""),
                    severity=f.get("severity", "medium"),
                    test_id=f.get("test_id"),
                ))

        diff = baseline.compare_findings(curr_findings)

        if json_mode:
            print(json.dumps(diff.summary(), indent=2, sort_keys=True))
        else:
            print("=" * 60)
            print(f" Security Baseline Comparison: {baseline.baseline_id}")
            print("=" * 60)
            print(f" Identical: {diff.is_identical}")
            print(f" New Findings: {len(diff.new_findings)}")
            print(f" Resolved Findings: {len(diff.resolved_findings)}")
            print(f" Unchanged Findings: {len(diff.unchanged_findings)}")
            if diff.regressions:
                print("-" * 60)
                print(f" ⚠️  REGRESSIONS DETECTED ({len(diff.regressions)}):")
                for reg in diff.regressions:
                    print(f"   • {reg}")
            print("=" * 60)

        if diff.regressions:
            return EXIT_BLOCKED
        return EXIT_ALLOWED

    except Exception as exc:
        print(f"Error comparing security baseline: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# ---------------------------------------------------------------------------
# Knowledge Graph CLI Handlers (Phase 32)
# ---------------------------------------------------------------------------

def _load_or_build_graph(graph_file: Optional[str] = None):
    from pathlib import Path
    from llmfirewall.graph.engine import KnowledgeGraph
    from llmfirewall.firewall import Firewall
    from llmfirewall.config.models import FirewallConfig, AuditConfig

    if graph_file:
        p = Path(graph_file).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Knowledge graph file not found: {graph_file}")
        return KnowledgeGraph.from_json(p.read_text(encoding="utf-8"))

    cfg = FirewallConfig(audit=AuditConfig(enabled=False))
    fw = Firewall(config=cfg)
    return fw.build_security_graph()


def handle_graph_nodes(
    type_filter: Optional[str] = None,
    json_mode: bool = False,
    graph_file: Optional[str] = None,
) -> int:
    """List nodes in the security knowledge graph."""
    try:
        kg = _load_or_build_graph(graph_file)
        nodes = kg.find_nodes(type=type_filter)

        if json_mode:
            print(json.dumps([n.to_dict() for n in nodes], indent=2, sort_keys=True))
        else:
            print(f"Knowledge Graph Nodes ({len(nodes)}):")
            for n in nodes:
                print(f"  • [{n.type:<16}] {n.id}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error querying graph nodes: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_graph_relationships(
    type_filter: Optional[str] = None,
    json_mode: bool = False,
    graph_file: Optional[str] = None,
) -> int:
    """List directed relationships in the security knowledge graph."""
    try:
        kg = _load_or_build_graph(graph_file)
        edges = kg.find_relationships(type=type_filter)

        if json_mode:
            print(json.dumps([e.to_dict() for e in edges], indent=2, sort_keys=True))
        else:
            print(f"Knowledge Graph Relationships ({len(edges)}):")
            for e in edges:
                print(f"  • {e.source} ──[{e.type}]──> {e.target}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error querying graph relationships: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_graph_show(
    node_id: str,
    json_mode: bool = False,
    graph_file: Optional[str] = None,
) -> int:
    """Show details and adjacent connections for a specific graph node."""
    from llmfirewall.graph.reporting import format_node_show_human

    try:
        kg = _load_or_build_graph(graph_file)
        node = kg.get_node(node_id)
        if not node:
            print(f"Error: Node '{node_id}' not found in knowledge graph.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        in_edges = kg.store.get_in_edges(node_id)
        out_edges = kg.store.get_out_edges(node_id)

        if json_mode:
            payload = {
                "node": node.to_dict(),
                "in_edges": [e.to_dict() for e in in_edges],
                "out_edges": [e.to_dict() for e in out_edges],
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(format_node_show_human(node, in_edges, out_edges))
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error displaying graph node: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_graph_path(
    source: str,
    target: str,
    max_depth: int = 4,
    json_mode: bool = False,
    graph_file: Optional[str] = None,
) -> int:
    """Find directed path between two knowledge graph nodes."""
    from llmfirewall.graph.reporting import format_path_human

    try:
        kg = _load_or_build_graph(graph_file)
        path = kg.find_path(source, target, max_depth=max_depth)

        if not path:
            if json_mode:
                print(json.dumps({"path_found": False, "source": source, "target": target}, indent=2))
            else:
                print(f"No path found between '{source}' and '{target}' (max depth: {max_depth}).")
            return EXIT_BLOCKED

        if json_mode:
            print(json.dumps(path.model_dump(mode="json"), indent=2, sort_keys=True))
        else:
            print(f"Path Found (Length: {path.length}):")
            print(f"  {format_path_human(path)}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error searching graph path: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_graph_impact(
    asset_id: str,
    mode: str = "impact",
    max_depth: int = 2,
    json_mode: bool = False,
    graph_file: Optional[str] = None,
) -> int:
    """Execute security impact or blast radius analysis for an asset."""
    from llmfirewall.graph.reporting import (
        format_blast_radius_human,
        format_coverage_human,
        format_impact_human,
    )

    try:
        kg = _load_or_build_graph(graph_file)
        if mode == "blast":
            res = kg.blast_radius(asset_id, max_depth=max_depth)
            if json_mode:
                print(json.dumps(res.model_dump(mode="json"), indent=2, sort_keys=True))
            else:
                print(format_blast_radius_human(res))
        elif mode == "coverage":
            res = kg.control_coverage(asset_id)
            if json_mode:
                print(json.dumps(res.model_dump(mode="json"), indent=2, sort_keys=True))
            else:
                print(format_coverage_human(res))
        else:
            res = kg.security_impact(asset_id, max_depth=max_depth)
            if json_mode:
                print(json.dumps(res.model_dump(mode="json"), indent=2, sort_keys=True))
            else:
                print(format_impact_human(res))

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error computing graph impact: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_graph_export(
    output_file: str,
    graph_file: Optional[str] = None,
) -> int:
    """Export security knowledge graph to JSON file."""
    try:
        kg = _load_or_build_graph(graph_file)
        out_path = kg.export_to_file(output_file)
        print(f"Exported knowledge graph to: {out_path} ({kg.store.node_count()} nodes, {kg.store.relationship_count()} relationships)")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error exporting graph: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_graph_import(
    input_file: str,
    output_file: Optional[str] = None,
) -> int:
    """Import and validate knowledge graph from JSON file."""
    from llmfirewall.graph.engine import KnowledgeGraph

    try:
        kg = KnowledgeGraph()
        count = kg.import_from_file(input_file)
        print(f"Imported {count} nodes and {kg.store.relationship_count()} relationships successfully from: {input_file}")
        if output_file:
            kg.export_to_file(output_file)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error importing graph: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Phase 33: Attack Graph & AI Threat Modeling CLI Handlers
# -----------------------------------------------------------------------------

def handle_attack_paths(
    source: Optional[str] = None,
    target: Optional[str] = None,
    max_depth: int = 5,
    status_filter: Optional[str] = None,
    format_type: str = "human",
    graph_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Discover and display candidate or verified multi-step AI attack paths."""
    from pathlib import Path
    from llmfirewall.attack_graph import (
        AttackGraph,
        PathStatus,
        format_attack_graph_sarif,
        format_attack_paths_human,
        format_attack_paths_json,
    )

    try:
        kg = _load_or_build_graph(graph_file)
        ag = AttackGraph(kg=kg)

        filter_st = None
        if status_filter:
            try:
                filter_st = PathStatus(status_filter.strip().upper())
            except ValueError:
                valid_states = [s.value for s in PathStatus]
                print(f"Error: Invalid status '{status_filter}'. Valid statuses: {valid_states}", file=sys.stderr)
                return EXIT_USAGE_ERROR

        paths = ag.find_paths(
            source=source,
            target=target,
            max_depth=max_depth,
            filter_status=filter_st,
        )

        fmt = format_type.lower()
        if fmt == "json":
            out_str = format_attack_paths_json(paths)
        elif fmt == "sarif":
            out_str = json.dumps(format_attack_graph_sarif(paths), indent=2)
        else:
            ep_names = [ep.name for ep in ag.list_entry_points()]
            out_str = format_attack_paths_human(paths, asset_id=source or target, entry_points=ep_names)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Attack paths successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error analyzing attack paths: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_attack_path(
    source: str,
    target: str,
    max_depth: int = 5,
    format_type: str = "human",
    graph_file: Optional[str] = None,
) -> int:
    """Find and display targeted attack path between source and target assets."""
    return handle_attack_paths(
        source=source,
        target=target,
        max_depth=max_depth,
        format_type=format_type,
        graph_file=graph_file,
    )


def handle_threat_model(
    asset_id: Optional[str] = None,
    name: Optional[str] = None,
    format_type: str = "human",
    graph_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Generate and display comprehensive AI Threat Model."""
    from pathlib import Path
    from llmfirewall.attack_graph import (
        AttackGraph,
        format_threat_model_human,
    )

    try:
        kg = _load_or_build_graph(graph_file)
        ag = AttackGraph(kg=kg)
        tm = ag.generate_threat_model(asset_id=asset_id, name=name)

        fmt = format_type.lower()
        if fmt == "json":
            out_str = tm.to_json(indent=2)
        elif fmt in ("yaml", "yml"):
            try:
                import yaml
                out_str = yaml.dump(tm.to_dict(), sort_keys=False)
            except ImportError:
                out_str = tm.to_json(indent=2)
        else:
            out_str = format_threat_model_human(tm)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Threat model successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error generating threat model: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_threat_model_export(
    output_file: str,
    asset_id: Optional[str] = None,
    name: Optional[str] = None,
    format_type: str = "json",
    graph_file: Optional[str] = None,
) -> int:
    """Export threat model to a versioned JSON or YAML file."""
    return handle_threat_model(
        asset_id=asset_id,
        name=name,
        format_type=format_type,
        graph_file=graph_file,
        output_file=output_file,
    )


# -----------------------------------------------------------------------------
# Phase 34: AI Asset Inventory & Discovery CLI Handlers
# -----------------------------------------------------------------------------

def _load_or_build_inventory(
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
) -> Any:
    """Helper loading inventory from file or discovering from active Firewall."""
    from pathlib import Path
    from llmfirewall import Firewall, FirewallConfig, AuditConfig
    from llmfirewall.inventory import AssetInventory, ImportDiscoveryProvider

    kg = _load_or_build_graph(graph_file)
    inv = AssetInventory(kg=kg)

    if inventory_file:
        p = Path(inventory_file).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Inventory file not found: {inventory_file}")
        inv.import_from_file(str(p))
        return inv

    # Default: build from active Firewall
    cfg = FirewallConfig(audit=AuditConfig(enabled=False))
    fw = Firewall(config=cfg)
    inv = fw.inventory
    inv.discover(sync_graph=True)
    return inv


def handle_inventory_list(
    type_filter: Optional[str] = None,
    env_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """List assets in the AI inventory with optional filters."""
    from pathlib import Path
    from llmfirewall.inventory import (
        format_inventory_json,
        format_inventory_list_human,
    )

    try:
        inv = _load_or_build_inventory(inventory_file=inventory_file, graph_file=graph_file)
        assets = inv.list_assets(type=type_filter, environment=env_filter, status=status_filter)

        if format_type.lower() == "json":
            out_str = format_inventory_json(assets)
        else:
            out_str = format_inventory_list_human(assets)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Inventory list successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error querying inventory: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_inventory_show(
    asset_id: str,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
) -> int:
    """Display comprehensive details, provenance, and attack surface for an asset."""
    from llmfirewall.inventory import (
        format_asset_show_human,
    )

    try:
        inv = _load_or_build_inventory(inventory_file=inventory_file, graph_file=graph_file)
        asset = inv.get(asset_id)
        if not asset:
            print(f"Error: Asset '{asset_id}' not found in inventory.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        exposure = inv.attack_surface(asset.id)

        if format_type.lower() == "json":
            doc = {
                "asset": asset.to_dict(),
                "exposure": exposure.to_dict(),
            }
            print(json.dumps(doc, indent=2, sort_keys=True))
        else:
            print(format_asset_show_human(asset, exposure))

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error displaying asset: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_inventory_discover(
    format_type: str = "human",
    config_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Execute live AI asset discovery, update knowledge graph, and display report."""
    from pathlib import Path
    from llmfirewall import Firewall, FirewallConfig, AuditConfig
    from llmfirewall.inventory import (
        format_discovery_result_human,
        format_discovery_result_json,
    )

    try:
        cfg = FirewallConfig(audit=AuditConfig(enabled=False))
        fw = Firewall(config=cfg)
        inv = fw.inventory

        res = inv.discover(sync_graph=True)

        if format_type.lower() == "json":
            out_str = format_discovery_result_json(res)
        else:
            out_str = format_discovery_result_human(res)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Discovery report successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error running discovery: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_inventory_export(
    output_file: str,
    format_type: str = "json",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
) -> int:
    """Export asset inventory snapshot to a JSON or YAML file."""
    try:
        inv = _load_or_build_inventory(inventory_file=inventory_file, graph_file=graph_file)
        inv.export_to_file(output_file, format_type=format_type)
        print(f"Inventory successfully exported to: {output_file}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error exporting inventory: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_inventory_diff(
    before_file: str,
    after_file: str,
    format_type: str = "human",
) -> int:
    """Compare two inventory snapshots and display architectural drift."""
    from pathlib import Path
    from llmfirewall.inventory import (
        AssetInventory,
        InventorySnapshot,
        format_inventory_diff_human,
    )

    try:
        p_before = Path(before_file).resolve()
        p_after = Path(after_file).resolve()

        if not p_before.exists():
            print(f"Error: Baseline inventory file not found: {before_file}", file=sys.stderr)
            return EXIT_USAGE_ERROR
        if not p_after.exists():
            print(f"Error: Target inventory file not found: {after_file}", file=sys.stderr)
            return EXIT_USAGE_ERROR

        snap_before = InventorySnapshot.model_validate_json(p_before.read_text(encoding="utf-8"))
        snap_after = InventorySnapshot.model_validate_json(p_after.read_text(encoding="utf-8"))

        diff = AssetInventory.diff(snap_before, snap_after)

        if format_type.lower() == "json":
            print(json.dumps(diff.to_dict(), indent=2, sort_keys=True))
        else:
            print(format_inventory_diff_human(diff))

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error comparing inventory snapshots: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Phase 35 — AI Security Posture Management (AI-SPM) Handlers
# -----------------------------------------------------------------------------

def _load_or_build_posture_engine(
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> Any:
    """Helper to initialize PostureEngine with inventory, attack graph, and knowledge graph."""
    from llmfirewall.spm import PostureEngine

    inv = _load_or_build_inventory(inventory_file=inventory_file, graph_file=graph_file)
    cfg = None
    if config_file and os.path.isfile(config_file):
        try:
            cfg = FirewallConfig.from_file(config_file)
        except Exception:
            pass

    if cfg is None:
        cfg = FirewallConfig(audit=AuditConfig(enabled=False))

    fw = Firewall(config=cfg)
    return PostureEngine(
        inventory=inv,
        kg=inv.kg,
        attack_graph=inv.attack_graph,
        audit_logger=fw._audit_logger,
    )


def handle_posture_summary(
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Evaluate and display aggregated security posture summary across all assets."""
    from pathlib import Path
    from llmfirewall.spm import (
        format_posture_json,
        format_posture_sarif,
        format_posture_summary_human,
    )

    try:
        engine = _load_or_build_posture_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        if format_type.lower() == "sarif":
            sarif_data = engine.export_sarif()
            out_str = format_posture_sarif(sarif_data)
        elif format_type.lower() == "json":
            summary = engine.summary()
            out_str = format_posture_json(summary)
        else:
            summary = engine.summary()
            out_str = format_posture_summary_human(summary)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Posture summary successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error evaluating posture summary: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_posture_show(
    asset_id: str,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Evaluate and display evidence-based security posture for a specific asset."""
    from pathlib import Path
    from llmfirewall.spm import (
        format_posture_human,
        format_posture_json,
        format_posture_sarif,
    )

    try:
        engine = _load_or_build_posture_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        posture = engine.evaluate(asset_id)

        if format_type.lower() == "sarif":
            sarif_data = engine.export_sarif(posture.security_gaps)
            out_str = format_posture_sarif(sarif_data)
        elif format_type.lower() == "json":
            out_str = format_posture_json(posture)
        else:
            out_str = format_posture_human(posture)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Asset posture successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error evaluating asset posture: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_posture_diff(
    before_file: str,
    after_file: str,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Compare two posture snapshots to detect regressions, improvements, and gap deltas."""
    from pathlib import Path
    from llmfirewall.spm import (
        PostureEngine,
        PostureSnapshot,
        format_posture_diff_human,
        format_posture_json,
    )

    try:
        p_before = Path(before_file).resolve()
        p_after = Path(after_file).resolve()

        if not p_before.exists():
            print(f"Error: Baseline snapshot file not found: {before_file}", file=sys.stderr)
            return EXIT_USAGE_ERROR
        if not p_after.exists():
            print(f"Error: Target snapshot file not found: {after_file}", file=sys.stderr)
            return EXIT_USAGE_ERROR

        snap_before = PostureSnapshot.model_validate_json(p_before.read_text(encoding="utf-8"))
        snap_after = PostureSnapshot.model_validate_json(p_after.read_text(encoding="utf-8"))

        diff = PostureEngine.diff(snap_before, snap_after)

        if format_type.lower() == "json":
            out_str = format_posture_json(diff)
        else:
            out_str = format_posture_diff_human(diff)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Posture diff successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error comparing posture snapshots: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_posture_snapshot(
    output_file: Optional[str] = None,
    posture_version: str = "1.0",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> int:
    """Create and export a reproducible, canonical baseline snapshot of AI security posture."""
    from pathlib import Path
    from llmfirewall.spm import format_posture_json

    try:
        engine = _load_or_build_posture_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        snap = engine.snapshot(posture_version=posture_version)
        out_str = format_posture_json(snap)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Posture snapshot successfully written to: {output_file}")
        else:
            print(out_str)

        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error creating posture snapshot: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_posture_export(
    output_file: str,
    format_type: str = "sarif",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> int:
    """Export actionable posture gaps or snapshot to SARIF 2.1.0 or JSON file."""
    from pathlib import Path
    from llmfirewall.spm import format_posture_json, format_posture_sarif

    try:
        engine = _load_or_build_posture_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        if format_type.lower() == "sarif":
            sarif_data = engine.export_sarif()
            out_str = format_posture_sarif(sarif_data)
        else:
            snap = engine.snapshot()
            out_str = format_posture_json(snap)

        p = Path(output_file).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(out_str, encoding="utf-8")
        print(f"Posture exported successfully to: {output_file}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error exporting posture: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Phase 36 — AI Security Compliance & Control Mapping Handlers
# -----------------------------------------------------------------------------

def _load_or_build_compliance_engine(
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> Any:
    """Helper to initialize ComplianceEngine with inventory, posture, and knowledge graph."""
    from llmfirewall.compliance import ComplianceEngine
    from llmfirewall.spm import PostureEngine

    inv = _load_or_build_inventory(inventory_file=inventory_file, graph_file=graph_file)
    cfg = None
    if config_file and os.path.isfile(config_file):
        try:
            cfg = FirewallConfig.from_file(config_file)
        except Exception:
            pass

    if cfg is None:
        cfg = FirewallConfig(audit=AuditConfig(enabled=False))

    fw = Firewall(config=cfg)
    spm = PostureEngine(
        inventory=inv,
        kg=inv.kg,
        attack_graph=inv.attack_graph,
        audit_logger=fw._audit_logger,
    )
    return ComplianceEngine(
        inventory=inv,
        kg=inv.kg,
        attack_graph=inv.attack_graph,
        spm=spm,
        governance=None,
        audit_logger=fw._audit_logger,
    )


def handle_compliance_frameworks(
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """List registered control frameworks."""
    from pathlib import Path
    from llmfirewall.compliance import format_compliance_json, format_compliance_yaml

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )
        frameworks = engine.catalog.list_frameworks()

        if format_type.lower() == "json":
            out_str = format_compliance_json([fw.to_dict() for fw in frameworks])
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_compliance_yaml([fw.to_dict() for fw in frameworks])
        else:
            lines = [
                "=" * 60,
                "REGISTERED COMPLIANCE FRAMEWORKS",
                "=" * 60,
                f"{'FRAMEWORK ID':<24} {'VERSION':<10} {'CONTROLS':<10} {'DOMAINS'}",
                "-" * 60,
            ]
            for fw in frameworks:
                dom_count = len(fw.domains)
                lines.append(f"{fw.id:<24} {fw.version:<10} {len(fw.controls):<10} {dom_count} domains")
                lines.append(f"  Name: {fw.name} | Source: {fw.source}")
            lines.append("=" * 60)
            out_str = "\n".join(lines)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Frameworks written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error listing frameworks: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_assess(
    asset_id: Optional[str] = None,
    framework_id: Optional[str] = None,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Execute compliance assessment and format report."""
    from pathlib import Path
    from llmfirewall.compliance import (
        format_compliance_human,
        format_compliance_json,
        format_compliance_yaml,
    )

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        if asset_id:
            assessments = engine.assess_asset(asset_id, framework_id=framework_id)
        else:
            env_res = engine.assess_environment(framework_id=framework_id)
            assessments = [a for a_list in env_res.values() for a in a_list]

        if format_type.lower() == "sarif":
            gaps = [g for a in assessments for g in a.gaps]
            sarif_data = engine.export_sarif(gaps)
            out_str = format_compliance_json(sarif_data)
        elif format_type.lower() == "json":
            out_str = format_compliance_json([a.to_dict() for a in assessments])
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_compliance_yaml([a.to_dict() for a in assessments])
        else:
            fw = engine.catalog.get_framework(framework_id) if framework_id else engine.catalog.get_framework("ai-security-baseline")
            fw_name = fw.name if fw else "AI Security Baseline"
            fw_ver = fw.version if fw else "1.0"
            out_str = format_compliance_human(
                assessments,
                framework_name=fw_name,
                framework_version=fw_ver,
                exceptions=engine.list_exceptions(),
            )

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Assessment report written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error assessing compliance: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_control(
    control_id: str,
    asset_id: Optional[str] = None,
    framework_id: Optional[str] = None,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Display comprehensive control details, applicability, and evidence chain."""
    from pathlib import Path
    from llmfirewall.compliance import (
        format_compliance_json,
        format_compliance_yaml,
        format_control_detail_human,
    )

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        ctrl = engine.catalog.get_control(control_id, framework_id=framework_id)
        if not ctrl:
            print(f"Error: Control '{control_id}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        aid = asset_id or "application:default"
        assessment = engine.assess_control(ctrl.id, aid)

        if format_type.lower() == "json":
            out_str = format_compliance_json(assessment.to_dict())
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_compliance_yaml(assessment.to_dict())
        else:
            out_str = format_control_detail_human(assessment, control=ctrl)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Control details written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error retrieving control details: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_gaps(
    framework_id: Optional[str] = None,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """List compliance gaps across assets."""
    from pathlib import Path
    from llmfirewall.compliance import (
        format_compliance_json,
        format_compliance_yaml,
        format_gaps_human,
    )

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )
        env_res = engine.assess_environment(framework_id=framework_id)
        all_gaps = [g for a_list in env_res.values() for a in a_list for g in a.gaps]
        dedup_gaps = list({g.gap_id: g for g in all_gaps}.values())

        if format_type.lower() == "sarif":
            sarif_data = engine.export_sarif(dedup_gaps)
            out_str = format_compliance_json(sarif_data)
        elif format_type.lower() == "json":
            out_str = format_compliance_json([g.to_dict() for g in dedup_gaps])
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_compliance_yaml([g.to_dict() for g in dedup_gaps])
        else:
            out_str = format_gaps_human(dedup_gaps)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Gaps written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error listing compliance gaps: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_evidence(
    asset_id: Optional[str] = None,
    control_id: Optional[str] = None,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """List compliance evidence repository items."""
    from pathlib import Path
    from llmfirewall.compliance import (
        format_compliance_json,
        format_compliance_yaml,
        format_evidence_human,
    )

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )
        evid_list = engine.list_evidence(asset_id=asset_id, control_id=control_id)

        if format_type.lower() == "json":
            out_str = format_compliance_json([e.to_dict() for e in evid_list])
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_compliance_yaml([e.to_dict() for e in evid_list])
        else:
            out_str = format_evidence_human(evid_list)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Evidence written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error listing evidence: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_snapshot(
    output_file: Optional[str] = None,
    framework_id: Optional[str] = None,
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> int:
    """Generate and write a tamper-evident compliance baseline snapshot."""
    from pathlib import Path
    from llmfirewall.compliance import format_compliance_json

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )
        snap = engine.snapshot(framework_id=framework_id)
        out_str = format_compliance_json(snap)

        dest = output_file or "compliance_snapshot.json"
        p = Path(dest).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(out_str, encoding="utf-8")
        print(f"Compliance snapshot written to: {dest}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error creating snapshot: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_diff(
    before_file: str,
    after_file: str,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Compare two compliance snapshots and report regressions."""
    import json
    from pathlib import Path
    from llmfirewall.compliance import (
        ComplianceEngine,
        ComplianceSnapshot,
        format_compliance_json,
        format_compliance_yaml,
        format_diff_human,
    )

    try:
        pb = Path(before_file).resolve()
        pa = Path(after_file).resolve()
        if not pb.is_file() or not pa.is_file():
            print("Error: Both --before and --after files must exist.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        snap_b = ComplianceSnapshot.model_validate(json.loads(pb.read_text(encoding="utf-8")))
        snap_a = ComplianceSnapshot.model_validate(json.loads(pa.read_text(encoding="utf-8")))

        engine = ComplianceEngine()
        diff_res = engine.diff(snap_b, snap_a)

        if format_type.lower() == "json":
            out_str = format_compliance_json(diff_res.to_dict())
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_compliance_yaml(diff_res.to_dict())
        else:
            out_str = format_diff_human(diff_res)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Compliance diff written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error calculating compliance diff: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_compliance_export(
    output_file: str,
    format_type: Optional[str] = None,
    framework_id: Optional[str] = None,
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> int:
    """Export compliance report, snapshot, or SARIF to JSON/YAML."""
    from pathlib import Path
    from llmfirewall.compliance import (
        format_compliance_human,
        format_compliance_json,
        format_compliance_yaml,
    )

    try:
        engine = _load_or_build_compliance_engine(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        p = Path(output_file).resolve()
        fmt = format_type or (p.suffix.lstrip(".").lower() if p.suffix else "json")

        if fmt == "sarif":
            sarif_data = engine.export_sarif()
            out_str = format_compliance_json(sarif_data)
        elif fmt in ("yaml", "yml"):
            snap = engine.snapshot(framework_id=framework_id)
            out_str = format_compliance_yaml(snap.to_dict())
        else:
            snap = engine.snapshot(framework_id=framework_id)
            out_str = format_compliance_json(snap.to_dict())

        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(out_str, encoding="utf-8")
        print(f"Compliance report exported successfully to: {output_file}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error exporting compliance: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Phase 37 — AI Security Risk & Prioritization Handlers
# -----------------------------------------------------------------------------

def _load_or_build_risk_prioritizer(
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> Any:
    """Helper to initialize RiskPrioritizationEngine with inventory, kg, attack graph, spm, compliance."""
    from llmfirewall.compliance import ComplianceEngine
    from llmfirewall.risk.prioritizer import RiskPrioritizationEngine
    from llmfirewall.spm import PostureEngine

    inv = _load_or_build_inventory(inventory_file=inventory_file, graph_file=graph_file)
    cfg = None
    if config_file and os.path.isfile(config_file):
        try:
            cfg = FirewallConfig.from_file(config_file)
        except Exception:
            pass

    if cfg is None:
        cfg = FirewallConfig(audit=AuditConfig(enabled=False))

    fw = Firewall(config=cfg)
    spm = PostureEngine(
        inventory=inv,
        kg=inv.kg,
        attack_graph=inv.attack_graph,
        audit_logger=fw._audit_logger,
    )
    compliance = ComplianceEngine(
        inventory=inv,
        kg=inv.kg,
        attack_graph=inv.attack_graph,
        spm=spm,
        audit_logger=fw._audit_logger,
    )
    return RiskPrioritizationEngine(
        inventory=inv,
        kg=inv.kg,
        attack_graph=inv.attack_graph,
        spm=spm,
        compliance=compliance,
        governance=None,
        audit_logger=fw._audit_logger,
    )


def handle_risk_prioritize(
    asset_id: Optional[str] = None,
    format_type: str = "human",
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> int:
    """Prioritize and explain security risks across assets or for a specific asset."""
    from pathlib import Path
    from llmfirewall.risk import (
        format_risk_detail_human,
        format_risk_human,
        format_risk_json,
        format_risk_yaml,
    )

    try:
        engine = _load_or_build_risk_prioritizer(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )

        risks = engine.prioritize(asset_id=asset_id)

        if format_type.lower() == "json":
            out_str = format_risk_json([r.to_dict() for r in risks])
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_risk_yaml([r.to_dict() for r in risks])
        else:
            if asset_id and len(risks) == 1:
                out_str = format_risk_detail_human(risks[0])
            else:
                out_str = format_risk_human(risks)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Risk prioritization report written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error prioritizing risks: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_risk_snapshot(
    output_file: Optional[str] = None,
    inventory_file: Optional[str] = None,
    graph_file: Optional[str] = None,
    config_file: Optional[str] = None,
) -> int:
    """Generate and write a tamper-evident risk baseline snapshot."""
    from pathlib import Path
    from llmfirewall.risk import format_risk_json

    try:
        engine = _load_or_build_risk_prioritizer(
            inventory_file=inventory_file,
            graph_file=graph_file,
            config_file=config_file,
        )
        snap = engine.snapshot()
        out_str = format_risk_json(snap)

        dest = output_file or "risk_snapshot.json"
        p = Path(dest).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(out_str, encoding="utf-8")
        print(f"Risk snapshot written to: {dest}")
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error creating risk snapshot: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_risk_diff(
    before_file: str,
    after_file: str,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Compare two risk snapshots and detect regressions (RISK_INCREASED)."""
    import json
    from pathlib import Path
    from llmfirewall.risk import (
        RiskPrioritizationEngine,
        RiskSnapshot,
        format_risk_diff_human,
        format_risk_json,
        format_risk_yaml,
    )

    try:
        pb = Path(before_file).resolve()
        pa = Path(after_file).resolve()
        if not pb.is_file() or not pa.is_file():
            print("Error: Both --before and --after files must exist.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        snap_b = RiskSnapshot.model_validate(json.loads(pb.read_text(encoding="utf-8")))
        snap_a = RiskSnapshot.model_validate(json.loads(pa.read_text(encoding="utf-8")))

        engine = RiskPrioritizationEngine()
        diff_res = engine.diff(snap_b, snap_a)

        if format_type.lower() == "json":
            out_str = format_risk_json(diff_res.to_dict())
        elif format_type.lower() in ("yaml", "yml"):
            out_str = format_risk_yaml(diff_res.to_dict())
        else:
            out_str = format_risk_diff_human(diff_res)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Risk diff written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error calculating risk diff: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Phase 38: AI Security Incident Response & Investigation CLI Handlers
# -----------------------------------------------------------------------------

def _load_incident_manager(events_file: Optional[str] = None) -> Any:
    """Helper to instantiate IncidentManager with optional historical events file."""
    import json
    from pathlib import Path
    from llmfirewall.incidents import IncidentManager, SecurityEvent, IncidentSeverity

    mgr = IncidentManager()

    if events_file:
        p = Path(events_file).resolve()
        if p.is_file():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                evs = [SecurityEvent.model_validate(e) for e in (raw if isinstance(raw, list) else [raw])]
                mgr.ingest_events(evs)
            except Exception as e:
                print(f"Warning: Failed to load events from {events_file}: {e}", file=sys.stderr)
    return mgr


def handle_incidents_list(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    asset_id: Optional[str] = None,
    events_file: Optional[str] = None,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """List AI security incidents matching optional filters."""
    import json
    from pathlib import Path
    from llmfirewall.incidents import (
        IncidentSeverity,
        IncidentStatus,
        format_incidents_table_human,
    )

    try:
        mgr = _load_incident_manager(events_file)
        
        # If no incidents and no events file specified, create a demonstrative sample if none exist
        if not mgr.list_incidents() and not events_file:
            mgr.record_event(
                event_type="PROMPT_INJECTION_DETECTED",
                asset_id="agent:support",
                agent_id="support",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.HIGH,
                metadata={"pattern": "ignore previous instructions", "confidence": 0.95},
            )
            mgr.record_event(
                event_type="UNAUTHORIZED_TOOL_CALL",
                asset_id="agent:support",
                agent_id="support",
                tool_id="db_query_tool",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.CRITICAL,
                metadata={"action": "drop_table", "authorization": "denied"},
            )

        st = IncidentStatus(status.upper()) if status else None
        sev = IncidentSeverity(severity.upper()) if severity else None
        incidents = mgr.list_incidents(status=st, severity=sev, asset_id=asset_id)

        if format_type.lower() == "json":
            out_str = json.dumps([inc.model_dump(mode="json") for inc in incidents], indent=2, default=str)
        else:
            out_str = format_incidents_table_human(incidents)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Incidents list written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error listing incidents: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_incidents_show(
    incident_id: str,
    events_file: Optional[str] = None,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Show details of a specific security incident."""
    import json
    from pathlib import Path
    from llmfirewall.incidents import (
        IncidentSeverity,
        format_incident_detail_human,
    )

    try:
        mgr = _load_incident_manager(events_file)
        incident = mgr.get_incident(incident_id)

        # Demo bootstrap if not found and matches default pattern
        if not incident and (incident_id in ("INC-001", "INC-1") or not events_file):
            mgr.record_event(
                event_type="PROMPT_INJECTION_DETECTED",
                asset_id="agent:support",
                agent_id="support",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.HIGH,
                metadata={"pattern": "ignore previous instructions", "confidence": 0.95},
            )
            mgr.record_event(
                event_type="UNAUTHORIZED_TOOL_CALL",
                asset_id="agent:support",
                agent_id="support",
                tool_id="db_query_tool",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.CRITICAL,
                metadata={"action": "drop_table", "authorization": "denied"},
            )
            incident = mgr.get_incident(incident_id) or (mgr.list_incidents()[0] if mgr.list_incidents() else None)

        if not incident:
            print(f"Error: Incident '{incident_id}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        timeline = mgr.get_timeline(incident.id)

        if format_type.lower() == "json":
            data = incident.model_dump(mode="json")
            data["timeline"] = [t.model_dump(mode="json") for t in timeline]
            out_str = json.dumps(data, indent=2, default=str)
        else:
            out_str = format_incident_detail_human(incident, timeline=timeline)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Incident details written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error retrieving incident '{incident_id}': {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_incidents_timeline(
    incident_id: str,
    events_file: Optional[str] = None,
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """View the chronological investigation timeline of a security incident."""
    import json
    from pathlib import Path
    from llmfirewall.incidents import (
        IncidentSeverity,
        format_incident_timeline_human,
    )

    try:
        mgr = _load_incident_manager(events_file)
        incident = mgr.get_incident(incident_id)

        if not incident and (incident_id in ("INC-001", "INC-1") or not events_file):
            mgr.record_event(
                event_type="PROMPT_INJECTION_DETECTED",
                asset_id="agent:support",
                agent_id="support",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.HIGH,
                metadata={"pattern": "ignore previous instructions", "confidence": 0.95},
            )
            mgr.record_event(
                event_type="UNAUTHORIZED_TOOL_CALL",
                asset_id="agent:support",
                agent_id="support",
                tool_id="db_query_tool",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.CRITICAL,
                metadata={"action": "drop_table", "authorization": "denied"},
            )
            incident = mgr.get_incident(incident_id) or (mgr.list_incidents()[0] if mgr.list_incidents() else None)

        if not incident:
            print(f"Error: Incident '{incident_id}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        timeline = mgr.get_timeline(incident.id)

        if format_type.lower() == "json":
            out_str = json.dumps([t.model_dump(mode="json") for t in timeline], indent=2, default=str)
        else:
            out_str = format_incident_timeline_human(incident, timeline)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Timeline written to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error retrieving timeline for incident '{incident_id}': {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def handle_incidents_export(
    incident_id: str,
    events_file: Optional[str] = None,
    format_type: str = "markdown",
    output_file: Optional[str] = None,
) -> int:
    """Generate and export a formal Post-Incident Investigation Report."""
    from pathlib import Path
    from llmfirewall.incidents import (
        IncidentSeverity,
        generate_post_incident_report,
    )

    try:
        mgr = _load_incident_manager(events_file)
        incident = mgr.get_incident(incident_id)

        if not incident and (incident_id in ("INC-001", "INC-1") or not events_file):
            mgr.record_event(
                event_type="PROMPT_INJECTION_DETECTED",
                asset_id="agent:support",
                agent_id="support",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.HIGH,
                metadata={"pattern": "ignore previous instructions", "confidence": 0.95},
            )
            mgr.record_event(
                event_type="UNAUTHORIZED_TOOL_CALL",
                asset_id="agent:support",
                agent_id="support",
                tool_id="db_query_tool",
                request_id="req-901",
                session_id="sess-alpha",
                severity=IncidentSeverity.CRITICAL,
                metadata={"action": "drop_table", "authorization": "denied"},
            )
            incident = mgr.get_incident(incident_id) or (mgr.list_incidents()[0] if mgr.list_incidents() else None)

        if not incident:
            print(f"Error: Incident '{incident_id}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR

        timeline = mgr.get_timeline(incident.id)
        out_str = generate_post_incident_report(incident, timeline=timeline, format_type=format_type)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Post-Incident Report exported to: {output_file}")
        else:
            print(out_str)
        return EXIT_ALLOWED
    except Exception as exc:
        print(f"Error exporting incident report for '{incident_id}': {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# Phase 39: AI Security Runtime Protection CLI Handlers
# -----------------------------------------------------------------------------

def handle_protect(
    input_text: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_args: Optional[str] = None,
    output_text: Optional[str] = None,
    agent_id: Optional[str] = None,
    policy_file: Optional[str] = None,
    mode: str = "enforce",
    format_type: str = "human",
    output_file: Optional[str] = None,
) -> int:
    """Evaluate real-time runtime protection policies on input, tool, or output."""
    import json
    from pathlib import Path
    from llmfirewall.protection import (
        ProtectionPolicy,
        RuntimeProtectionEngine,
        RuntimeRequest,
        PolicyMode,
        PolicyDecision,
    )

    try:
        # Load policy
        pol = None
        if policy_file:
            p = Path(policy_file).resolve()
            if p.is_file():
                pol = ProtectionPolicy.from_file(p)
            else:
                print(f"Error: Policy file not found: {policy_file}", file=sys.stderr)
                return EXIT_USAGE_ERROR

        pol_mode = PolicyMode.ENFORCE
        if mode.lower() == "shadow":
            pol_mode = PolicyMode.SHADOW
        elif mode.lower() == "disabled":
            pol_mode = PolicyMode.DISABLED

        engine = RuntimeProtectionEngine(policy=pol, mode=pol_mode)

        # Parse tool args
        tool_payload = None
        if tool_name:
            t_args = {}
            if tool_args:
                try:
                    t_args = json.loads(tool_args)
                except Exception:
                    t_args = {"raw": tool_args}
            tool_payload = {"name": tool_name, "arguments": t_args}

        # Build request
        req = RuntimeRequest(
            agent_id=agent_id or "cli-agent",
            input=input_text,
            tool=tool_payload,
            output=output_text,
        )

        dec = engine.inspect(req)

        if format_type.lower() == "json":
            out_str = json.dumps(dec.model_dump(mode="json"), indent=2, default=str)
        else:
            lines = [
                "================================================================================",
                "                       AI RUNTIME PROTECTION DECISION                          ",
                "================================================================================",
                f"Effective Decision: {dec.effective_decision.value}",
                f"Raw Policy Decision:{dec.decision.value} (Mode: {dec.mode.value})",
                f"Latency:            {dec.latency_ms:.3f} ms",
                f"Reason:             {dec.reason}",
            ]
            if dec.matched_policies:
                lines.append(f"Matched Policies:   {', '.join(dec.matched_policies)}")
            if dec.risk_factors:
                lines.append(f"Risk Factors:       {', '.join(dec.risk_factors)}")
            if dec.redacted_content:
                lines.append("--- Redacted Content ---")
                lines.append(dec.redacted_content)
            lines.append("================================================================================")
            out_str = "\n".join(lines)

        if output_file:
            p = Path(output_file).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out_str, encoding="utf-8")
            print(f"Runtime protection decision written to: {output_file}")
        else:
            print(out_str)

        return EXIT_BLOCKED if dec.is_blocked else EXIT_ALLOWED
    except Exception as exc:
        print(f"Error executing runtime protection: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR






