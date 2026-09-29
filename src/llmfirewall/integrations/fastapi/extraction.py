"""Extraction strategies for retrieving text payloads from FastAPI HTTP requests."""

import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from starlette.requests import Request


# Extraction callable type: (Request, body_bytes) -> Tuple[Optional[str], Optional[Dict[str, Any]]]
ExtractorCallable = Callable[[Request, bytes], Tuple[Optional[str], Optional[Dict[str, Any]]]]


class FieldExtractor:
    """Extracts string payloads from JSON request bodies by key or nested path."""

    def __init__(self, field_names: Optional[List[str]] = None) -> None:
        """
        Args:
            field_names: Ordered candidate field names to search in JSON body.
                         Defaults to common LLM fields: ['prompt', 'text', 'message', 'question', 'content', 'input'].
        """
        self.field_names = field_names or [
            "prompt",
            "text",
            "message",
            "question",
            "content",
            "input",
        ]

    def __call__(self, request: Request, body_bytes: bytes) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Extract candidate string and parsed json dictionary.
        
        Returns:
            (extracted_text, parsed_json_dict)
        """
        if not body_bytes:
            return None, None

        # Check content type if available
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type and not body_bytes.strip().startswith((b"{", b"[")):
            # If not json, return raw text if utf-8 decodable
            try:
                return body_bytes.decode("utf-8"), None
            except UnicodeDecodeError:
                return None, None

        try:
            data = json.loads(body_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, None

        if isinstance(data, dict):
            for field in self.field_names:
                if field in data and isinstance(data[field], str):
                    return data[field], data

        elif isinstance(data, str):
            return data, None

        return None, (data if isinstance(data, dict) else None)
