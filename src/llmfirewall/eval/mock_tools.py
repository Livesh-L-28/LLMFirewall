"""Mock tools and safe execution sandbox preventing external side effects during security testing."""

from typing import Any, Dict, List, Optional
import uuid


class MockToolRegistry:
    """Isolated, side-effect-free tool registry for security test evaluation.
    
    Guarantees:
    - Never performs real disk writes or file deletions.
    - Never communicates over real networks, SMTP, or webhooks.
    - Never alters production databases or executes host shell processes.
    - Records every tool invocation in an in-memory audit log for inspection.
    """

    def __init__(self) -> None:
        self.invocations: List[Dict[str, Any]] = []
        self._mock_filesystem: Dict[str, str] = {
            "./documents/sample.txt": "Public documentation content.",
            "./documents/allowed.txt": "Approved research data.",
        }
        self._mock_database: Dict[str, Dict[str, Any]] = {
            "users": {"1": {"name": "Alice"}, "2": {"name": "Bob"}},
            "orders": {"101": {"amount": 50}},
        }
        self._mock_outbox: List[Dict[str, str]] = []

    def reset(self) -> None:
        """Clear execution log and revert mock state."""
        self.invocations.clear()
        self._mock_outbox.clear()

    def execute_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dispatch tool invocation safely against mock state."""
        args = arguments or {}
        call_id = str(uuid.uuid4())
        record = {
            "call_id": call_id,
            "tool_name": tool_name,
            "arguments": args,
        }
        self.invocations.append(record)

        if tool_name in ("read_file", "filesystem.read"):
            return self.mock_read_file(args.get("path", ""))

        elif tool_name in ("write_file", "filesystem.write"):
            return self.mock_write_file(args.get("path", ""), args.get("content", ""))

        elif tool_name in ("send_email", "email.send"):
            return self.mock_send_email(args.get("to", ""), args.get("subject", ""), args.get("body", ""))

        elif tool_name in ("db_delete", "database.delete"):
            return self.mock_database_delete(args.get("table", ""), str(args.get("record_id", "")))

        elif tool_name in ("terminal", "shell.execute", "execute_command"):
            return self.mock_execute_shell(args.get("command", ""))

        elif tool_name in ("web_fetch", "network.request"):
            return self.mock_web_fetch(args.get("url", ""))

        else:
            return {"status": "SUCCESS", "tool": tool_name, "output": f"Mock output for {tool_name}"}

    def mock_read_file(self, path: str) -> Dict[str, Any]:
        """Safe file read mock."""
        if path in self._mock_filesystem:
            return {"status": "SUCCESS", "path": path, "content": self._mock_filesystem[path]}
        return {"status": "ERROR", "path": path, "error": "File not found or permission denied"}

    def mock_write_file(self, path: str, content: str) -> Dict[str, Any]:
        """Safe in-memory write mock without touching the host filesystem."""
        self._mock_filesystem[path] = content
        return {"status": "SUCCESS", "path": path, "bytes_written": len(content)}

    def mock_send_email(self, to: str, subject: str, body: str) -> Dict[str, Any]:
        """Safe email send mock without network transmission."""
        msg = {"to": to, "subject": subject, "body": body}
        self._mock_outbox.append(msg)
        return {"status": "SUCCESS", "message": "Email queued in mock outbox"}

    def mock_database_delete(self, table: str, record_id: str) -> Dict[str, Any]:
        """Safe mock database delete."""
        if table in self._mock_database and record_id in self._mock_database[table]:
            del self._mock_database[table][record_id]
            return {"status": "SUCCESS", "table": table, "record_id": record_id, "deleted": True}
        return {"status": "SUCCESS", "table": table, "record_id": record_id, "deleted": False}

    def mock_execute_shell(self, command: str) -> Dict[str, Any]:
        """Safe shell execute mock returning simulated output without invoking subprocess."""
        return {
            "status": "SUCCESS",
            "command": command,
            "stdout": f"[MOCK OUTPUT] Executed: {command}",
            "exit_code": 0,
        }

    def mock_web_fetch(self, url: str) -> Dict[str, Any]:
        """Safe network fetch mock."""
        return {
            "status": "SUCCESS",
            "url": url,
            "body": f"[MOCK HTML] Contents of {url}",
            "status_code": 200,
        }
