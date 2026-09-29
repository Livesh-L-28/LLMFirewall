"""CLI exit code constants for LLMFirewall."""

# Exit code contracts:
# 0 -> Scan passed (ALLOW, WARN, or REDACT)
# 1 -> Scan failed/blocked (BLOCK)
# 2 -> Usage, syntax, or configuration error (invalid flags, missing args, missing file)
# 3 -> System, runtime, or I/O error

EXIT_ALLOWED = 0
EXIT_BLOCKED = 1
EXIT_USAGE_ERROR = 2
EXIT_SYSTEM_ERROR = 3
