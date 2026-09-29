"""Main command-line entrypoint for LLMFirewall."""

import argparse
import sys
from typing import List, Optional

from llmfirewall._version import __version__
from llmfirewall.cli.commands import handle_scan
from llmfirewall.cli.errors import EXIT_ALLOWED, EXIT_USAGE_ERROR


def build_parser() -> argparse.ArgumentParser:
    """Construct the main CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="llmfirewall",
        description="LLMFirewall: Lightweight, provider-agnostic security and policy enforcement for LLMs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  llmfirewall scan \"Hello, how are you?\"\n"
            "  llmfirewall scan --file prompt.txt\n"
            "  cat prompt.txt | llmfirewall scan --stdin\n"
            "  llmfirewall scan --json \"Check this input\"\n"
            "  llmfirewall scan --disable-pii \"Ignore PII here\"\n"
            "\n"
            "Exit Codes:\n"
            "  0  Request allowed (ALLOW, WARN, REDACT)\n"
            "  1  Request rejected by security policy (BLOCK)\n"
            "  2  CLI usage or input error\n"
            "  3  System or runtime error\n"
        ),
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program version and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan text, files, or stdin for security threats and policy violations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument(
        "text",
        nargs="?",
        default=None,
        help="Text string payload to inspect.",
    )
    scan_parser.add_argument(
        "--file",
        "-f",
        dest="file_path",
        default=None,
        help="Path to file containing text to inspect.",
    )
    scan_parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read text payload from standard input (stdin).",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Output result as structured, machine-readable JSON.",
    )
    scan_parser.add_argument(
        "--direction",
        "-d",
        choices=["input", "output"],
        default="input",
        help="Scan direction: 'input' for user prompts, 'output' for LLM generations (default: input).",
    )
    scan_parser.add_argument(
        "--config",
        "-c",
        dest="config_file",
        default=None,
        help="Path to JSON configuration file for FirewallConfig.",
    )
    scan_parser.add_argument(
        "--policy",
        "-p",
        dest="policy_file",
        default=None,
        help="Path to Policy-as-Code document (.json or .yaml) to enforce.",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Evaluate policy without executing downstream side effects.",
    )
    scan_parser.add_argument(
        "--disable-injection",
        action="store_true",
        help="Disable prompt injection and jailbreak detection for this scan.",
    )
    scan_parser.add_argument(
        "--disable-pii",
        action="store_true",
        help="Disable PII detection for this scan.",
    )
    scan_parser.add_argument(
        "--disable-secrets",
        action="store_true",
        help="Disable secrets and credentials detection for this scan.",
    )

    # policy subcommand
    policy_parser = subparsers.add_parser(
        "policy",
        help="Inspect, validate, and manage Policy-as-Code documents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    policy_subparsers = policy_parser.add_subparsers(dest="policy_subcommand", help="Policy actions")

    # policy validate
    val_parser = policy_subparsers.add_parser(
        "validate",
        help="Validate syntax, schema, and rule integrity of a policy file.",
    )
    val_parser.add_argument("file", help="Path to policy file (.json or .yaml)")
    val_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output validation as JSON")

    # policy show
    show_parser = policy_subparsers.add_parser(
        "show",
        help="Display rules, priorities, and default actions of a policy file.",
    )
    show_parser.add_argument("file", help="Path to policy file (.json or .yaml)")
    show_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output policy details as JSON")

    # tool subcommand (Phase 22)
    tool_parser = subparsers.add_parser(
        "tool",
        help="Inspect and evaluate AI agent tool calls and arguments against security policies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tool_subparsers = tool_parser.add_subparsers(dest="tool_subcommand", help="Tool actions")

    # tool check
    tool_check_parser = tool_subparsers.add_parser(
        "check",
        help="Inspect a tool call (name and JSON arguments) against security guardrails.",
    )
    tool_check_parser.add_argument("name", help="Tool identifier (e.g. 'search_web', 'shell')")
    tool_check_parser.add_argument(
        "--args",
        dest="arguments",
        default="{}",
        help="JSON string or file path containing tool arguments dictionary (default: '{}')",
    )
    tool_check_parser.add_argument(
        "--policy",
        "-p",
        dest="policy_file",
        default=None,
        help="Optional path to custom Policy document (.json or .yaml)",
    )
    tool_check_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Output result as structured JSON",
    )

    # eval subcommand (Phase 23)
    eval_parser = subparsers.add_parser(
        "eval",
        help="Execute AI Security Evaluation suite, red-team simulation, and regression testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    eval_subparsers = eval_parser.add_subparsers(dest="eval_subcommand", help="Evaluation actions")

    # eval run
    eval_run_parser = eval_subparsers.add_parser(
        "run",
        help="Run security evaluation test suite against LLMFirewall.",
    )
    eval_run_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Policy file to test")
    eval_run_parser.add_argument("--baseline", "-b", dest="baseline_file", default=None, help="Baseline JSON to compare against for regressions")
    eval_run_parser.add_argument("--category", "-c", dest="category", default=None, help="Filter by attack category")
    eval_run_parser.add_argument("--severity", "-s", dest="severity", default=None, help="Filter by severity")
    eval_run_parser.add_argument("--tag", "-t", dest="tag", default=None, help="Filter by tag")
    eval_run_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "sarif", "junit"], default="human", help="Output format")
    eval_run_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file")

    # eval baseline
    eval_base_parser = eval_subparsers.add_parser(
        "baseline",
        help="Capture and store a security evaluation baseline JSON file.",
    )
    eval_base_parser.add_argument("--output", "-o", dest="output_path", default="baseline.json", help="Path to write baseline JSON")
    eval_base_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Policy file to evaluate")

    # observe subcommand (Phase 24)
    observe_parser = subparsers.add_parser(
        "observe",
        help="Production observability, security intelligence, event querying, and trends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    observe_subparsers = observe_parser.add_subparsers(dest="observe_subcommand", help="Observability actions")

    # observe summary
    obs_sum_parser = observe_subparsers.add_parser("summary", help="Show operational metrics and security summary.")
    obs_sum_parser.add_argument("--backend", default="sqlite", choices=["sqlite", "jsonl", "memory"], help="Storage backend (default: sqlite)")
    obs_sum_parser.add_argument("--path", dest="storage_path", default=None, help="Path to storage file/database")
    obs_sum_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output summary as JSON")
    obs_sum_parser.add_argument("--prometheus", action="store_true", dest="prometheus_mode", help="Output summary in Prometheus exposition format")

    # observe events
    obs_ev_parser = observe_subparsers.add_parser("events", help="Query and list stored security events.")
    obs_ev_parser.add_argument("--backend", default="sqlite", choices=["sqlite", "jsonl", "memory"], help="Storage backend (default: sqlite)")
    obs_ev_parser.add_argument("--path", dest="storage_path", default=None, help="Path to storage file/database")
    obs_ev_parser.add_argument("--action", choices=["ALLOW", "WARN", "REDACT", "BLOCK"], default=None, help="Filter by action")
    obs_ev_parser.add_argument("--severity", choices=["DEBUG", "INFO", "WARNING", "HIGH", "CRITICAL"], default=None, help="Filter by severity")
    obs_ev_parser.add_argument("--detector", default=None, help="Filter by detector name")
    obs_ev_parser.add_argument("--tool", dest="tool_name", default=None, help="Filter by tool name")
    obs_ev_parser.add_argument("--limit", type=int, default=50, help="Maximum events to return (default: 50)")
    obs_ev_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output events as JSON")

    # observe trends
    obs_tr_parser = observe_subparsers.add_parser("trends", help="Analyze period-over-period security trends and anomalies.")
    obs_tr_parser.add_argument("--backend", default="sqlite", choices=["sqlite", "jsonl", "memory"], help="Storage backend (default: sqlite)")
    obs_tr_parser.add_argument("--path", dest="storage_path", default=None, help="Path to storage file/database")
    obs_tr_parser.add_argument("--window", dest="window_hours", type=int, default=24, help="Window size in hours (default: 24)")
    obs_tr_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output trends as JSON")

    # observe export
    obs_exp_parser = observe_subparsers.add_parser("export", help="Export stored security events.")
    obs_exp_parser.add_argument("--backend", default="sqlite", choices=["sqlite", "jsonl", "memory"], help="Storage backend (default: sqlite)")
    obs_exp_parser.add_argument("--path", dest="storage_path", default=None, help="Path to storage file/database")
    obs_exp_parser.add_argument("--format", dest="format_type", choices=["json", "jsonl", "csv"], default="json", help="Export format (default: json)")
    obs_exp_parser.add_argument("--output", "-o", dest="output_path", default=None, help="Output file path (default: stdout)")

    # -------------------------------------------------------------------------
    # runtime subcommand (Phase 26)
    # -------------------------------------------------------------------------
    runtime_parser = subparsers.add_parser(
        "runtime",
        help="Inspect runtime sessions and simulate agent execution guardrails.",
    )
    runtime_subparsers = runtime_parser.add_subparsers(dest="runtime_subcommand", help="Runtime commands")

    # runtime inspect
    run_ins_parser = runtime_subparsers.add_parser("inspect", help="Inspect an agent runtime session trace.")
    run_ins_parser.add_argument("--trace-id", dest="trace_id", required=False, default=None, help="Trace ID to inspect")
    run_ins_parser.add_argument("--runtime-id", dest="runtime_id", required=False, default=None, help="Runtime session ID")
    run_ins_parser.add_argument("--backend", default="sqlite", choices=["sqlite", "jsonl", "memory"], help="Storage backend (default: sqlite)")
    run_ins_parser.add_argument("--path", dest="storage_path", default=None, help="Path to storage file/database")
    run_ins_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output inspection as JSON")

    # runtime simulate
    run_sim_parser = runtime_subparsers.add_parser("simulate", help="Simulate an agent runtime execution against policies.")
    run_sim_parser.add_argument("--input", "-i", dest="user_input", default="What is 2 + 2?", help="Simulated initial user input")
    run_sim_parser.add_argument("--tool", dest="tool_name", default=None, help="Optional simulated tool name")
    run_sim_parser.add_argument("--args", dest="tool_args", default="{}", help="Simulated tool arguments (JSON string)")
    run_sim_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Path to custom policy file")
    run_sim_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output simulation as JSON")

    # -------------------------------------------------------------------------
    # rag subcommand (Phase 27)
    # -------------------------------------------------------------------------
    rag_parser = subparsers.add_parser(
        "rag",
        help="Scan documents for ingestion and inspect retrieved RAG context.",
    )
    rag_subparsers = rag_parser.add_subparsers(dest="rag_subcommand", help="RAG commands")

    # rag scan
    rag_scan_parser = rag_subparsers.add_parser("scan", help="Scan a document before ingestion/indexing.")
    rag_scan_parser.add_argument("document_path", help="Path to document file to scan")
    rag_scan_parser.add_argument("--doc-id", dest="doc_id", default=None, help="Optional document ID (defaults to filename)")
    rag_scan_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Path to policy file")
    rag_scan_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output scan result as JSON")

    # rag inspect-context
    rag_insp_parser = rag_subparsers.add_parser("inspect-context", help="Inspect and filter retrieved context items.")
    rag_insp_parser.add_argument("--context-file", "-f", dest="context_file", required=True, help="Path to JSON file containing list of chunk objects or strings")
    rag_insp_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Path to policy file")
    rag_insp_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output inspection as JSON")

    # -------------------------------------------------------------------------
    # model subcommand (Phase 28)
    # -------------------------------------------------------------------------
    model_parser = subparsers.add_parser(
        "model",
        help="Inspect and verify model artifacts and weights.",
    )
    model_subparsers = model_parser.add_subparsers(dest="model_subcommand", help="Model actions")

    # model verify
    mod_ver_parser = model_subparsers.add_parser("verify", help="Verify cryptographic hash and format of a model file.")
    mod_ver_parser.add_argument("file_path", help="Path to local model artifact file")
    mod_ver_parser.add_argument("--sha256", dest="sha256", default=None, help="Expected SHA-256 hash")
    mod_ver_parser.add_argument("--sha512", dest="sha512", default=None, help="Expected SHA-512 hash")
    mod_ver_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output verification as JSON")

    # -------------------------------------------------------------------------
    # supply-chain subcommand (Phase 28)
    # -------------------------------------------------------------------------
    sc_parser = subparsers.add_parser(
        "supply-chain",
        help="AI Supply-chain security, dependency scanning, SBOM, and drift detection.",
    )
    sc_subparsers = sc_parser.add_subparsers(dest="supply_chain_subcommand", help="Supply chain actions")

    # supply-chain scan
    sc_scan_parser = sc_subparsers.add_parser("scan", help="Scan dependencies and manifests against policy.")
    sc_scan_parser.add_argument("--manifest", "-m", dest="manifest_file", default=None, help="Path to models manifest YAML")
    sc_scan_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Path to policy YAML/JSON")
    sc_scan_parser.add_argument("--offline", action="store_true", default=True, help="Perform scan offline")
    sc_scan_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output scan as JSON")

    # supply-chain dependencies
    sc_dep_parser = sc_subparsers.add_parser("dependencies", help="List installed dependencies inventory.")
    sc_dep_parser.add_argument("--format", dest="format_type", choices=["table", "json"], default="table", help="Output format")
    sc_dep_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output as JSON")

    # supply-chain sbom
    sc_sbom_parser = sc_subparsers.add_parser("sbom", help="Export CycloneDX-compatible or normalized SBOM.")
    sc_sbom_parser.add_argument("--format", dest="format_type", choices=["cyclonedx", "normalized"], default="cyclonedx", help="SBOM standard format")
    sc_sbom_parser.add_argument("--output", "-o", dest="output_path", default=None, help="Output file path (default stdout)")

    # supply-chain snapshot
    sc_snap_parser = sc_subparsers.add_parser("snapshot", help="Create a deterministic AI security snapshot.")
    sc_snap_parser.add_argument("--output", "-o", dest="output_path", default=None, help="Output file path")

    # supply-chain diff
    sc_diff_parser = sc_subparsers.add_parser("diff", help="Compare two security snapshot files to detect drift.")
    sc_diff_parser.add_argument("snapshot_a", help="Path to baseline snapshot JSON")
    sc_diff_parser.add_argument("snapshot_b", help="Path to candidate snapshot JSON")
    sc_diff_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output diff as JSON")

    # -------------------------------------------------------------------------
    # agent subcommand (Phase 29)
    # -------------------------------------------------------------------------
    agent_parser = subparsers.add_parser(
        "agent",
        help="Agent capability security, action budgets, and capability authorization.",
    )
    agent_subparsers = agent_parser.add_subparsers(dest="agent_subcommand", help="Agent actions")

    # agent capabilities
    ag_caps_parser = agent_subparsers.add_parser("capabilities", help="List standard capabilities and action classifications.")
    ag_caps_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output capabilities as JSON")

    # agent policy-check
    ag_chk_parser = agent_subparsers.add_parser("policy-check", help="Simulate capability authorization for an agent action.")
    ag_chk_parser.add_argument("capability_name", help="Capability name (e.g. 'filesystem.read', 'shell.execute')")
    ag_chk_parser.add_argument("--agent-id", dest="agent_id", default="default_agent", help="Agent identifier")
    ag_chk_parser.add_argument("--resource", dest="resource", default=None, help="Target resource or path")
    ag_chk_parser.add_argument("--tool", dest="tool_name", default="custom_tool", help="Tool name")
    ag_chk_parser.add_argument("--grant", dest="grant_capability", default=None, help="Pre-grant capability to agent for test")
    ag_chk_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output result as JSON")

    # -------------------------------------------------------------------------
    # test subcommand (Phase 30: Continuous AI Security Testing)
    # -------------------------------------------------------------------------
    test_parser = subparsers.add_parser(
        "test",
        help="Continuous AI security testing, red-team benchmarks, and regression validation.",
    )
    test_subparsers = test_parser.add_subparsers(dest="test_subcommand", help="Test actions")

    # test security
    t_sec_parser = test_subparsers.add_parser("security", help="Execute AI security test suite.")
    t_sec_parser.add_argument(
        "--suite",
        dest="suite",
        default="core",
        help="Security test suite to run (core, prompt-injection, pii, secrets, tool, agent, rag, memory, supply-chain, config, regression, all).",
    )
    t_sec_parser.add_argument("--ci", action="store_true", dest="ci", help="CI mode enforcing strict pass/fail exit codes.")
    t_sec_parser.add_argument(
        "--format",
        dest="format_type",
        choices=["human", "json", "sarif", "junit", "html"],
        default="human",
        help="Report output format (default: human).",
    )
    t_sec_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Path to write test report.")
    t_sec_parser.add_argument("--workers", "-w", type=int, dest="workers", default=1, help="Parallel worker threads (default: 1).")
    t_sec_parser.add_argument("--seed", type=int, dest="seed", default=None, help="Deterministic random seed.")
    t_sec_parser.add_argument("--baseline", dest="baseline_file", default=None, help="Baseline JSON report for regression comparison.")
    t_sec_parser.add_argument("--target", dest="target_type", choices=["firewall", "mock", "http"], default="firewall", help="Target type.")
    t_sec_parser.add_argument("--endpoint", dest="endpoint", default=None, help="Target URL when target is 'http'.")
    t_sec_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Policy-as-Code file to enforce.")

    # test list
    t_list_parser = test_subparsers.add_parser("list", help="List available security test definitions.")
    t_list_parser.add_argument("--suite", dest="suite_name", default=None, help="Filter tests by suite name.")
    t_list_parser.add_argument("--category", dest="category", default=None, help="Filter tests by attack category.")
    t_list_parser.add_argument("--tag", dest="tag", default=None, help="Filter tests by metadata tag.")
    t_list_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output test definitions as JSON.")

    # test suites
    t_suites_parser = test_subparsers.add_parser("suites", help="List pre-built security test suites.")
    t_suites_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output suite information as JSON.")

    # test run
    t_run_parser = test_subparsers.add_parser("run", help="Run a specific test case or targeted category.")
    t_run_parser.add_argument("test_id", nargs="?", default=None, help="Specific test ID to execute (e.g. 'PI-001').")
    t_run_parser.add_argument("--category", dest="category", default=None, help="Filter by attack category.")
    t_run_parser.add_argument("--tag", dest="tag", default=None, help="Filter by tag.")
    t_run_parser.add_argument("--workers", type=int, dest="workers", default=1, help="Parallel worker threads.")
    t_run_parser.add_argument("--format", dest="format_type", choices=["human", "json", "html"], default="human", help="Report format.")
    t_run_parser.add_argument("--target", dest="target_type", choices=["firewall", "mock", "http"], default="firewall", help="Target type.")
    t_run_parser.add_argument("--endpoint", dest="endpoint", default=None, help="Target endpoint.")
    t_run_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Policy file.")

    # gate subcommand (Phase 31)
    gate_parser = subparsers.add_parser(
        "gate",
        help="Evaluate security gates, continuous assurance, and release readiness.",
    )
    gate_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Path to governance policy YAML/JSON.")
    gate_parser.add_argument("--ci", action="store_true", dest="ci", help="CI mode: non-zero exit code if blocked/failed.")
    gate_parser.add_argument("--baseline", "-b", dest="baseline_file", default=None, help="Path to security baseline JSON.")
    gate_parser.add_argument("--results", "-r", dest="results_file", default=None, help="Path to security test results JSON.")
    gate_parser.add_argument("--snapshot", "-s", dest="snapshot_file", default=None, help="Path to security snapshot JSON.")
    gate_parser.add_argument("--changed", action="store_true", dest="changed", help="Evaluate controls for changed components.")
    gate_parser.add_argument("--offline", action="store_true", dest="offline", help="Run in offline mode.")
    gate_parser.add_argument(
        "--format",
        dest="format_type",
        choices=["human", "json", "sarif"],
        default="human",
        help="Output report format (default: human).",
    )
    gate_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Path to save report output.")
    gate_parser.add_argument("--override-reason", dest="override_reason", default=None, help="Auditable justification for emergency override.")
    gate_parser.add_argument("--override-owner", dest="override_owner", default=None, help="Authorized owner for emergency override.")

    # baseline subcommand (Phase 31)
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Create and compare cryptographically anchored security baselines.",
    )
    base_subparsers = baseline_parser.add_subparsers(dest="baseline_subcommand", help="Baseline actions")

    # baseline create
    b_create_parser = base_subparsers.add_parser("create", help="Create a reproducible security baseline.")
    b_create_parser.add_argument("--output", "-o", dest="output_path", required=True, help="Output path for baseline JSON.")
    b_create_parser.add_argument("--id", dest="baseline_id", default=None, help="Custom baseline identifier.")
    b_create_parser.add_argument("--results", "-r", dest="results_file", default=None, help="Path to security test results JSON.")
    b_create_parser.add_argument("--snapshot", "-s", dest="snapshot_file", default=None, help="Path to security snapshot JSON.")
    b_create_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Path to policy YAML/JSON.")
    b_create_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output creation summary as JSON.")

    # baseline compare
    b_comp_parser = base_subparsers.add_parser("compare", help="Compare current evaluation against a baseline.")
    b_comp_parser.add_argument("--current", "-c", dest="current_file", required=True, help="Current test results/findings JSON.")
    b_comp_parser.add_argument("--baseline", "-b", dest="baseline_file", required=True, help="Security baseline JSON.")
    b_comp_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output comparison result as JSON.")

    # graph subcommand (Phase 32)
    graph_parser = subparsers.add_parser(
        "graph",
        help="Inspect, query, and analyze the AI security knowledge graph.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    graph_subparsers = graph_parser.add_subparsers(dest="graph_subcommand", help="Graph actions")

    # graph nodes
    g_nodes_parser = graph_subparsers.add_parser("nodes", help="List nodes in the security knowledge graph.")
    g_nodes_parser.add_argument("--type", "-t", dest="type_filter", default=None, help="Filter by node type (e.g. agent, tool, model).")
    g_nodes_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    g_nodes_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output nodes as JSON.")

    # graph relationships
    g_rel_parser = graph_subparsers.add_parser("relationships", help="List relationships in the security knowledge graph.")
    g_rel_parser.add_argument("--type", "-t", dest="type_filter", default=None, help="Filter by relationship type (e.g. USES, CAN_CALL).")
    g_rel_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    g_rel_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output relationships as JSON.")

    # graph show
    g_show_parser = graph_subparsers.add_parser("show", help="Show details and connections for a specific node.")
    g_show_parser.add_argument("node_id", help="Identifier of the node to inspect.")
    g_show_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    g_show_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output node details as JSON.")

    # graph path
    g_path_parser = graph_subparsers.add_parser("path", help="Find path between two knowledge graph nodes.")
    g_path_parser.add_argument("source", help="Source node ID.")
    g_path_parser.add_argument("target", help="Target node ID.")
    g_path_parser.add_argument("--max-depth", "-d", dest="max_depth", type=int, default=4, help="Maximum traversal depth (default: 4).")
    g_path_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    g_path_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output path as JSON.")

    # graph impact
    g_impact_parser = graph_subparsers.add_parser("impact", help="Analyze security impact, blast radius, or control coverage for an asset.")
    g_impact_parser.add_argument("asset_id", help="Asset identifier to analyze.")
    g_impact_parser.add_argument("--mode", "-m", dest="mode", choices=["impact", "blast", "coverage"], default="impact", help="Analysis mode (impact, blast, coverage).")
    g_impact_parser.add_argument("--max-depth", "-d", dest="max_depth", type=int, default=2, help="Maximum traversal depth (default: 2).")
    g_impact_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    g_impact_parser.add_argument("--format", dest="format_type", default=None, help="Output format: 'json' or human-readable.")
    g_impact_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output impact as JSON.")

    # graph export
    g_exp_parser = graph_subparsers.add_parser("export", help="Export security knowledge graph to JSON.")
    g_exp_parser.add_argument("--output", "-o", dest="output_file", default="security_graph.json", help="Output file path (default: security_graph.json).")
    g_exp_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Input knowledge graph JSON file (defaults to active firewall graph).")

    # graph import
    g_imp_parser = graph_subparsers.add_parser("import", help="Import and validate a knowledge graph JSON file.")
    g_imp_parser.add_argument("input_file", help="Path to knowledge graph JSON file to import.")
    g_imp_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Optional output path to re-export validated graph.")

    # attack subcommand (Phase 33)
    attack_parser = subparsers.add_parser(
        "attack",
        help="Discover, query, and analyze multi-step AI attack paths.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    attack_subparsers = attack_parser.add_subparsers(dest="attack_subcommand", help="Attack graph actions")

    # attack paths
    a_paths_parser = attack_subparsers.add_parser("paths", help="Discover candidate or validated AI attack paths.")
    a_paths_parser.add_argument("--source", "-s", dest="source", default=None, help="Optional source asset or entry point.")
    a_paths_parser.add_argument("--target", "-t", dest="target", default=None, help="Optional target crown-jewel asset.")
    a_paths_parser.add_argument("--max-depth", "-d", dest="max_depth", type=int, default=5, help="Maximum traversal depth (default: 5).")
    a_paths_parser.add_argument("--status", dest="status_filter", default=None, help="Filter by path status (CANDIDATE, SUPPORTED, TESTED, OBSERVED, BLOCKED).")
    a_paths_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "sarif"], default="human", help="Output format.")
    a_paths_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    a_paths_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")

    # attack path
    a_path_parser = attack_subparsers.add_parser("path", help="Query specific attack path between source and target.")
    a_path_parser.add_argument("--source", "-s", dest="source", required=True, help="Source asset ID.")
    a_path_parser.add_argument("--target", "-t", dest="target", required=True, help="Target asset ID.")
    a_path_parser.add_argument("--max-depth", "-d", dest="max_depth", type=int, default=5, help="Maximum traversal depth (default: 5).")
    a_path_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "sarif"], default="human", help="Output format.")
    a_path_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")

    # threat-model subcommand (Phase 33)
    tm_parser = subparsers.add_parser(
        "threat-model",
        help="Generate, analyze, or export comprehensive AI Threat Models.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tm_parser.add_argument("--asset", "-a", dest="asset_id", default=None, help="Scope threat model to asset ID and dependencies.")
    tm_parser.add_argument("--name", "-n", dest="name", default=None, help="Custom threat model name.")
    tm_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "yaml", "yml"], default="human", help="Output format.")
    tm_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")
    tm_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")

    tm_subparsers = tm_parser.add_subparsers(dest="threat_subcommand", help="Threat model actions")
    tm_exp_parser = tm_subparsers.add_parser("export", help="Export threat model to file.")
    tm_exp_parser.add_argument("--asset", "-a", dest="asset_id", default=None, help="Scope threat model to asset ID.")
    tm_exp_parser.add_argument("--name", "-n", dest="name", default=None, help="Custom threat model name.")
    tm_exp_parser.add_argument("--output", "-o", dest="output_file", default="threat_model.json", help="Output file path (default: threat_model.json).")
    tm_exp_parser.add_argument("--format", "-f", dest="format_type", choices=["json", "yaml", "yml"], default="json", help="Export format.")
    tm_exp_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Path to knowledge graph JSON file.")

    # inventory subcommand (Phase 34)
    inv_parser = subparsers.add_parser(
        "inventory",
        help="Discover, catalog, inspect, and diff AI assets and their security exposure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inv_subparsers = inv_parser.add_subparsers(dest="inventory_subcommand", help="Inventory actions")

    # inventory list
    inv_list_parser = inv_subparsers.add_parser("list", help="List AI assets in inventory.")
    inv_list_parser.add_argument("--type", "-t", dest="type_filter", default=None, help="Filter by asset type (e.g. agent, model, tool).")
    inv_list_parser.add_argument("--environment", "-e", dest="env_filter", default=None, help="Filter by environment (development, staging, production).")
    inv_list_parser.add_argument("--status", "-s", dest="status_filter", default=None, help="Filter by status (ACTIVE, INACTIVE, STALE, REMOVED).")
    inv_list_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json"], default="human", help="Output format.")
    inv_list_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output result as JSON.")
    inv_list_parser.add_argument("--inventory", "-i", dest="inventory_file", default=None, help="Optional inventory JSON/YAML file.")
    inv_list_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Optional knowledge graph JSON file.")
    inv_list_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")

    # inventory show
    inv_show_parser = inv_subparsers.add_parser("show", help="Show asset details, provenance, and security attack surface.")
    inv_show_parser.add_argument("asset_id", help="Asset identifier (e.g. 'agent:customer-support', 'model:gpt-4o').")
    inv_show_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json"], default="human", help="Output format.")
    inv_show_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output result as JSON.")
    inv_show_parser.add_argument("--inventory", "-i", dest="inventory_file", default=None, help="Optional inventory JSON/YAML file.")
    inv_show_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Optional knowledge graph JSON file.")

    # inventory discover
    inv_disc_parser = inv_subparsers.add_parser("discover", help="Discover AI assets across config, runtime, dependencies, and code.")
    inv_disc_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json"], default="human", help="Output format.")
    inv_disc_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output result as JSON.")
    inv_disc_parser.add_argument("--config", "-c", dest="config_file", default=None, help="Path to config file.")
    inv_disc_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Optional knowledge graph JSON file to sync with.")
    inv_disc_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write discovery report to file.")

    # inventory export
    inv_exp_parser = inv_subparsers.add_parser("export", help="Export asset inventory snapshot to JSON or YAML.")
    inv_exp_parser.add_argument("output_file", help="Destination file path (.json or .yaml).")
    inv_exp_parser.add_argument("--format", "-f", dest="format_type", choices=["json", "yaml", "yml"], default="json", help="Export format.")
    inv_exp_parser.add_argument("--inventory", "-i", dest="inventory_file", default=None, help="Source inventory JSON/YAML file.")
    inv_exp_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Knowledge graph file.")

    # inventory diff
    inv_diff_parser = inv_subparsers.add_parser("diff", help="Compare two inventory snapshots for architectural and security drift.")
    inv_diff_parser.add_argument("--before", "-b", dest="before_file", required=True, help="Baseline inventory snapshot JSON.")
    inv_diff_parser.add_argument("--after", "-a", dest="after_file", required=True, help="Current inventory snapshot JSON.")
    inv_diff_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json"], default="human", help="Output format.")
    inv_diff_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output diff as JSON.")

    # posture (Phase 35 — AI-SPM)
    posture_parser = subparsers.add_parser(
        "posture",
        help="AI Security Posture Management (AI-SPM) evaluation, baselines, and gap analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    posture_parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target asset ID (e.g. 'agent:customer-support') or action ('summary', 'diff', 'snapshot', 'export').",
    )
    posture_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "sarif"], default="human", help="Output format.")
    posture_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output posture as JSON.")
    posture_parser.add_argument("--sarif", action="store_true", dest="sarif_mode", help="Output actionable posture gaps as SARIF 2.1.0.")
    posture_parser.add_argument("--before", "-b", dest="before_file", default=None, help="Baseline snapshot JSON for diff.")
    posture_parser.add_argument("--after", "-a", dest="after_file", default=None, help="Current snapshot JSON for diff.")
    posture_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")
    posture_parser.add_argument("--inventory", "-i", dest="inventory_file", default=None, help="Optional inventory JSON/YAML file.")
    posture_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Optional knowledge graph JSON file.")
    posture_parser.add_argument("--config", "-c", dest="config_file", default=None, help="Optional Firewall config file.")

    # compliance (Phase 36 — AI Security Compliance & Control Mapping)
    compliance_parser = subparsers.add_parser(
        "compliance",
        help="AI Security Compliance & Control Mapping engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    compliance_parser.add_argument(
        "compliance_target",
        nargs="?",
        default=None,
        help="Target action ('frameworks', 'assess', 'control', 'gaps', 'evidence', 'snapshot', 'diff', 'export') or asset ID.",
    )
    compliance_parser.add_argument(
        "sub_target",
        nargs="?",
        default=None,
        help="Sub-target such as control ID, asset ID, or output file path.",
    )
    compliance_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "yaml", "sarif"], default="human", help="Output format.")
    compliance_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output as JSON.")
    compliance_parser.add_argument("--yaml", action="store_true", dest="yaml_mode", help="Output as YAML.")
    compliance_parser.add_argument("--sarif", action="store_true", dest="sarif_mode", help="Output as SARIF 2.1.0.")
    compliance_parser.add_argument("--framework", dest="framework_id", default=None, help="Target framework ID (e.g. 'ai-security-baseline').")
    compliance_parser.add_argument("--control", dest="control_id", default=None, help="Target control ID (e.g. 'AC-01').")
    compliance_parser.add_argument("--asset", dest="asset_id", default=None, help="Target asset ID (e.g. 'agent:support').")
    compliance_parser.add_argument("--before", "-b", dest="before_file", default=None, help="Baseline snapshot JSON for diff.")
    compliance_parser.add_argument("--after", "-a", dest="after_file", default=None, help="Current snapshot JSON for diff.")
    compliance_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")
    compliance_parser.add_argument("--inventory", "-i", dest="inventory_file", default=None, help="Optional inventory JSON/YAML file.")
    compliance_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Optional knowledge graph JSON file.")
    compliance_parser.add_argument("--config", "-c", dest="config_file", default=None, help="Optional Firewall config file.")

    # risk (Phase 37 — AI Security Risk & Prioritization Engine)
    risk_parser = subparsers.add_parser(
        "risk",
        help="AI Security Risk & Prioritization engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    risk_parser.add_argument(
        "risk_target",
        nargs="?",
        default=None,
        help="Target action ('snapshot', 'diff') or asset ID (e.g. 'agent:support').",
    )
    risk_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "yaml"], default="human", help="Output format.")
    risk_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output as JSON.")
    risk_parser.add_argument("--yaml", action="store_true", dest="yaml_mode", help="Output as YAML.")
    risk_parser.add_argument("--before", "-b", dest="before_file", default=None, help="Baseline snapshot JSON for diff.")
    risk_parser.add_argument("--after", "-a", dest="after_file", default=None, help="Current snapshot JSON for diff.")
    risk_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")
    risk_parser.add_argument("--inventory", "-i", dest="inventory_file", default=None, help="Optional inventory JSON/YAML file.")
    risk_parser.add_argument("--graph", "-g", dest="graph_file", default=None, help="Optional knowledge graph JSON file.")
    risk_parser.add_argument("--config", "-c", dest="config_file", default=None, help="Optional Firewall config file.")

    # incidents (Phase 38 — AI Security Incident Response & Investigation)
    incidents_parser = subparsers.add_parser(
        "incidents",
        help="AI Security Incident Response & Investigation engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    incidents_parser.add_argument(
        "incident_action",
        nargs="?",
        default="list",
        help="Subaction: 'list', 'show', 'timeline', 'export' or incident ID directly.",
    )
    incidents_parser.add_argument(
        "incident_target",
        nargs="?",
        default=None,
        help="Incident ID (e.g. 'INC-001').",
    )
    incidents_parser.add_argument("--status", "-s", dest="status", default=None, help="Filter by incident status.")
    incidents_parser.add_argument("--severity", dest="severity", default=None, help="Filter by incident severity.")
    incidents_parser.add_argument("--asset", "-a", dest="asset_id", default=None, help="Filter by asset ID.")
    incidents_parser.add_argument("--events", "-e", dest="events_file", default=None, help="Path to events JSON file.")
    incidents_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json", "markdown"], default="human", help="Output format.")
    incidents_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output as JSON.")
    incidents_parser.add_argument("--output", "-o", dest="output_file", default=None, help="Write output to file.")

    # protect (Phase 39 — AI Security Runtime Protection & Policy Enforcement)
    protect_parser = subparsers.add_parser(
        "protect",
        help="Real-time AI security runtime protection and policy enforcement.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    protect_parser.add_argument("input_text", nargs="?", default=None, help="Input prompt or message to inspect.")
    protect_parser.add_argument("--input", "-i", dest="opt_input", default=None, help="Input prompt text.")
    protect_parser.add_argument("--tool", "-t", dest="tool_name", default=None, help="Tool name to authorize.")
    protect_parser.add_argument("--tool-args", dest="tool_args", default=None, help="Tool arguments JSON.")
    protect_parser.add_argument("--output", dest="output_text", default=None, help="Model output text to inspect.")
    protect_parser.add_argument("--agent", "-a", dest="agent_id", default=None, help="Target agent identifier.")
    protect_parser.add_argument("--policy", "-p", dest="policy_file", default=None, help="Custom policy YAML/JSON file.")
    protect_parser.add_argument("--mode", "-m", dest="mode", choices=["enforce", "shadow", "disabled"], default="enforce", help="Policy mode.")
    protect_parser.add_argument("--format", "-f", dest="format_type", choices=["human", "json"], default="human", help="Output format.")
    protect_parser.add_argument("--json", action="store_true", dest="json_mode", help="Output as JSON.")
    protect_parser.add_argument("--out-file", "-o", dest="output_file", default=None, help="Write output to file.")

    return parser




def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    from llmfirewall.cli.commands import (
        handle_agent_capabilities,
        handle_agent_policy_check,
        handle_test_security,
        handle_test_list,
        handle_test_suites,
        handle_test_run,
        handle_eval_baseline,
        handle_eval_run,
        handle_model_verify,
        handle_observe_events,
        handle_observe_export,
        handle_observe_summary,
        handle_observe_trends,
        handle_policy_show,
        handle_policy_validate,
        handle_rag_inspect_context,
        handle_rag_scan,
        handle_runtime_inspect,
        handle_runtime_simulate,
        handle_supply_chain_dependencies,
        handle_supply_chain_diff,
        handle_supply_chain_sbom,
        handle_supply_chain_scan,
        handle_supply_chain_snapshot,
        handle_tool_check,
        handle_governance_gate,
        handle_baseline_create,
        handle_baseline_compare,
        handle_graph_nodes,
        handle_graph_relationships,
        handle_graph_show,
        handle_graph_path,
        handle_graph_impact,
        handle_graph_export,
        handle_graph_import,
        handle_attack_paths,
        handle_attack_path,
        handle_threat_model,
        handle_threat_model_export,
        handle_inventory_list,
        handle_inventory_show,
        handle_inventory_discover,
        handle_inventory_export,
        handle_inventory_diff,
        handle_posture_summary,
        handle_posture_show,
        handle_posture_diff,
        handle_posture_snapshot,
        handle_posture_export,
        handle_compliance_frameworks,
        handle_compliance_assess,
        handle_compliance_control,
        handle_compliance_gaps,
        handle_compliance_evidence,
        handle_compliance_snapshot,
        handle_compliance_diff,
        handle_compliance_export,
        handle_risk_prioritize,
        handle_risk_snapshot,
        handle_risk_diff,
        handle_incidents_list,
        handle_incidents_show,
        handle_incidents_timeline,
        handle_incidents_export,
        handle_protect,
    )

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return EXIT_ALLOWED

    if args.subcommand == "scan":
        return handle_scan(
            text=args.text,
            file_path=args.file_path,
            use_stdin=args.stdin,
            direction=args.direction,
            json_mode=args.json_mode,
            config_file=args.config_file,
            policy_file=args.policy_file,
            dry_run=args.dry_run,
            disable_injection=args.disable_injection,
            disable_pii=args.disable_pii,
            disable_secrets=args.disable_secrets,
        )

    if args.subcommand == "policy":
        if args.policy_subcommand == "validate":
            return handle_policy_validate(policy_file=args.file, json_mode=args.json_mode)
        elif args.policy_subcommand == "show":
            return handle_policy_show(policy_file=args.file, json_mode=args.json_mode)
        else:
            parser.parse_args(["policy", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "tool":
        if args.tool_subcommand == "check":
            return handle_tool_check(
                name=args.name,
                arguments_input=args.arguments,
                policy_file=args.policy_file,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["tool", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "eval":
        if args.eval_subcommand == "run":
            return handle_eval_run(
                policy_file=args.policy_file,
                baseline_file=args.baseline_file,
                category=args.category,
                severity=args.severity,
                tag=args.tag,
                format_type=args.format_type,
                output_file=args.output_file,
            )
        elif args.eval_subcommand == "baseline":
            return handle_eval_baseline(
                output_path=args.output_path,
                policy_file=args.policy_file,
            )
        else:
            parser.parse_args(["eval", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "observe":
        if args.observe_subcommand == "summary":
            return handle_observe_summary(
                backend=args.backend,
                storage_path=args.storage_path,
                json_mode=args.json_mode,
                prometheus_mode=args.prometheus_mode,
            )
        elif args.observe_subcommand == "events":
            return handle_observe_events(
                backend=args.backend,
                storage_path=args.storage_path,
                action=args.action,
                severity=args.severity,
                detector=args.detector,
                tool_name=args.tool_name,
                limit=args.limit,
                json_mode=args.json_mode,
            )
        elif args.observe_subcommand == "trends":
            return handle_observe_trends(
                backend=args.backend,
                storage_path=args.storage_path,
                window_hours=args.window_hours,
                json_mode=args.json_mode,
            )
        elif args.observe_subcommand == "export":
            return handle_observe_export(
                backend=args.backend,
                storage_path=args.storage_path,
                output_path=args.output_path,
                format_type=args.format_type,
            )
        else:
            parser.parse_args(["observe", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "runtime":
        if args.runtime_subcommand == "inspect":
            return handle_runtime_inspect(
                trace_id=args.trace_id,
                runtime_id=args.runtime_id,
                backend=args.backend,
                storage_path=args.storage_path,
                json_mode=args.json_mode,
            )
        elif args.runtime_subcommand == "simulate":
            return handle_runtime_simulate(
                user_input=args.user_input,
                tool_name=args.tool_name,
                tool_args=args.tool_args,
                policy_file=args.policy_file,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["runtime", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "rag":
        if args.rag_subcommand == "scan":
            return handle_rag_scan(
                document_path=args.document_path,
                doc_id=args.doc_id,
                policy_file=args.policy_file,
                json_mode=args.json_mode,
            )
        elif args.rag_subcommand == "inspect-context":
            return handle_rag_inspect_context(
                context_file=args.context_file,
                policy_file=args.policy_file,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["rag", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "model":
        if args.model_subcommand == "verify":
            return handle_model_verify(
                file_path=args.file_path,
                sha256=args.sha256,
                sha512=args.sha512,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["model", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "supply-chain":
        if args.supply_chain_subcommand == "scan":
            return handle_supply_chain_scan(
                manifest_file=args.manifest_file,
                policy_file=args.policy_file,
                offline=args.offline,
                json_mode=args.json_mode,
            )
        elif args.supply_chain_subcommand == "dependencies":
            return handle_supply_chain_dependencies(
                format_type=args.format_type,
                json_mode=args.json_mode,
            )
        elif args.supply_chain_subcommand == "sbom":
            return handle_supply_chain_sbom(
                format_type=args.format_type,
                output_path=args.output_path,
            )
        elif args.supply_chain_subcommand == "snapshot":
            return handle_supply_chain_snapshot(
                output_path=args.output_path,
                json_mode=True,
            )
        elif args.supply_chain_subcommand == "diff":
            return handle_supply_chain_diff(
                snapshot_a_path=args.snapshot_a,
                snapshot_b_path=args.snapshot_b,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["supply-chain", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "agent":
        if args.agent_subcommand == "capabilities":
            return handle_agent_capabilities(json_mode=args.json_mode)
        elif args.agent_subcommand == "policy-check":
            return handle_agent_policy_check(
                capability_name=args.capability_name,
                agent_id=args.agent_id,
                resource=args.resource,
                tool_name=args.tool_name,
                grant_capability=args.grant_capability,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["agent", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "test":
        if args.test_subcommand == "security":
            return handle_test_security(
                suite=args.suite,
                ci=args.ci,
                format_type=args.format_type,
                output_file=args.output_file,
                workers=args.workers,
                seed=args.seed,
                baseline_file=args.baseline_file,
                target_type=args.target_type,
                endpoint=args.endpoint,
                policy_file=args.policy_file,
            )
        elif args.test_subcommand == "list":
            return handle_test_list(
                suite_name=args.suite_name,
                category=args.category,
                tag=args.tag,
                json_mode=args.json_mode,
            )
        elif args.test_subcommand == "suites":
            return handle_test_suites(json_mode=args.json_mode)
        elif args.test_subcommand == "run":
            return handle_test_run(
                test_id=args.test_id,
                category=args.category,
                tag=args.tag,
                workers=args.workers,
                format_type=args.format_type,
                target_type=args.target_type,
                endpoint=args.endpoint,
                policy_file=args.policy_file,
            )
        else:
            parser.parse_args(["test", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "gate":
        return handle_governance_gate(
            policy_file=args.policy_file,
            ci=args.ci,
            baseline_file=args.baseline_file,
            results_file=args.results_file,
            snapshot_file=args.snapshot_file,
            changed=args.changed,
            offline=args.offline,
            format_type=args.format_type,
            output_file=args.output_file,
            override_reason=args.override_reason,
            override_owner=args.override_owner,
        )

    if args.subcommand == "baseline":
        if args.baseline_subcommand == "create":
            return handle_baseline_create(
                output_path=args.output_path,
                baseline_id=args.baseline_id,
                results_file=args.results_file,
                snapshot_file=args.snapshot_file,
                policy_file=args.policy_file,
                json_mode=args.json_mode,
            )
        elif args.baseline_subcommand == "compare":
            return handle_baseline_compare(
                current_file=args.current_file,
                baseline_file=args.baseline_file,
                json_mode=args.json_mode,
            )
        else:
            parser.parse_args(["baseline", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "graph":
        if args.graph_subcommand == "nodes":
            return handle_graph_nodes(
                type_filter=args.type_filter,
                json_mode=args.json_mode,
                graph_file=args.graph_file,
            )
        elif args.graph_subcommand == "relationships":
            return handle_graph_relationships(
                type_filter=args.type_filter,
                json_mode=args.json_mode,
                graph_file=args.graph_file,
            )
        elif args.graph_subcommand == "show":
            return handle_graph_show(
                node_id=args.node_id,
                json_mode=args.json_mode,
                graph_file=args.graph_file,
            )
        elif args.graph_subcommand == "path":
            return handle_graph_path(
                source=args.source,
                target=args.target,
                max_depth=args.max_depth,
                json_mode=args.json_mode,
                graph_file=args.graph_file,
            )
        elif args.graph_subcommand == "impact":
            json_m = args.json_mode or (getattr(args, "format_type", None) == "json")
            return handle_graph_impact(
                asset_id=args.asset_id,
                mode=args.mode,
                max_depth=args.max_depth,
                json_mode=json_m,
                graph_file=args.graph_file,
            )
        elif args.graph_subcommand == "export":
            return handle_graph_export(
                output_file=args.output_file,
                graph_file=args.graph_file,
            )
        elif args.graph_subcommand == "import":
            return handle_graph_import(
                input_file=args.input_file,
                output_file=args.output_file,
            )
        else:
            parser.parse_args(["graph", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "attack":
        if args.attack_subcommand == "paths":
            return handle_attack_paths(
                source=args.source,
                target=args.target,
                max_depth=args.max_depth,
                status_filter=args.status_filter,
                format_type=args.format_type,
                graph_file=args.graph_file,
                output_file=args.output_file,
            )
        elif args.attack_subcommand == "path":
            return handle_attack_path(
                source=args.source,
                target=args.target,
                max_depth=args.max_depth,
                format_type=args.format_type,
                graph_file=args.graph_file,
            )
        else:
            parser.parse_args(["attack", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "threat-model":
        if getattr(args, "threat_subcommand", None) == "export":
            out_f = args.output_file or "threat_model.json"
            return handle_threat_model_export(
                output_file=out_f,
                asset_id=args.asset_id,
                name=args.name,
                format_type=args.format_type,
                graph_file=args.graph_file,
            )
        else:
            return handle_threat_model(
                asset_id=args.asset_id,
                name=args.name,
                format_type=args.format_type,
                graph_file=args.graph_file,
                output_file=args.output_file,
            )

    if args.subcommand == "inventory":
        if args.inventory_subcommand == "list":
            fmt = "json" if getattr(args, "json_mode", False) else getattr(args, "format_type", "human")
            return handle_inventory_list(
                type_filter=args.type_filter,
                env_filter=args.env_filter,
                status_filter=args.status_filter,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                output_file=args.output_file,
            )
        elif args.inventory_subcommand == "show":
            fmt = "json" if getattr(args, "json_mode", False) else getattr(args, "format_type", "human")
            return handle_inventory_show(
                asset_id=args.asset_id,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
            )
        elif args.inventory_subcommand == "discover":
            fmt = "json" if getattr(args, "json_mode", False) else getattr(args, "format_type", "human")
            return handle_inventory_discover(
                format_type=fmt,
                config_file=args.config_file,
                graph_file=args.graph_file,
                output_file=args.output_file,
            )
        elif args.inventory_subcommand == "export":
            return handle_inventory_export(
                output_file=args.output_file,
                format_type=args.format_type,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
            )
        elif args.inventory_subcommand == "diff":
            fmt = "json" if getattr(args, "json_mode", False) else getattr(args, "format_type", "human")
            return handle_inventory_diff(
                before_file=args.before_file,
                after_file=args.after_file,
                format_type=fmt,
            )
        else:
            parser.parse_args(["inventory", "--help"])
            return EXIT_USAGE_ERROR

    if args.subcommand == "posture":
        if getattr(args, "sarif_mode", False):
            fmt = "sarif"
        elif getattr(args, "json_mode", False):
            fmt = "json"
        else:
            fmt = getattr(args, "format_type", "human")

        target = getattr(args, "target", None)

        if target == "diff" or (args.before_file and args.after_file):
            if not args.before_file or not args.after_file:
                print("Error: --before and --after snapshot files are required for posture diff.", file=sys.stderr)
                return EXIT_USAGE_ERROR
            return handle_posture_diff(
                before_file=args.before_file,
                after_file=args.after_file,
                format_type=fmt,
                output_file=args.output_file,
            )
        elif target == "snapshot":
            return handle_posture_snapshot(
                output_file=args.output_file,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
            )
        elif target == "export":
            out_f = args.output_file or ("posture.sarif" if fmt == "sarif" else "posture.json")
            return handle_posture_export(
                output_file=out_f,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
            )
        elif target == "summary" or target is None:
            return handle_posture_summary(
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )
        else:
            return handle_posture_show(
                asset_id=target,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )

    if args.subcommand == "compliance":
        if getattr(args, "sarif_mode", False):
            fmt = "sarif"
        elif getattr(args, "yaml_mode", False):
            fmt = "yaml"
        elif getattr(args, "json_mode", False):
            fmt = "json"
        else:
            fmt = getattr(args, "format_type", "human")

        target = getattr(args, "compliance_target", None)
        sub_target = getattr(args, "sub_target", None)

        if target == "frameworks":
            return handle_compliance_frameworks(
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )
        elif target == "control":
            cid = sub_target or args.control_id
            if not cid:
                print("Error: Control ID is required (e.g. 'llmfirewall compliance control AC-01').", file=sys.stderr)
                return EXIT_USAGE_ERROR
            return handle_compliance_control(
                control_id=cid,
                asset_id=args.asset_id,
                framework_id=args.framework_id,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )
        elif target == "gaps":
            return handle_compliance_gaps(
                framework_id=args.framework_id,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )
        elif target == "evidence":
            return handle_compliance_evidence(
                asset_id=args.asset_id,
                control_id=args.control_id or sub_target,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )
        elif target == "snapshot":
            return handle_compliance_snapshot(
                output_file=args.output_file or sub_target,
                framework_id=args.framework_id,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
            )
        elif target == "diff" or (args.before_file and args.after_file):
            if not args.before_file or not args.after_file:
                print("Error: Both --before and --after snapshot files are required for compliance diff.", file=sys.stderr)
                return EXIT_USAGE_ERROR
            return handle_compliance_diff(
                before_file=args.before_file,
                after_file=args.after_file,
                format_type=fmt,
                output_file=args.output_file,
            )
        elif target == "export":
            out_f = sub_target or args.output_file or "compliance_report.json"
            return handle_compliance_export(
                output_file=out_f,
                format_type=fmt if fmt != "human" else None,
                framework_id=args.framework_id,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
            )
        elif target == "assess" or target is None:
            aid = sub_target or args.asset_id
            return handle_compliance_assess(
                asset_id=aid,
                framework_id=args.framework_id,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )
        else:
            return handle_compliance_assess(
                asset_id=target,
                framework_id=args.framework_id,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )

    if args.subcommand == "risk":
        if getattr(args, "yaml_mode", False):
            fmt = "yaml"
        elif getattr(args, "json_mode", False):
            fmt = "json"
        else:
            fmt = getattr(args, "format_type", "human")

        target = getattr(args, "risk_target", None)

        if target == "snapshot":
            return handle_risk_snapshot(
                output_file=args.output_file,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
            )
        elif target == "diff" or (args.before_file and args.after_file):
            if not args.before_file or not args.after_file:
                print("Error: Both --before and --after files are required for risk diff.", file=sys.stderr)
                return EXIT_USAGE_ERROR
            return handle_risk_diff(
                before_file=args.before_file,
                after_file=args.after_file,
                format_type=fmt,
                output_file=args.output_file,
            )
        else:
            return handle_risk_prioritize(
                asset_id=target,
                format_type=fmt,
                inventory_file=args.inventory_file,
                graph_file=args.graph_file,
                config_file=args.config_file,
                output_file=args.output_file,
            )

    if args.subcommand == "incidents":
        fmt = "json" if getattr(args, "json_mode", False) else getattr(args, "format_type", "human")
        action = getattr(args, "incident_action", "list")
        target = getattr(args, "incident_target", None)

        # Allow shortcut: llmfirewall incidents INC-001
        if action and action.upper().startswith("INC-") and not target:
            target = action
            action = "show"

        if action == "list" or (not action and not target):
            return handle_incidents_list(
                status=args.status,
                severity=args.severity,
                asset_id=args.asset_id,
                events_file=args.events_file,
                format_type=fmt,
                output_file=args.output_file,
            )
        elif action == "show":
            inc_id = target or "INC-001"
            return handle_incidents_show(
                incident_id=inc_id,
                events_file=args.events_file,
                format_type=fmt,
                output_file=args.output_file,
            )
        elif action == "timeline":
            inc_id = target or "INC-001"
            return handle_incidents_timeline(
                incident_id=inc_id,
                events_file=args.events_file,
                format_type=fmt,
                output_file=args.output_file,
            )
        elif action == "export":
            inc_id = target or "INC-001"
            exp_fmt = "json" if fmt == "json" else "markdown"
            return handle_incidents_export(
                incident_id=inc_id,
                events_file=args.events_file,
                format_type=exp_fmt,
                output_file=args.output_file,
            )
        else:
            # If action wasn't recognized but could be an incident ID
            return handle_incidents_show(
                incident_id=action,
                events_file=args.events_file,
                format_type=fmt,
                output_file=args.output_file,
            )

    if args.subcommand == "protect":
        in_text = getattr(args, "opt_input", None) or getattr(args, "input_text", None)
        fmt = "json" if getattr(args, "json_mode", False) else getattr(args, "format_type", "human")
        return handle_protect(
            input_text=in_text,
            tool_name=args.tool_name,
            tool_args=args.tool_args,
            output_text=args.output_text,
            agent_id=args.agent_id,
            policy_file=args.policy_file,
            mode=args.mode,
            format_type=fmt,
            output_file=args.output_file,
        )

    return EXIT_USAGE_ERROR




if __name__ == "__main__":
    sys.exit(main())
