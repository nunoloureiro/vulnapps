#!/bin/bash
# Import security scan results into Vulnapps with LLM-assisted vuln mapping

set -e

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"
TOOL="$SCRIPT_DIR/tools/import_scan.py"

header() {
    echo ""
    echo -e "  ${BOLD}${CYAN}🛡 Vulnapps Scan Importer${NC}"
    echo -e "  ${DIM}─────────────────────────${NC}"
    echo ""
}

show_help() {
    header
    echo -e "  ${BOLD}Usage:${NC} ./scanimport.sh ${DIM}<command> [options]${NC}"
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo -e "    ${GREEN}import${NC}     Import scan results from a directory, file, or Probely"
    echo -e "    ${GREEN}dry-run${NC}    Preview the LLM mapping without submitting"
    echo ""
    echo -e "  ${BOLD}Target app${NC} ${DIM}(one of)${NC}${BOLD}:${NC}"
    echo -e "    ${CYAN}--app-id${NC} ${DIM}<id>${NC}              Existing app ID in Vulnapps"
    echo -e "    ${CYAN}--app-name${NC} ${DIM}<name>${NC}          Look up by name; create if missing"
    echo -e "      ${CYAN}--app-version${NC} ${DIM}<v>${NC}        Version for lookup/creation (default: empty)"
    echo -e "      ${CYAN}--app-url${NC} ${DIM}<url>${NC}          App URL ${DIM}(create only)${NC}"
    echo -e "      ${CYAN}--app-description${NC} ${DIM}<t>${NC}    App description ${DIM}(create only)${NC}"
    echo -e "      ${CYAN}--app-tech${NC} ${DIM}<list>${NC}        Comma-separated tech stack ${DIM}(create only)${NC}"
    echo -e "      ${CYAN}--app-visibility${NC} ${DIM}<v>${NC}     public|private|team ${DIM}(create only, default: private)${NC}"
    echo ""
    echo -e "  ${BOLD}Scan source${NC} ${DIM}(one of)${NC}${BOLD}:${NC}"
    echo -e "    ${CYAN}--dir${NC} ${DIM}<path>${NC}               Directory containing .md scan files"
    echo -e "    ${CYAN}--file${NC} ${DIM}<path>${NC}              Single .md file"
    echo -e "    ${CYAN}--probely${NC} ${DIM}<ids>${NC}            Probely scan ID(s), comma-separated (max 2)"
    echo ""
    echo -e "  ${BOLD}Connection:${NC}"
    echo -e "    ${CYAN}--url${NC} ${DIM}<url>${NC}                Vulnapps URL (default: \$VULNAPPS_URL)"
    echo -e "    ${CYAN}--api-key${NC} ${DIM}<key>${NC}            API key (default: \$VULNAPPS_API_KEY)"
    echo ""
    echo -e "  ${BOLD}Scan metadata:${NC}"
    echo -e "    ${CYAN}--scanner${NC} ${DIM}<name>${NC}           Override LLM-detected scanner name"
    echo -e "    ${CYAN}--scan-date${NC} ${DIM}<YYYY-MM-DD>${NC}   Override LLM-detected scan date"
    echo -e "    ${CYAN}--public${NC}                    Make scan public (default: private)"
    echo -e "    ${CYAN}--labels${NC} ${DIM}<list>${NC}            Comma-separated labels ${DIM}(auto-created if missing)${NC}"
    echo -e "    ${CYAN}--notes${NC} ${DIM}<text>${NC}             Notes to attach to the scan"
    echo -e "    ${CYAN}--cost${NC} ${DIM}<usd>${NC}               Scan cost in USD ${DIM}(private, for LLM-based scans)${NC}"
    echo -e "    ${CYAN}--tokens${NC} ${DIM}<n>${NC}               Token count ${DIM}(private, auto-captured if omitted)${NC}"
    echo -e "    ${CYAN}--duration${NC} ${DIM}<sec>${NC}           Scan duration in seconds ${DIM}(private)${NC}"
    echo ""
    echo -e "  ${BOLD}LLM mapping${NC} ${DIM}(used by the importer to map findings to known vulns)${NC}${BOLD}:${NC}"
    echo -e "    ${CYAN}--model${NC} ${DIM}<model>${NC}            Claude model used by the importer for mapping"
    echo -e "                            ${DIM}(default: claude-sonnet-4-20250514)${NC}"
    echo -e "                            ${DIM}This is NOT the model used to run the scan itself —${NC}"
    echo -e "                            ${DIM}record that with a label (see examples).${NC}"
    echo -e "    ${CYAN}--provider${NC} ${DIM}<p>${NC}             anthropic|vertex ${DIM}(default: auto from CLAUDE_CODE_USE_VERTEX)${NC}"
    echo -e "    ${CYAN}--vertex-region${NC} ${DIM}<r>${NC}        Vertex region (default: \$ANTHROPIC_VERTEX_LOCATION or us-east5)"
    echo -e "    ${CYAN}--vertex-project${NC} ${DIM}<p>${NC}       GCP project ID (default: \$ANTHROPIC_VERTEX_PROJECT_ID)"
    echo ""
    echo -e "  ${BOLD}Flow:${NC}"
    echo -e "    ${CYAN}--confirm${NC}                  Ask for confirmation before submitting"
    echo ""
    echo -e "  ${BOLD}Environment:${NC}"
    echo -e "    ${DIM}VULNAPPS_URL${NC}                  Vulnapps instance URL"
    echo -e "    ${DIM}VULNAPPS_API_KEY${NC}              API key (vuln-mapper scope)"
    echo -e "    ${DIM}ANTHROPIC_API_KEY${NC}             Anthropic API key"
    echo -e "    ${DIM}CLAUDE_CODE_USE_VERTEX=1${NC}      Use Vertex AI instead"
    echo -e "    ${DIM}ANTHROPIC_VERTEX_PROJECT_ID${NC}   GCP project for Vertex"
    echo -e "    ${DIM}ANTHROPIC_VERTEX_LOCATION${NC}     Vertex region"
    echo -e "    ${DIM}PROBELY_API_KEY${NC}               Probely API key (required for --probely)"
    echo ""
    echo -e "  ${BOLD}Examples:${NC}"
    echo -e "    ./scanimport.sh dry-run --app-id 1 --dir ./scan-results/"
    echo -e "    ./scanimport.sh import --app-id 1 --file ./zap-scan.md"
    echo -e "    ./scanimport.sh import --app-name juice-shop --app-version 14 --file ./scan.md"
    echo -e "    ./scanimport.sh import --app-id 1 --dir ./scans/ --labels \"claude-opus-4-6,greybox\""
    echo -e "    ./scanimport.sh import --app-id 1 --probely abc123,def456"
    echo ""
}

# ── Preflight checks ─────────────────────────────────────────

preflight() {
    local errors=0

    if [ ! -f "$PYTHON" ]; then
        echo -e "  ${RED}✗${NC} Python venv not found at ${DIM}$PYTHON${NC}"
        echo -e "    Run: ${CYAN}python3 -m venv .venv && .venv/bin/pip install httpx \"anthropic[vertex]\"${NC}"
        errors=1
    fi

    if [ ! -f "$TOOL" ]; then
        echo -e "  ${RED}✗${NC} import_scan.py not found at ${DIM}$TOOL${NC}"
        errors=1
    fi

    if [ -z "$VULNAPPS_URL" ] && [ -z "$VULNAPPS_API_KEY" ]; then
        echo -e "  ${RED}✗${NC} Set ${CYAN}VULNAPPS_URL${NC} and ${CYAN}VULNAPPS_API_KEY${NC} environment variables"
        errors=1
    fi

    if [ "$errors" -eq 1 ]; then
        echo ""
        exit 1
    fi
}

# ── Main ──────────────────────────────────────────────────────

if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
    exit 0
fi

COMMAND="$1"
shift

case "$COMMAND" in
    import|dry-run)
        header
        preflight "$@"

        ARGS=()
        if [ "$COMMAND" = "dry-run" ]; then
            ARGS+=(--dry-run)
        fi

        exec "$PYTHON" "$TOOL" "${ARGS[@]}" "$@"
        ;;
    *)
        echo -e "\n  ${RED}✗${NC} Unknown command: ${RED}${COMMAND}${NC}"
        show_help
        exit 1
        ;;
esac
