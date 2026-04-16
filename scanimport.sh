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
    echo -e "    ${GREEN}import${NC}     Import scan results from a directory or file"
    echo -e "    ${GREEN}dry-run${NC}    Preview the LLM mapping without submitting"
    echo ""
    echo -e "  ${BOLD}Required:${NC}"
    echo -e "    ${CYAN}--app-id${NC} ${DIM}<id>${NC}      Target app ID in Vulnapps"
    echo -e "    ${CYAN}--dir${NC} ${DIM}<path>${NC}        Directory containing .md scan files"
    echo -e "    ${CYAN}--file${NC} ${DIM}<path>${NC}       Single .md file (instead of --dir)"
    echo ""
    echo -e "  ${BOLD}Optional:${NC}"
    echo -e "    ${CYAN}--url${NC} ${DIM}<url>${NC}         Vulnapps URL (default: \$VULNAPPS_URL)"
    echo -e "    ${CYAN}--api-key${NC} ${DIM}<key>${NC}     API key (default: \$VULNAPPS_API_KEY)"
    echo -e "    ${CYAN}--private${NC}            Make scan private (default: public)"
    echo -e "    ${CYAN}--notes${NC} ${DIM}<text>${NC}      Notes to attach to the scan"
    echo -e "    ${CYAN}--model${NC} ${DIM}<model>${NC}     Claude model (default: claude-sonnet-4-20250514)"
    echo ""
    echo -e "  ${BOLD}Environment:${NC}"
    echo -e "    ${DIM}VULNAPPS_URL${NC}                  Vulnapps instance URL"
    echo -e "    ${DIM}VULNAPPS_API_KEY${NC}              API key (vuln-mapper scope)"
    echo -e "    ${DIM}ANTHROPIC_API_KEY${NC}             Anthropic API key"
    echo -e "    ${DIM}CLAUDE_CODE_USE_VERTEX=1${NC}      Use Vertex AI instead"
    echo -e "    ${DIM}ANTHROPIC_VERTEX_PROJECT_ID${NC}   GCP project for Vertex"
    echo -e "    ${DIM}ANTHROPIC_VERTEX_LOCATION${NC}     Vertex region"
    echo ""
    echo -e "  ${BOLD}Examples:${NC}"
    echo -e "    ./scanimport.sh dry-run --app-id 1 --dir ./scan-results/"
    echo -e "    ./scanimport.sh import --app-id 1 --file ./zap-scan.md"
    echo -e "    ./scanimport.sh import --app-id 1 --dir ./scans/ --private --notes \"Q1 batch\""
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

    if [ -z "$VULNAPPS_URL" ] && ! echo "$@" | grep -q -- "--url"; then
        echo -e "  ${RED}✗${NC} No Vulnapps URL. Set ${CYAN}VULNAPPS_URL${NC} or pass ${CYAN}--url${NC}"
        errors=1
    fi

    if [ -z "$VULNAPPS_API_KEY" ] && ! echo "$@" | grep -q -- "--api-key"; then
        echo -e "  ${RED}✗${NC} No API key. Set ${CYAN}VULNAPPS_API_KEY${NC} or pass ${CYAN}--api-key${NC}"
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

        # Build args — inject --url from env if not explicitly passed
        ARGS=()
        if ! echo "$@" | grep -q -- "--url"; then
            ARGS+=(--url "$VULNAPPS_URL")
        fi

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
