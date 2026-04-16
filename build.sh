#!/bin/bash
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

echo ""
echo -e "${CYAN}  ───────────────────────────────────────────────────────────${NC}"
echo -e "${BOLD}${YELLOW}   __      __    _                                          ${NC}"
echo -e "${BOLD}${YELLOW}   \\ \\    / /   | |                                         ${NC}"
echo -e "${BOLD}${YELLOW}    \\ \\  / /   _| |_ __   __ _ _ __  _ __  ___              ${NC}"
echo -e "${BOLD}${YELLOW}     \\ \\/ / | | | | '_ \\ / _\` | '_ \\| '_ \\/ __|             ${NC}"
echo -e "${BOLD}${YELLOW}      \\  /| |_| | | | | | (_| | |_) | |_) \\__ \\             ${NC}"
echo -e "${BOLD}${YELLOW}       \\/  \\__,_|_|_| |_|\\__,_| .__/| .__/|___/             ${NC}"
echo -e "${BOLD}${YELLOW}                               | |   | |                    ${NC}"
echo -e "${BOLD}${YELLOW}                               |_|   |_|                    ${NC}"
echo -e "${CYAN}  ───────────────────────────────────────────────────────────${NC}"
echo ""

IMAGE="nunoloureiro/vulnapps:latest"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python"

show_help() {
    echo -e "${BOLD}Usage:${NC} ./build.sh [OPTIONS]"
    echo ""
    echo "  Build, test, and push the Vulnapps Docker image."
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${CYAN}--prune${NC}    Prune unused Docker images after build"
    echo -e "  ${CYAN}--help${NC}     Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./build.sh            Build and push"
    echo "  ./build.sh --prune    Build, push, and prune unused images"
}

DO_PRUNE=false

for arg in "$@"; do
    case "$arg" in
        --prune) DO_PRUNE=true ;;
        --help|-h) show_help; exit 0 ;;
        *) echo -e "${RED}Unknown option: $arg${NC}"; show_help; exit 1 ;;
    esac
done

# ── Tests ──────────────────────────────────────────────────────
echo -e "  ${BLUE}${BOLD}[1/3]${NC} ${BOLD}Running tests...${NC}"
echo -e "  ${DIM}─────────────────────────────────────────${NC}"

"$PYTHON" -m pytest -q 2>/dev/null || TEST_EXIT=$?
TEST_EXIT=${TEST_EXIT:-0}
if [ $TEST_EXIT -eq 0 ] || [ $TEST_EXIT -eq 5 ]; then
    echo ""
    if [ $TEST_EXIT -eq 5 ]; then
        echo -e "  ${YELLOW}⚠ No tests found — skipping${NC}"
    else
        echo -e "  ${GREEN}✓ Tests passed${NC}"
    fi
else
    echo ""
    echo -e "  ${RED}✗ Tests failed — aborting build.${NC}"
    exit 1
fi

# ── Build ──────────────────────────────────────────────────────
echo ""
echo -e "  ${BLUE}${BOLD}[2/3]${NC} ${BOLD}Building Docker image...${NC}"
echo -e "  ${DIM}─────────────────────────────────────────${NC}"

docker build --platform linux/amd64 --no-cache -t "$IMAGE" .

echo ""
echo -e "  ${GREEN}✓ Image built: ${BOLD}$IMAGE${NC}"

# ── Push ───────────────────────────────────────────────────────
echo ""
echo -e "  ${BLUE}${BOLD}[3/3]${NC} ${BOLD}Pushing to Docker Hub...${NC}"
echo -e "  ${DIM}─────────────────────────────────────────${NC}"

docker push "$IMAGE"

echo ""
echo -e "  ${GREEN}✓ Pushed: ${BOLD}$IMAGE${NC}"

# ── Prune (optional) ──────────────────────────────────────────
if $DO_PRUNE; then
    echo ""
    echo -e "  ${YELLOW}Pruning unused Docker images...${NC}"
    docker image prune -f
    echo -e "  ${GREEN}✓ Pruned${NC}"
fi

echo ""
echo -e "  ${CYAN}───────────────────────────────────────${NC}"
echo -e "  ${GREEN}${BOLD}✓ All done!${NC} ${DIM}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""
