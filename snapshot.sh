#!/bin/bash
# Snapshot the Vulnapps database

set -e

# --- Colors & symbols ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'
CHECK="${GREEN}✔${RESET}"
CROSS="${RED}✖${RESET}"
ARROW="${CYAN}➜${RESET}"
WARN="${YELLOW}⚠${RESET}"

# --- Spinner ---
spin() {
    local pid=$1
    local msg=$2
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    tput civis 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${RESET} %s" "${frames[$i]}" "$msg"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.08
    done
    wait "$pid" 2>/dev/null
    local exit_code=$?
    tput cnorm 2>/dev/null || true
    if [ $exit_code -eq 0 ]; then
        printf "\r  ${CHECK} %s\n" "$msg"
    else
        printf "\r  ${CROSS} %s\n" "$msg"
        exit $exit_code
    fi
}

# Run a command with a spinner
run() {
    local msg=$1
    shift
    "$@" &>/dev/null &
    spin $! "$msg"
}

header() {
    echo ""
    echo -e "  ${BOLD}${CYAN}🛡 Vulnapps Snapshot${RESET}"
    echo -e "  ${DIM}─────────────────────${RESET}"
    echo ""
}

usage() {
    header
    echo -e "  ${BOLD}Usage:${RESET} $0 ${DIM}<command>${RESET}"
    echo ""
    echo -e "  ${BOLD}Commands:${RESET}"
    echo -e "    ${GREEN}--local${RESET}                         Snapshot locally on the EC2 host"
    echo -e "    ${GREEN}--remote${RESET}                        Fetch snapshot from EC2 to local machine"
    echo -e "    ${GREEN}--remote --restore ${DIM}<file>${RESET}       Restore a local snapshot to EC2"
    echo -e "    ${GREEN}--help${RESET}                          Show this help message"
    echo ""
}

if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
    exit 0
fi

CONTAINER=vulnapps
DB_PATH=/data/vulnapps.db
SNAPSHOT_DIR=./snapshots
SNAPSHOT_DATE=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_FILE="$SNAPSHOT_DIR/vulnapps-$SNAPSHOT_DATE.db"

# --- Remote restore ---
if [ "$1" = "--remote" ] && [ "$2" = "--restore" ]; then
    RESTORE_FILE="$3"
    if [ -z "$RESTORE_FILE" ] || [ ! -f "$RESTORE_FILE" ]; then
        echo -e "\n  ${CROSS} File not found: ${RED}${RESTORE_FILE:-<none>}${RESET}"
        echo -e "  Usage: $0 --remote --restore <snapshot-file>\n"
        exit 1
    fi

    header
    echo -e "  ${WARN}  ${BOLD}${RED}WARNING: This will overwrite the production database${RESET}"
    echo -e "  ${DIM}   File: ${RESTORE_FILE}${RESET}"
    echo ""
    echo -ne "  ${YELLOW}Press Enter to continue, Ctrl-C to cancel...${RESET} "
    read -r
    echo ""

    run "Uploading snapshot to EC2" \
        scp "$RESTORE_FILE" t.sig9.net:vulnapps.db
    run "Stopping container" \
        ssh t.sig9.net "sudo docker stop $CONTAINER"
    run "Restoring database" \
        ssh t.sig9.net "sudo docker cp ~/vulnapps.db $CONTAINER:$DB_PATH && sudo docker exec $CONTAINER rm -f $DB_PATH-shm $DB_PATH-wal"
    run "Starting container" \
        ssh t.sig9.net "sudo docker start $CONTAINER"

    echo ""
    echo -e "  ${CHECK} ${BOLD}${GREEN}Restore complete!${RESET}"
    echo ""
    exit 0
fi

# --- Remote snapshot ---
if [ "$1" = "--remote" ]; then
    header
    echo -e "  ${ARROW} Fetching snapshot from EC2..."
    echo ""

    run "Extracting database from container" \
        ssh t.sig9.net "sudo docker exec $CONTAINER rm -f $DB_PATH-shm $DB_PATH-wal && sudo docker cp $CONTAINER:$DB_PATH ./vulnapps.db && sudo chown nuno ./vulnapps.db"

    mkdir -p "$SNAPSHOT_DIR"

    run "Downloading snapshot" \
        scp "t.sig9.net:vulnapps.db" "$SNAPSHOT_FILE"

    SIZE=$(du -h "$SNAPSHOT_FILE" | cut -f1)
    echo ""
    echo -e "  ${CHECK} ${BOLD}${GREEN}Snapshot saved!${RESET}"
    echo -e "     ${DIM}File:${RESET} $SNAPSHOT_FILE"
    echo -e "     ${DIM}Size:${RESET} $SIZE"
    echo ""
    exit 0
fi

# --- Local snapshot ---
if [ "$1" = "--local" ]; then
    header
    echo -e "  ${ARROW} Creating local snapshot..."
    echo ""

    mkdir -p "$SNAPSHOT_DIR"

    run "Copying database from container" \
        docker cp "$CONTAINER:$DB_PATH" "$SNAPSHOT_FILE"

    SIZE=$(du -h "$SNAPSHOT_FILE" | cut -f1)
    echo ""
    echo -e "  ${CHECK} ${BOLD}${GREEN}Snapshot saved!${RESET}"
    echo -e "     ${DIM}File:${RESET} $SNAPSHOT_FILE"
    echo -e "     ${DIM}Size:${RESET} $SIZE"
    echo ""
    ls -lh "$SNAPSHOT_DIR"/vulnapps-*.db
    echo ""
    exit 0
fi

echo -e "\n  ${CROSS} Unknown option: ${RED}$1${RESET}"
usage
exit 1
