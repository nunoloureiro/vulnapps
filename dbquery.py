#!/usr/bin/env python3
"""Interactive SQLite query tool for Vulnapps database.

Usage:
    python3 dbquery.py [DATABASE_PATH]

    If DATABASE_PATH is not provided, uses $DATABASE_PATH env var or /data/vulnapps.db

Examples:
    # Local
    python3 dbquery.py ./vulnapps.db

    # Inside Docker container
    docker exec -it vulnapps python3 dbquery.py

    # EC2 via docker exec
    docker exec -it vulnapps python3 dbquery.py /data/vulnapps.db
"""

import os
import sys
import sqlite3
import textwrap

# ANSI colors
BOLD = "\033[1m"
DIM = "\033[2m"
ORANGE = "\033[38;5;208m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"
UNDERLINE = "\033[4m"


def colorize(text, color):
    return f"{color}{text}{RESET}"


def print_banner():
    print(f"""
{ORANGE}{BOLD}  ╔══════════════════════════════════════╗
  ║     Vulnapps Database Query Tool     ║
  ╚══════════════════════════════════════╝{RESET}
""")


def print_help():
    print(f"""
  {BOLD}Commands:{RESET}
    {ORANGE}.schema{RESET}           Show all table schemas
    {ORANGE}.schema TABLE{RESET}     Show schema for a specific table
    {ORANGE}.tables{RESET}           List all tables
    {ORANGE}.count TABLE{RESET}      Count rows in a table
    {ORANGE}.stats{RESET}            Show database statistics
    {ORANGE}.help{RESET}             Show this help
    {ORANGE}.quit{RESET}             Exit

  {BOLD}SQL:{RESET}
    Type any SQL query. Multi-line queries end with {ORANGE};{RESET}
    Results are displayed as formatted tables.
""")


def get_tables(db):
    cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return [row[0] for row in cursor.fetchall()]


def show_tables(db):
    tables = get_tables(db)
    print(f"\n  {BOLD}Tables ({len(tables)}):{RESET}")
    for t in tables:
        count = db.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        print(f"    {ORANGE}{t}{RESET} {DIM}({count} rows){RESET}")
    print()


def show_schema(db, table_name=None):
    if table_name:
        cursor = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        row = cursor.fetchone()
        if row:
            print(f"\n  {BOLD}{table_name}:{RESET}")
            print(f"  {DIM}{row[0]}{RESET}\n")
        else:
            print(f"\n  {RED}Table '{table_name}' not found.{RESET}\n")
    else:
        tables = db.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for name, sql in tables:
            count = db.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
            print(f"\n  {BOLD}{ORANGE}{name}{RESET} {DIM}({count} rows){RESET}")
            # Parse columns from pragma for a cleaner view
            cols = db.execute(f"PRAGMA table_info([{name}])").fetchall()
            for col in cols:
                cid, cname, ctype, notnull, default, pk = col
                parts = []
                if pk:
                    parts.append(colorize("PK", YELLOW))
                parts.append(colorize(ctype or "?", CYAN))
                if notnull and not pk:
                    parts.append(colorize("NOT NULL", DIM))
                if default is not None:
                    parts.append(colorize(f"DEFAULT {default}", DIM))
                print(f"    {cname:<25} {' '.join(parts)}")
        print()


def show_stats(db):
    tables = get_tables(db)
    print(f"\n  {BOLD}Database Statistics:{RESET}")

    total_rows = 0
    for t in tables:
        count = db.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        total_rows += count

    print(f"    Tables:     {ORANGE}{len(tables)}{RESET}")
    print(f"    Total rows: {ORANGE}{total_rows}{RESET}")

    # App-specific stats
    try:
        apps = db.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
        vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        scans = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        findings = db.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0]
        print(f"\n    Users:          {GREEN}{users}{RESET}")
        print(f"    Apps:           {GREEN}{apps}{RESET}")
        print(f"    Vulnerabilities:{GREEN} {vulns}{RESET}")
        print(f"    Scans:          {GREEN}{scans}{RESET}")
        print(f"    Scan Findings:  {GREEN}{findings}{RESET}")
    except sqlite3.OperationalError:
        pass
    print()


def format_table(cursor):
    if cursor.description is None:
        return

    headers = [d[0] for d in cursor.description]
    rows = cursor.fetchall()

    if not rows:
        print(f"\n  {DIM}(0 rows){RESET}\n")
        return

    # Calculate column widths (cap at 50 chars)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            s = str(val) if val is not None else "NULL"
            widths[i] = min(max(widths[i], len(s)), 50)

    # Print header
    header_line = "  "
    sep_line = "  "
    for i, h in enumerate(headers):
        header_line += colorize(h.ljust(widths[i]), BOLD) + "  "
        sep_line += "─" * widths[i] + "  "

    print()
    print(header_line)
    print(colorize(sep_line, DIM))

    # Print rows
    for row in rows:
        line = "  "
        for i, val in enumerate(row):
            if val is None:
                s = colorize("NULL", DIM)
                padding = widths[i] - 4
            else:
                s = str(val)
                if len(s) > 50:
                    s = s[:47] + "..."
                padding = widths[i] - len(s)
            line += s + " " * max(padding, 0) + "  "
        print(line)

    print(f"\n  {DIM}({len(rows)} row{'s' if len(rows) != 1 else ''}){RESET}\n")


def run_query(db, sql):
    try:
        cursor = db.execute(sql)
        if cursor.description:
            format_table(cursor)
        else:
            print(f"\n  {GREEN}OK{RESET} ({db.total_changes} rows affected)\n")
            if sql.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")):
                db.commit()
    except sqlite3.Error as e:
        print(f"\n  {RED}Error: {e}{RESET}\n")


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DATABASE_PATH", "/data/vulnapps.db")

    if not os.path.exists(db_path):
        print(f"{RED}Database not found: {db_path}{RESET}")
        print(f"Usage: python3 dbquery.py [DATABASE_PATH]")
        sys.exit(1)

    db = sqlite3.connect(db_path)
    db.row_factory = None  # Use tuples for format_table

    print_banner()
    print(f"  {DIM}Connected to: {db_path}{RESET}")
    print(f"  {DIM}Type .help for commands, .quit to exit{RESET}\n")

    buffer = ""
    while True:
        try:
            prompt = f"  {ORANGE}{'...' if buffer else 'sql'}{RESET}{BOLD}>{RESET} "
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break

        stripped = line.strip()

        # Handle dot commands (only when no buffer)
        if not buffer and stripped.startswith("."):
            parts = stripped.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else None

            if cmd in (".quit", ".exit", ".q"):
                break
            elif cmd == ".help":
                print_help()
            elif cmd == ".tables":
                show_tables(db)
            elif cmd == ".schema":
                show_schema(db, arg)
            elif cmd == ".count" and arg:
                run_query(db, f"SELECT COUNT(*) as count FROM [{arg}]")
            elif cmd == ".stats":
                show_stats(db)
            else:
                print(f"  {RED}Unknown command: {cmd}{RESET}")
            continue

        # Accumulate SQL
        buffer += (" " if buffer else "") + line

        # Execute when we see a semicolon
        if buffer.rstrip().endswith(";"):
            run_query(db, buffer)
            buffer = ""

    db.close()
    print(f"  {DIM}Bye!{RESET}\n")


if __name__ == "__main__":
    main()
