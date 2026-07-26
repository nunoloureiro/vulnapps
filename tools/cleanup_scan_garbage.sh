#!/usr/bin/env bash
#
# cleanup_scan_garbage.sh — remove recon/scan garbage from a Vulnapps DB.
#
# Garbage is defined by ownership: every account whose email is NOT "@snyk.io"
# is a throwaway recon/test account (verified: 200 such accounts, all created
# 2026-06-22..07-16 by diogolala41+* gmail plus-addresses and one-off test
# emails). Everything those accounts own — apps, vulns, scans, findings, teams,
# api keys — is the garbage. Legit @snyk.io data is untouched.
#
# The script runs in two phases:
#   1. SELECT/preview  — prints exactly what will be deleted and what will
#                        remain, and changes NOTHING.
#   2. DELETE          — only after you press Enter. Backs up the DB first,
#                        deletes inside a single transaction, then VACUUMs.
#
# Usage:  tools/cleanup_scan_garbage.sh /path/to/vulnapps.db
#
set -euo pipefail

DB="${1:-}"
if [[ -z "$DB" || ! -f "$DB" ]]; then
  echo "usage: $0 /path/to/vulnapps.db" >&2
  exit 1
fi

# The one knob: who is legit. Everyone else's data is garbage.
LEGIT="email LIKE '%@snyk.io'"

# Reusable garbage-set predicates (kept identical between preview and delete).
G_USERS="SELECT id FROM users WHERE NOT ($LEGIT)"
G_APPS="SELECT id FROM apps WHERE created_by IN ($G_USERS)"
G_SCANS="SELECT id FROM scans WHERE submitted_by IN ($G_USERS) OR app_id IN ($G_APPS)"
G_TEAMS="SELECT id FROM teams WHERE created_by IN ($G_USERS)"

q() { sqlite3 "$DB" "$1"; }

echo "════════════════════════════════════════════════════════════════"
echo " Vulnapps garbage cleanup — DB: $DB"
echo " Legit = @snyk.io accounts.  Garbage = everything else."
echo "════════════════════════════════════════════════════════════════"
echo
echo "── PHASE 1: PREVIEW (no changes) ───────────────────────────────"
echo
printf "%-22s %12s %12s\n" "table" "TO DELETE" "WILL REMAIN"
printf "%-22s %12s %12s\n" "----------------------" "------------" "------------"

row() { # name  delete_count_sql  total_table
  local name="$1" del="$2" tbl="$3"
  local d t
  d=$(q "SELECT COUNT(*) FROM ($del);")
  t=$(q "SELECT COUNT(*) FROM $tbl;")
  printf "%-22s %12s %12s\n" "$name" "$d" "$((t - d))"
}

row "users"            "SELECT id FROM users WHERE NOT ($LEGIT)" users
row "apps"             "$G_APPS" apps
row "vulnerabilities"  "SELECT id FROM vulnerabilities WHERE app_id IN ($G_APPS) OR created_by IN ($G_USERS)" vulnerabilities
row "scans"            "$G_SCANS" scans
row "scan_findings"    "SELECT id FROM scan_findings WHERE scan_id IN ($G_SCANS)" scan_findings
row "scan_labels"      "SELECT rowid FROM scan_labels WHERE scan_id IN ($G_SCANS)" scan_labels
row "app_technologies" "SELECT id FROM app_technologies WHERE app_id IN ($G_APPS)" app_technologies
row "teams"            "$G_TEAMS" teams
row "team_members"     "SELECT id FROM team_members WHERE team_id IN ($G_TEAMS) OR user_id IN ($G_USERS)" team_members
row "api_keys"         "SELECT id FROM api_keys WHERE user_id IN ($G_USERS)" api_keys

echo
echo "── KEPT accounts (@snyk.io) — never deleted ────────────────────"
sqlite3 -noheader -list "$DB" "
SELECT printf('   [%d] %s  (%s)  — %d apps, %d vulns, %d scans',
         id, email, role,
         (SELECT COUNT(*) FROM apps a WHERE a.created_by=users.id),
         (SELECT COUNT(*) FROM vulnerabilities v WHERE v.created_by=users.id),
         (SELECT COUNT(*) FROM scans s WHERE s.submitted_by=users.id))
FROM users WHERE $LEGIT ORDER BY id;"

# Did any KEPT account create garbage? (guards against a 'normal' user who ran
# their own recon: a suspicious name, or an app with an abnormal vuln count.)
echo
echo "── Integrity check: garbage owned by a KEPT account? ───────────"
SUSPECT=$(sqlite3 -noheader -list "$DB" "
SELECT printf('   [%d] %s  ->  app %d \"%s\" (%d vulns)',
         a.created_by, (SELECT email FROM users WHERE id=a.created_by),
         a.id, substr(a.name,1,30),
         (SELECT COUNT(*) FROM vulnerabilities v WHERE v.app_id=a.id))
FROM apps a
WHERE a.created_by IN (SELECT id FROM users WHERE $LEGIT)
  AND ( (SELECT COUNT(*) FROM vulnerabilities v WHERE v.app_id=a.id) > 100
        OR a.name LIKE '%<%' OR a.name LIKE '%''%'
        OR lower(a.name) LIKE '%recon%' OR lower(a.name) LIKE '%test%' );")
if [[ -z "$SUSPECT" ]]; then
  echo "   ✓ None. Every @snyk.io account's data looks legitimate."
else
  echo "   ⚠ A KEPT account owns suspicious apps. These are NOT deleted by this"
  echo "     script (owner is legit) — review and remove manually if they are junk:"
  echo "$SUSPECT"
fi

# ── Full listing of everything to delete, by user, in the natural hierarchy:
#    user -> apps -> (vulns, scans -> findings).
NWITH=$(q "SELECT COUNT(DISTINCT created_by) FROM apps WHERE created_by IN ($G_USERS)")
echo
echo "── DELETE — garbage users WITH content ($NWITH) : user -> apps -> vulns/scans/findings ──"
sqlite3 -noheader -list "$DB" "
WITH gu AS (SELECT id,email,created_at FROM users WHERE NOT ($LEGIT))
SELECT line FROM (
  SELECT gu.id uid,
         (SELECT COUNT(*) FROM vulnerabilities v WHERE v.created_by=gu.id) uv,
         0 typ, '' anm,
         printf('[%d] %s  (joined %s)  — %d apps, %d vulns, %d scans, %d api_keys',
           gu.id, gu.email, substr(gu.created_at,1,10),
           (SELECT COUNT(*) FROM apps a WHERE a.created_by=gu.id),
           (SELECT COUNT(*) FROM vulnerabilities v WHERE v.created_by=gu.id),
           (SELECT COUNT(*) FROM scans s WHERE s.submitted_by=gu.id),
           (SELECT COUNT(*) FROM api_keys k WHERE k.user_id=gu.id)) line
  FROM gu WHERE gu.id IN (SELECT created_by FROM apps)
  UNION ALL
  SELECT a.created_by uid,
         (SELECT COUNT(*) FROM vulnerabilities v WHERE v.created_by=a.created_by) uv,
         1 typ, a.name anm,
         printf('       app %d \"%s\"  — %d vulns, %d scans, %d findings',
           a.id, substr(a.name,1,32),
           (SELECT COUNT(*) FROM vulnerabilities v WHERE v.app_id=a.id),
           (SELECT COUNT(*) FROM scans s WHERE s.app_id=a.id),
           (SELECT COUNT(*) FROM scan_findings f JOIN scans s ON f.scan_id=s.id WHERE s.app_id=a.id)) line
  FROM apps a WHERE a.created_by IN (SELECT id FROM gu)
) ORDER BY uv DESC, uid, typ, anm;"

echo
echo "── DELETE — garbage users WITHOUT content (empty throwaway accounts) ──"
sqlite3 -noheader -list "$DB" "
SELECT printf('   [%d] %s  (%d api_keys)', id, email,
         (SELECT COUNT(*) FROM api_keys k WHERE k.user_id=users.id))
FROM users WHERE NOT ($LEGIT) AND id NOT IN (SELECT created_by FROM apps)
ORDER BY id;"

echo
echo "────────────────────────────────────────────────────────────────"
echo "Review the FULL list above. Everyone listed under DELETE, and ALL"
echo "their apps/vulns/scans/findings/keys, will be removed."
read -r -p "Press ENTER to DELETE (Ctrl-C to abort)... " _

echo
echo "── PHASE 2: DELETE ─────────────────────────────────────────────"
BACKUP="${DB}.bak-$(date +%Y%m%d-%H%M%S)"
cp "$DB" "$BACKUP"
echo "Backup written: $BACKUP"

sqlite3 "$DB" <<SQL
PRAGMA foreign_keys=OFF;
BEGIN;
CREATE TEMP TABLE _g_users AS $G_USERS;
CREATE TEMP TABLE _g_apps  AS SELECT id FROM apps  WHERE created_by IN (SELECT id FROM _g_users);
CREATE TEMP TABLE _g_scans AS SELECT id FROM scans WHERE submitted_by IN (SELECT id FROM _g_users) OR app_id IN (SELECT id FROM _g_apps);
CREATE TEMP TABLE _g_teams AS SELECT id FROM teams WHERE created_by IN (SELECT id FROM _g_users);

DELETE FROM scan_findings   WHERE scan_id IN (SELECT id FROM _g_scans);
DELETE FROM scan_labels     WHERE scan_id IN (SELECT id FROM _g_scans);
DELETE FROM scans           WHERE id IN (SELECT id FROM _g_scans);
DELETE FROM app_technologies WHERE app_id IN (SELECT id FROM _g_apps);
DELETE FROM vulnerabilities WHERE app_id IN (SELECT id FROM _g_apps) OR created_by IN (SELECT id FROM _g_users);
DELETE FROM team_members    WHERE team_id IN (SELECT id FROM _g_teams) OR user_id IN (SELECT id FROM _g_users);
DELETE FROM teams           WHERE id IN (SELECT id FROM _g_teams);
DELETE FROM apps            WHERE id IN (SELECT id FROM _g_apps);
DELETE FROM api_keys        WHERE user_id IN (SELECT id FROM _g_users);
DELETE FROM users           WHERE id IN (SELECT id FROM _g_users);
COMMIT;
VACUUM;
SQL

echo "Done. Remaining row counts:"
for t in users apps vulnerabilities scans scan_findings teams team_members api_keys; do
  printf "   %-18s %s\n" "$t" "$(q "SELECT COUNT(*) FROM $t;")"
done
echo
echo "New DB size: $(du -h "$DB" | cut -f1)  (backup at $BACKUP)"
