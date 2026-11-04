#!/usr/bin/env bash
# =============================================================================
# L10 – File Permissions: SUID/SGID/World-Writable (Linux)
# =============================================================================
# ID       : L10
# Category : File/Registry Permissions & Hardening
# Severity : High
# OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
# Admin    : Yes
# Language : Bash
# Author   : CyberSWISS Security Team
# Usage    : sudo ./L10_file_permissions.sh [--json] [--fix]
# =============================================================================
set -euo pipefail
# shellcheck source=common/json_fields.bash
source "$(dirname -- "${BASH_SOURCE[0]}")/../common/json_fields.bash"

SCRIPT_ID="L10"
SCRIPT_NAME="File Permissions: SUID/SGID/World-Writable"
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON_MODE=false
FIX_MODE=false
FINDINGS='[]'
SCAN_ROOT=/

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --json) JSON_MODE=true ;;
        --fix)  FIX_MODE=true ;;
        --root)
            [[ "$#" -ge 2 && -d "$2" ]] || { echo "--root requires an existing directory" >&2; exit 3; }
            SCAN_ROOT=$(cd -- "$2" && pwd -P)
            shift
            ;;
        -h|--help) echo "Usage: sudo $0 [--json] [--fix] [--root DIRECTORY]"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 3 ;;
    esac
    shift
done

if [[ "$FIX_MODE" == true && "$SCAN_ROOT" != / ]]; then
    echo "--root supports read-only inventories; --fix requires the default system root." >&2
    exit 3
fi

add_finding() {
    local id="$1" name="$2" sev="$3" status="$4" detail="$5" remediation="$6"
    local entry
    entry=$(printf '{"id":"%s","name":"%s","severity":"%s","status":"%s","detail":"%s","remediation":"%s","timestamp":"%s"}' \
        "$id" "$name" "$sev" "$status" "$(json_escape "$detail")" "$(json_escape "$remediation")" "$TIMESTAMP")
    if [[ "$FINDINGS" == '[]' ]]; then FINDINGS="[$entry]"; else FINDINGS="${FINDINGS%]},${entry}]"; fi
    if [[ "$JSON_MODE" == false ]]; then
        case "$status" in
            PASS) colour='\033[0;32m' ;; WARN) colour='\033[0;33m' ;; FAIL) colour='\033[0;31m' ;; *) colour='\033[0;36m' ;;
        esac
        printf "${colour}[%s] [%s] %s: %s\033[0m\n" "$status" "$sev" "$id" "$name"
        [[ -n "$detail" ]]      && printf "       Detail : %s\n" "$detail"
        [[ "$status" != "PASS" && -n "$remediation" ]] && printf "\033[0;36m       Remedy : %s\033[0m\n" "$remediation"
    fi
    return 0
}

# C1 – SUID binaries (exclude expected ones)
EXPECTED_SUID=(
    "/usr/bin/sudo" "/usr/bin/passwd" "/usr/bin/su" "/usr/bin/newgrp"
    "/usr/bin/gpasswd" "/usr/bin/chsh" "/usr/bin/chfn" "/bin/ping"
    "/usr/bin/ping" "/usr/sbin/pam_timestamp_check" "/usr/bin/pkexec"
    "/usr/libexec/polkit-agent-helper-1" "/sbin/mount.nfs"
    "/usr/bin/mount" "/usr/bin/umount"
)

scope_prefix=${SCAN_ROOT%/}

# Classify all five permission checks in one filesystem walk. Repeating find /
# five times caused complete scans to time out on large CI/developer images.
snapshot=$(mktemp)
find_errors=$(mktemp)
trap 'rm -f -- "$snapshot" "$find_errors"' EXIT
find_status=0
LC_ALL=C find "$SCAN_ROOT" -xdev \
    \( -type f \( \
        \( -perm -4000 -printf 's%p\0' \) , \
        \( -perm -2000 -printf 'g%p\0' \) , \
        \( -perm -0002 ! -path "$scope_prefix/tmp/*" ! -path "$scope_prefix/var/tmp/*" ! -path "$scope_prefix/proc/*" ! -path "$scope_prefix/sys/*" -printf 'w%p\0' \) , \
        \( \( -nouser -o -nogroup \) -printf 'u%p\0' \) \
    \) \) -o \
    \( -type d -perm -0002 ! -perm -1000 ! -path "$scope_prefix/proc/*" ! -path "$scope_prefix/sys/*" ! -path "$scope_prefix/dev/*" -printf 'd%p\0' \) \
    > "$snapshot" 2> "$find_errors" || find_status=$?
if [[ "$find_status" -ne 0 ]]; then
    # Unreadable paths are an explicit coverage warning, not a clean result.
    if [[ "$find_status" -ne 1 ]] || grep -qv 'Permission denied$' "$find_errors"; then
        cat "$find_errors" >&2
        exit 3
    fi
    add_finding "${SCRIPT_ID}-C0" "Filesystem Coverage" "Med" "WARN" \
        "Some paths below ${SCAN_ROOT} could not be read; permission checks are incomplete." \
        "Run with sufficient read permissions and review the scan scope."
fi
suid_items=() sgid_count=0 ww_items=() ww_dir_items=() unowned_items=()
while IFS= read -r -d '' record; do
    case "${record:0:1}" in
        s) suid_items+=("${record:1}") ;;
        g) sgid_count=$((sgid_count + 1)) ;;
        w) if [[ "${#ww_items[@]}" -lt 20 ]]; then ww_items+=("${record:1}"); fi ;;
        d) if [[ "${#ww_dir_items[@]}" -lt 20 ]]; then ww_dir_items+=("${record:1}"); fi ;;
        u) if [[ "${#unowned_items[@]}" -lt 10 ]]; then unowned_items+=("${record:1}"); fi ;;
    esac
done < "$snapshot"
suid_files=$(printf '%s\n' "${suid_items[@]}")
unexpected_suid=()
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    found=false
    for expected in "${EXPECTED_SUID[@]}"; do
        [[ "$file" == "$expected" ]] && found=true && break
    done
    if [[ "$found" == false ]]; then
        unexpected_suid+=("$file")
    fi
done <<< "$suid_files"

suid_total=$(echo "$suid_files" | grep -c '/' || true)

if [[ "${#unexpected_suid[@]}" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C1" "Unexpected SUID Binaries" "High" "WARN" \
        "${#unexpected_suid[@]} unexpected SUID files: ${unexpected_suid[*]:0:10}" \
        "Review each: for f in <files>; do ls -la \$f; done – remove SUID if not needed: chmod u-s <file>"
else
    add_finding "${SCRIPT_ID}-C1" "SUID Binaries" "High" "PASS" \
        "${suid_total} SUID files found – all match expected list" ""
fi

# C2 – SGID binaries (flag unusual ones)
if [[ "$sgid_count" -gt 20 ]]; then
    add_finding "${SCRIPT_ID}-C2" "SGID Binaries Count" "Med" "WARN" \
        "${sgid_count} SGID files found (> 20 may warrant review)" \
        "Review: find / -xdev -perm -2000 -type f – remove SGID if not needed: chmod g-s <file>"
else
    add_finding "${SCRIPT_ID}-C2" "SGID Binaries Count" "Med" "PASS" \
        "${sgid_count} SGID files found (within expected range)" ""
fi

# C3 – World-writable files outside /tmp and /var/tmp
ww_files=$(printf '%s\n' "${ww_items[@]}")
ww_count=$(echo "$ww_files" | grep -c '/' || true)
if [[ "$ww_count" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C3" "World-Writable Files" "High" "FAIL" \
        "${ww_count} world-writable files (sample): $(echo "$ww_files" | tr '\n' ',')" \
        "Remove world-write: chmod o-w <file>"
else
    add_finding "${SCRIPT_ID}-C3" "World-Writable Files" "High" "PASS" \
        "No unexpected world-writable files detected" ""
fi

# C4 – World-writable directories without sticky bit (outside /tmp)
ww_dirs=$(printf '%s\n' "${ww_dir_items[@]}")
ww_dir_count=$(echo "$ww_dirs" | grep -c '/' || true)
if [[ "$ww_dir_count" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C4" "World-Writable Dirs (no sticky)" "High" "FAIL" \
        "${ww_dir_count} world-writable dirs without sticky bit: $(echo "$ww_dirs" | tr '\n' ',')" \
        "Add sticky bit: chmod +t <directory>"
else
    add_finding "${SCRIPT_ID}-C4" "World-Writable Dirs (no sticky)" "High" "PASS" \
        "No world-writable directories without sticky bit" ""
fi

# C5 – Unowned files
unowned=$(printf '%s\n' "${unowned_items[@]}")
unowned_count=$(echo "$unowned" | grep -c '/' || true)
if [[ "$unowned_count" -gt 0 ]]; then
    add_finding "${SCRIPT_ID}-C5" "Unowned Files" "Med" "WARN" \
        "${unowned_count} files with no owner/group: $(echo "$unowned" | tr '\n' ',')" \
        "Assign ownership: chown root:root <file> or delete if unnecessary"
else
    add_finding "${SCRIPT_ID}-C5" "Unowned Files" "Med" "PASS" \
        "No unowned files detected" ""
fi

# C6 – /etc/passwd and /etc/shadow permissions
for f_path in /etc/passwd /etc/group; do
    perm=$(stat -c "%a" "$f_path" 2>/dev/null || echo "unknown")
    if [[ "$perm" =~ ^(644|640|600)$ ]]; then
        add_finding "${SCRIPT_ID}-C6-${f_path##*/}" "Permission: ${f_path}" "High" "PASS" \
            "${f_path} permissions: ${perm}" ""
    else
        add_finding "${SCRIPT_ID}-C6-${f_path##*/}" "Permission: ${f_path}" "High" "WARN" \
            "${f_path} permissions: ${perm} (expected 644 or less)" \
            "Fix: chmod 644 ${f_path}"
    fi
done

if [[ -f /etc/shadow ]]; then
    shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "unknown")
    if [[ "$shadow_perm" =~ ^(640|600|000)$ ]]; then
        add_finding "${SCRIPT_ID}-C6-shadow" "Permission: /etc/shadow" "Critical" "PASS" \
            "/etc/shadow permissions: ${shadow_perm}" ""
    else
        add_finding "${SCRIPT_ID}-C6-shadow" "Permission: /etc/shadow" "Critical" "FAIL" \
            "/etc/shadow permissions: ${shadow_perm} (expected 640 or 600)" \
            "Fix: chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
    fi
fi

# ── Optional Fix ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "INFO: --fix requires root to correct file permissions." >&2
    else
        echo "INFO: --fix will apply safe permission corrections for critical files and world-writable directories." >&2

        chmod 644 /etc/passwd /etc/group 2>/dev/null || true
        if [[ -f /etc/shadow ]]; then
            if getent group shadow >/dev/null 2>&1; then
                chown root:shadow /etc/shadow 2>/dev/null || true
            else
                chown root:root /etc/shadow 2>/dev/null || true
            fi
            chmod 640 /etc/shadow 2>/dev/null || true
        fi

        while IFS= read -r dir_path; do
            [[ -z "$dir_path" ]] && continue
            chmod +t "$dir_path" 2>/dev/null || true
        done <<< "$ww_dirs"

        echo "INFO: Applied chmod 644 to /etc/passwd and /etc/group, chmod 640 to /etc/shadow, and added sticky bits to flagged world-writable directories." >&2
        echo "INFO: SUID/SGID binaries and world-writable regular files still require manual review." >&2
    fi
fi

# ── Output ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == true ]]; then
    printf '{"script":"%s","host":"%s","timestamp":"%s","findings":%s}\n' \
        "${SCRIPT_ID}_file_permissions" "$HOSTNAME_VAL" "$TIMESTAMP" "$FINDINGS"
else
    echo ""
    echo "=== ${SCRIPT_ID} ${SCRIPT_NAME} – ${HOSTNAME_VAL} ==="
    FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
    WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
    TOTAL=$(printf '%s\n' "$FINDINGS" | grep -c '"id":' || true)
    echo "Summary: ${TOTAL} finding(s), ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"
fi

FAIL_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"FAIL"' || true)
WARN_COUNT=$(printf '%s\n' "$FINDINGS" | grep -c '"status":"WARN"' || true)
if [[ "$FAIL_COUNT" -gt 0 ]]; then exit 2; fi
if [[ "$WARN_COUNT" -gt 0 ]]; then exit 1; fi
exit 0
