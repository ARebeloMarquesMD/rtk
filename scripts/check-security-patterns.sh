#!/usr/bin/env bash
set -euo pipefail

# check-security-patterns.sh — CI guard: new code must not introduce dangerous patterns
#
# Scans only ADDED lines in the diff — never flags pre-existing code.
# This avoids false positives on runner.rs which already uses Command::new("sh") (issue #640).
#
# Usage:
#   bash scripts/check-security-patterns.sh [BASE_BRANCH]
#   bash scripts/check-security-patterns.sh --self-test
#
# BASE_BRANCH defaults to origin/develop

HARD_FAIL=0

if [ "${1:-}" = "--self-test" ]; then
    # Self-test: inject known-bad patterns into a temp diff and verify detection
    TMPDIR_SELF=$(mktemp -d)
    trap 'rm -rf "$TMPDIR_SELF"' EXIT

    FAKE_DIFF="$TMPDIR_SELF/fake.diff"
    cat > "$FAKE_DIFF" <<'DIFF'
+    let output = Command::new("sh").args(["-c", cmd]).output()?;
+    unsafe { std::ptr::null::<u8>(); }
DIFF

    ADDED=$(grep '^+' "$FAKE_DIFF" | grep -v '^+++' || true)

    DETECTED_SHELL=0
    DETECTED_UNSAFE=0

    if echo "$ADDED" | grep -qE 'Command::new\("(sh|bash|cmd)"\)'; then
        DETECTED_SHELL=1
    fi
    if echo "$ADDED" | grep -qE 'unsafe\s*\{'; then
        DETECTED_UNSAFE=1
    fi

    if [ "$DETECTED_SHELL" -eq 1 ] && [ "$DETECTED_UNSAFE" -eq 1 ]; then
        echo "PASS: --self-test both patterns detected correctly"
        exit 0
    else
        echo "FAIL: --self-test broken"
        [ "$DETECTED_SHELL" -eq 0 ] && echo "  shell pattern NOT detected"
        [ "$DETECTED_UNSAFE" -eq 0 ] && echo "  unsafe pattern NOT detected"
        exit 1
    fi
fi

BASE_BRANCH="${1:-origin/develop}"

# Extract only added lines from Rust source files (exclude diff header lines starting with +++)
ADDED=$(git diff --unified=0 --diff-filter=AM --no-renames "$BASE_BRANCH"...HEAD \
    -- 'src/**/*.rs' 2>/dev/null \
    | grep '^+' | grep -v '^+++' || true)

if [ -z "$ADDED" ]; then
    echo "check-security-patterns: no Rust additions detected — OK"
    exit 0
fi

echo "check-security-patterns: scanning new Rust lines for dangerous patterns..."
echo ""

# ── HARD FAIL patterns ────────────────────────────────────────────────────────

NEW_SHELL=$(echo "$ADDED" | grep -E 'Command::new\("(sh|bash|cmd)"\)' || true)
if [ -n "$NEW_SHELL" ]; then
    echo "  FAIL  New shell execution detected:"
    echo "$NEW_SHELL" | head -5 | sed 's/^/        /'
    echo ""
    echo "        Shell command execution via sh/bash/cmd is a known injection vector."
    echo "        Reference: issue #640 (C-1 shell injection)"
    echo "        If this is intentional, document the security rationale in the PR."
    HARD_FAIL=1
fi

NEW_UNSAFE=$(echo "$ADDED" | grep -E 'unsafe\s*\{' || true)
if [ -n "$NEW_UNSAFE" ]; then
    echo "  FAIL  New unsafe block detected:"
    echo "$NEW_UNSAFE" | head -5 | sed 's/^/        /'
    echo ""
    echo "        RTK codebase has zero unsafe blocks. Any addition requires"
    echo "        explicit maintainer review and strong justification."
    HARD_FAIL=1
fi

# ── WARN patterns (visible in CI log, not blocking) ──────────────────────────

NEW_UNWRAP=$(echo "$ADDED" | grep -E '\.unwrap\(\)' | grep -v 'lazy_static\|#\[test\]\|#\[cfg(test)\]' || true)
if [ -n "$NEW_UNWRAP" ]; then
    echo "  WARN  New .unwrap() calls detected (not blocking, but prefer .context()?):"
    echo "$NEW_UNWRAP" | head -5 | sed 's/^/        /'
    echo ""
fi

NEW_PRINTLN=$(echo "$ADDED" | grep -E 'println!' || true)
if [ -n "$NEW_PRINTLN" ]; then
    echo "  WARN  New println! in Rust source (not blocking, but verify it belongs in a filter):"
    echo "$NEW_PRINTLN" | head -5 | sed 's/^/        /'
    echo ""
fi

# ── Verdict ───────────────────────────────────────────────────────────────────

if [ "$HARD_FAIL" -ne 0 ]; then
    echo "check-security-patterns: FAILED — dangerous patterns introduced. Fix before merging."
    exit 1
else
    echo "check-security-patterns: no dangerous patterns detected — OK"
fi
