#!/bin/bash
# Runs omarchy-m-test (github.com/maralcbr/omarchy-m-testing) inside the GUI
# user's desktop session and keeps its signed report. Installs or upgrades the
# tool first with its own installer, which checks the release signature.
#
# It runs unattended: one Enter accepts the disclaimer, and then input ends,
# so every question the tool asks a person (look at the screen, close the lid,
# reload the Wi-Fi driver, upload) is answered "skip" or "no", never "yes".
# --dry-run: it never uploads by itself; labd publishes known-good runs.
set -u
out=${MACLAB_OUT:-.}
export PATH="$HOME/.local/bin:$PATH"
releases=https://github.com/maralcbr/omarchy-m-testing/releases/latest/download

have=$(omarchy-m-test --version 2>/dev/null | awk '{print $2}')
want=$(curl -fsSL --max-time 20 "$releases/VERSION" 2>/dev/null | tr -d '[:space:]')
if [ -z "$have" ] || { [ -n "$want" ] && [ "$want" != "$have" ]; }; then
    echo "installing omarchy-m-test ${want:-latest} (had ${have:-none})"
    if ! curl -fsSL --max-time 120 https://omarchy-m-testing.org/install | bash; then
        [ -n "$have" ] || { echo "FAIL: could not install omarchy-m-test"; exit 1; }
        echo "upgrade failed; running $have"
    fi
fi
echo "omarchy-m-test $(omarchy-m-test --version | awk '{print $2}') on $(uname -r)"

# A Volunteer's Mac is locked while this runs (MACLAB_SKIP_ON_SCREEN=1): the
# video section (a full-screen test card checked by screenshot) would only
# capture the lock surface, so it is left out of the reference and the test run alike.
skip=()
if [ -n "${MACLAB_SKIP_ON_SCREEN:-}" ]; then
    skip=(--skip video)
    echo "locked screen: on-screen checks left out"
fi

printf '\n' | omarchy-m-test --dry-run "${skip[@]}" --output "$out/omt-report.json" > "$out/omt-run.txt" 2>&1
rc=$?
grep -E '^\s*(PASS|FAIL|SKIP)\b' "$out/omt-run.txt" | sed 's/^\s*//' | head -200
if [ ! -s "$out/omt-report.json" ]; then
    echo "FAIL: omarchy-m-test exited $rc without a report; see omt-run.txt"
    tail -20 "$out/omt-run.txt"
    exit 1
fi
echo "report: $(stat -c %s "$out/omt-report.json") bytes (exit $rc)"
