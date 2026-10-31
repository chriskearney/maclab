#!/bin/bash
# Runs omarchy-m-test (github.com/maralcbr/omarchy-m-testing) inside the GUI
# user's desktop session and keeps its signed report. Installs or upgrades the
# tool first with its own installer, which checks the release signature.
#
# It runs with --unattended (omarchy-m-test 0.1.15 and later): automatic checks
# only, no tone, brightness steps or camera window, nothing disruptive. It still
# reads the microphone for 3 s and 30 camera frames, measured and discarded.
# One Enter accepts the disclaimer, and then input ends.
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
running=$(omarchy-m-test --version | awk '{print $2}')
echo "omarchy-m-test $running on $(uname -r)"

args=(--dry-run)
# A tool older than 0.1.15 (the upgrade failed) doesn't know the flag and would
# refuse to run. Without it, every question still goes unanswered, but the tone,
# the brightness steps and the camera window happen as they did before.
case "$(omarchy-m-test --help 2>/dev/null)" in
    *--unattended*) args+=(--unattended) ;;
    *) echo "omarchy-m-test $running has no --unattended: running without it (tone, brightness steps, camera window)" ;;
esac

# A Volunteer's Mac is locked while this runs (MACLAB_SKIP_ON_SCREEN=1), so the
# video section's full-screen test card is left out of the reference and the
# test run alike. omarchy-m-test 0.1.15 skips it under --unattended anyway; once
# maralcbr/omarchy-m-testing#61 ships it runs on an unlocked session, and this
# keeps it off a Volunteer's screen.
if [ -n "${MACLAB_SKIP_ON_SCREEN:-}" ]; then
    args+=(--skip video)
    echo "locked screen: on-screen checks left out"
fi

printf '\n' | omarchy-m-test "${args[@]}" --output "$out/omt-report.json" > "$out/omt-run.txt" 2>&1
rc=$?
grep -E '^\s*(PASS|FAIL|SKIP)\b' "$out/omt-run.txt" | sed 's/^\s*//' | head -200
if [ ! -s "$out/omt-report.json" ]; then
    echo "FAIL: omarchy-m-test exited $rc without a report; see omt-run.txt"
    tail -20 "$out/omt-run.txt"
    exit 1
fi
echo "report: $(stat -c %s "$out/omt-report.json") bytes (exit $rc)"
