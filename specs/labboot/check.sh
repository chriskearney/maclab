#!/usr/bin/env bash
# Model-checks LabBoot.tla with every model in models/ and fails unless each
# ends as its "\* expect:" line says: "pass", or the name of the invariant
# TLC must find violated. A bug-* model, one per line of models/bugs.txt,
# replays a fixed bug, so it is checked a second time with Bugs = {}, which
# must pass: the fix is what makes it hold. A model's "\* witnesses:" line
# names invariants TLC must find violated, one run each: states the model has
# to reach for its passing to mean anything.
#
#   specs/labboot/check.sh [models/<name>.cfg | bug-<name> ...]
#
# TLA2TOOLS names tla2tools.jar (make spec fetches the pinned one).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
jar=${TLA2TOOLS:-$here/../.tools/tla2tools.jar}
[ -r "$jar" ] || { echo "no tla2tools.jar at $jar: run make spec, or set TLA2TOOLS" >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$here"

# bugs.txt's lines become models: name | expect | BootTimeout | OOB | Faults | Bugs | what
trim() { sed 's/^ *//; s/ *$//' <<<"$1"; }
while IFS='|' read -r name expect boot oob faults bugs what || [ -n "$name" ]; do # a last line with no newline too
	name=$(trim "$name")
	[ -n "$name" ] && [ "${name:0:1}" != "#" ] || continue
	[[ $name == bug-* ]] || { echo "models/bugs.txt: $name: a bug's name starts with bug-" >&2; exit 2; }
	printf '%s\n' "\\* $(trim "$what")" "\\* expect: $(trim "$expect")" "SPECIFICATION Spec" "CONSTANTS" \
		"    BootTimeout = $(trim "$boot")" "    BootLen = 2" "    TestLen = 2" "    MaxTime = 70" "    Skew = 1" \
		"    OOB = $(trim "$oob")" "    Faults = {$(trim "$faults")}" "    Bugs = {$(trim "$bugs")}" \
		"INVARIANTS" "    TypeOK" "    $(trim "$expect")" >"$tmp/$name.cfg"
done <models/bugs.txt

models=()
for m in "$@"; do
	if [ -e "$tmp/$m.cfg" ]; then models+=("$tmp/$m.cfg"); else models+=("$m"); fi
done
[ ${#models[@]} -gt 0 ] || models=(models/*.cfg "$tmp"/bug-*.cfg)

# tlc <cfg> <expect> <label>
tlc() {
	local cfg=$1 expect=$2 label=$3
	local out=$tmp/$label.out
	java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -deadlock -workers auto \
		-metadir "$tmp/$label.states" -config "$cfg" LabBoot >"$out" 2>&1 || true
	local got
	if grep -q '^Model checking completed. No error has been found.' "$out"; then
		got=pass
	elif got=$(grep -o '^Error: Invariant [A-Za-z0-9_]* is violated' "$out"); then
		got=$(awk '{print $3}' <<<"$got")
	else
		got=error
	fi
	if [ "$got" = "$expect" ]; then
		printf 'ok    %-40s %s (%s)\n' "$label" "$got" "$(grep -o '[0-9,]* distinct states found' "$out" | head -1)"
		return 0
	fi
	printf 'FAIL  %-40s expected %s, got %s\n' "$label" "$expect" "$got"
	sed 's/^/      /' "$out" | tail -60
	return 1
}

status=0
for cfg in "${models[@]}"; do
	name=$(basename "$cfg" .cfg)
	expect=$(sed -n 's/^\\\* expect: *//p' "$cfg")
	[ -n "$expect" ] || { echo "FAIL  $name: no \"\\* expect:\" line" >&2; status=1; continue; }
	tlc "$cfg" "$expect" "$name" || status=1
	if [[ $name == bug-* ]]; then
		fixed=$tmp/$name-fixed.cfg
		sed 's/^\( *Bugs = \).*/\1{}/' "$cfg" >"$fixed"
		tlc "$fixed" pass "$name+fix" || status=1
	fi
	for w in $(sed -n 's/^\\\* witnesses: *//p' "$cfg"); do
		wcfg=$tmp/$name-$w.cfg
		sed '/^INVARIANTS/,$d' "$cfg" >"$wcfg"
		printf 'INVARIANTS\n    %s\n' "$w" >>"$wcfg"
		tlc "$wcfg" "$w" "$name~$w" || status=1
	done
done
exit $status
