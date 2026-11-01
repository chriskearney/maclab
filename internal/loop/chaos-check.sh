#!/bin/sh
# lab-loop's chaos-check test: proves the boot ran the chaos kernel with the
# code and marker the night asked for, so this result belongs to this boot.
# It never learns which fault the code means. It passes on a boot with no
# maclab_chaos on its cmdline.
#
# Every boot waits until 20 s after the late faults are due, so an oops or
# panic lands during the job, not after it. Waiting on every boot, healthy
# ones too, keeps the timing from giving the fault away.
set -u
# CMDLINE, DMESG, JOURNAL and UPTIME are for its tests.
arg() { tr ' ' '\n' <"${CMDLINE:-/proc/cmdline}" | sed -n "s/^$1=//p" | tail -n1; }
code=$(arg maclab_chaos.code)
marker=$(arg maclab_chaos.marker)
delay=$(arg maclab_chaos.delay_sec)
[ -n "$code" ] || { echo "no maclab_chaos.code on the cmdline"; exit 0; }
due=$(( ${delay:-90} + 20 ))
up=$(cut -d. -f1 "${UPTIME:-/proc/uptime}")
[ "$up" -ge "$due" ] || sleep $((due - up))
# The ring buffer can wrap on a long boot; the journal keeps the line.
line=$( (${DMESG:-dmesg}; ${JOURNAL:-journalctl -k -b -o cat} 2>/dev/null) | grep -m1 'maclab-chaos: code=') || {
	echo "the kernel never printed maclab-chaos: is this the chaos kernel?"
	exit 1
}
case "$line" in
*"code=$code marker=$marker") echo "chaos kernel, code=$code marker=$marker" ;;
*) echo "kernel said: $line; cmdline asked for code=$code marker=$marker"; exit 1 ;;
esac
