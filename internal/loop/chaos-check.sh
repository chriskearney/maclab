#!/bin/sh
# lab-loop's chaos-check test: proves the boot ran the chaos kernel with the
# mode the night asked for, and for a marker boot that this result belongs to
# this boot. It passes on a boot with no maclab_chaos on its cmdline.
set -u
# CMDLINE and DMESG are for its tests.
arg() { tr ' ' '\n' <"${CMDLINE:-/proc/cmdline}" | sed -n "s/^$1=//p" | tail -n1; }
mode=$(arg maclab_chaos.mode)
marker=$(arg maclab_chaos.marker)
[ -n "$mode" ] || { echo "no maclab_chaos.mode on the cmdline"; exit 0; }
line=$(${DMESG:-dmesg} | grep -m1 'maclab-chaos: mode=') || {
	echo "the kernel never printed maclab-chaos: is this the chaos kernel?"
	exit 1
}
case "$line" in
*"mode=$mode marker=$marker") echo "chaos kernel, mode=$mode${marker:+ marker=$marker}" ;;
*) echo "kernel said: $line; cmdline asked for mode=$mode marker=$marker"; exit 1 ;;
esac
