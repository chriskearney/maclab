#!/bin/sh
# apply.sh <kernel tree>: adds maclab_chaos to a kernel tree as a built-in, for
# a lab-only branch that lab-loop's nights boot. Commit the result on its own
# branch of the kernel fork and build it with `lab build`; never merge it.
set -eu
tree=${1:?usage: apply.sh <kernel tree>}
here=$(cd "$(dirname "$0")" && pwd)
[ -f "$tree/drivers/misc/Makefile" ] || { echo "$tree is not a kernel tree" >&2; exit 1; }
cp "$here/maclab_chaos.c" "$tree/drivers/misc/maclab_chaos.c"
grep -qx 'obj-y += maclab_chaos.o' "$tree/drivers/misc/Makefile" ||
	printf '\n# lab-only fault injection (maclab tools/chaos); never ship\nobj-y += maclab_chaos.o\n' >>"$tree/drivers/misc/Makefile"
echo "added drivers/misc/maclab_chaos.c to $tree"
