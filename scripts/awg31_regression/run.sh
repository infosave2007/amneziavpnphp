#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$base/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/awg31-regression.XXXXXX")
mkdir -p "$tmp/scripts"
cp -R "$base" "$tmp/scripts/awg31_regression"
ln -s "$root/inc" "$tmp/inc"
for test in allocator-regen.php panel-import.php panel-import-config-absent.php native.php native-activate-twice.php selected-resolver.php restore-lifecycle.php; do php "$tmp/scripts/awg31_regression/$test"; done

[ "${AWG31_KEEP_TEST_TMP:-0}" = 1 ] || find "$tmp" -depth -delete
