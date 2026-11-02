#!/usr/bin/env python3
"""Production-function regressions using text fixtures and stubbed effects only."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('lab-only-autounlock')


class AutoUnlockTests(unittest.TestCase):
    def scenario(self, action='disable', current=None, images=None, staged='none',
                 active=(1, 5, 7), keep=(1, 2), stop_confirm=False,
                 rebuild_update=True, passphrase_slot=1):
        functions = SCRIPT.read_text().split('# ---- main ', 1)
        self.assertEqual(len(functions), 2)
        self.assertIsNotNone(shutil.which('script'), 'util-linux script is needed for an isolated fixture tty')
        images = images or {}
        with tempfile.TemporaryDirectory(prefix='maclab-autounlock-test-') as tmp:
            root = Path(tmp)
            (root / 'scratch').mkdir()
            for label in ('A', 'B', 'DEAD', 'OWNER'):
                (root / ('payload-' + label)).write_text('fixture-not-a-disk-key-' + label)
            if current:
                (root / 'current.fixture').write_text('fixture-not-a-disk-key-' + current)
                (root / 'dropin.fixture').write_text('FILES+=(' + str(root / 'current.fixture') + ')\n')
            (root / 'effects').write_text('')
            init = '\n'.join([
                'FIX=' + shlex.quote(tmp), 'ACTION=' + shlex.quote(action),
                'KEY=$FIX/current.fixture', 'DROPIN=$FIX/dropin.fixture', 'CMDFILE=$FIX/command.fixture',
                'DEVICE=fixture-not-a-device', 'TOKEN=fixture-token', 'VOLUME=fixture',
                'STATE=$FIX/state.fixture', 'LIMINE_CONF=fixture-menu', 'KEEP=(' + ' '.join(map(str, keep)) + ')',
                'ACTIVE=(' + ' '.join(map(str, active)) + ')',
                'STAGED=' + shlex.quote(staged), 'IMAGE_STATE=present',
                'STOP_CONFIRM=' + str(int(stop_confirm)), 'REBUILD_UPDATE=' + str(int(rebuild_update)),
                'PASSPHRASE_SLOT=' + str(passphrase_slot), 'CMD_PRESENT=' + str(int(bool(current))),
                'declare -A CONTENT=()', 'IMAGES=()',
                *['IMAGES+=(' + shlex.quote(name) + '); CONTENT[' + shlex.quote(name) + ']=' + shlex.quote(label)
                  for name, label in images.items()],
            ])
            controls = r'''
cleanup() { :; } # no real shred/remove trap: Python owns ordinary text fixtures
note() { printf '%s\n' "$*" >>"$FIX/effects"; }
forbidden() { printf 'FORBIDDEN: %s\n' "$*" >&2; exit 99; }
probe_file() {
 PROBED=
 [[ -f $1 ]] || return 0
 local label slot
 label=$(cat "$1")
 case $label in
  fixture-not-a-disk-key-A) slot=5;;
  fixture-not-a-disk-key-B) slot=7;;
  fixture-not-a-disk-key-OWNER) slot=1;;
  fixture-not-a-disk-key-DEAD) return 0;;
  *) forbidden unexpected-fixture;;
 esac
 [[ " ${ACTIVE[*]} " != *" $slot "* ]] || PROBED=$slot
 return 0
}
keyslots() { printf '%s\n' "${ACTIVE[@]}"; }
pbkdf2_slots() { PBKDF2_SLOTS=(); } # live fixtures may be adopted argon2id slots
staged_ukis() { [[ $STAGED == none ]] || printf '%s\n' staged.efi; return 0; }
ukis() { local f; for f in "${IMAGES[@]}"; do [[ $f != *.efi ]] || printf '%s\n' "$f"; done; return 0; }
initramfs_images() { local f; for f in "${IMAGES[@]}"; do [[ $f != *.img ]] || printf '%s\n' "$f"; done; return 0; }
lsinitcpio() {
 local label=${CONTENT[$1]:-UNKNOWN}
 if [[ $1 == staged.efi ]]; then
  [[ $STAGED != unreadable ]] || return 1
  [[ $STAGED != key ]] || { printf '%s\n' etc/cryptsetup-keys.d/fixture.key; return 0; }
  printf '%s\n' etc/other; return 0
 fi
 [[ $IMAGE_STATE != clear ]] || { printf '%s\n' etc/other; return 0; }
 [[ $label != UNKNOWN ]] || return 1
 printf '%s\n' etc/cryptsetup-keys.d/fixture.key
}
make_tmpd() { TMPD=$FIX/scratch; }
extract_key() {
 local label=${CONTENT[$1]:-UNKNOWN}
 [[ $label != UNKNOWN && $label != OPAQUE ]] || return 1
 printf '%s\n' "$FIX/payload-$label"
}
uki_token() { [[ $IMAGE_STATE == clear ]] && echo no || echo yes; }
limine_entries() { (( ${#IMAGES[@]} )) || return 0; [[ $IMAGE_STATE == clear ]] && printf 'fixture\tno\n' || printf 'fixture\tyes\n'; }
cmdfile_has_token() { (( CMD_PRESENT )); }
crypttab_entry() { :; }
other_luks_keys() { :; }
foreign_key_configs() { :; }
check_cmdfile() { :; }
need_rebuild_tools() { :; }
need_tty() { :; }
readable_warnings() { :; }
confirm() { (( !STOP_CONFIRM )) || { echo 'fixture stops before changes'; exit 77; }; note confirm; }
edit_cmdline() { note edit; [[ $1 == add ]] && CMD_PRESENT=1 || CMD_PRESENT=0; }
rebuild() {
 note rebuild
 if (( REBUILD_UPDATE )); then
  if [[ $ACTION == disable ]]; then IMAGE_STATE=clear
  else for f in "${IMAGES[@]}"; do CONTENT[$f]=A; done
  fi
 fi
 return 0
}
cryptsetup() {
 if [[ $1 == open ]]; then printf 'Key slot %s unlocked.\n' "$PASSPHRASE_SLOT"; return 0; fi
 [[ $1 == luksRemoveKey && $2 == fixture-not-a-device ]] || forbidden cryptsetup-arguments
 probe_file "$3"
 [[ -n $PROBED ]] || forbidden removing-nonlive-fixture
 note "remove $PROBED"
 local s next=()
 for s in "${ACTIVE[@]}"; do [[ $s == "$PROBED" ]] || next+=("$s"); done
 ACTIVE=("${next[@]}")
}
rm() {
 [[ $1 == -f ]] || forbidden rm-options
 shift
 local f
 for f in "$@"; do [[ $f == "$FIX/"* ]] || forbidden rm-outside-fixture; done
 note rm
 command rm -f -- "$@"
}
install() { forbidden install; }
mv() { forbidden mv; }
chmod() { forbidden chmod; }
chown() { forbidden chown; }
cp() { forbidden cp; }
shred() { forbidden shred; }
"$ACTION"
'''
            fixture = root / 'functions-test.sh'
            fixture.write_text(functions[0] + '\n' + init + '\n' + controls)
            # A private PTY lets the production </dev/tty redirection reach only
            # our cryptsetup shell function, never any crypto executable/device.
            result = subprocess.run(
                ['script', '--quiet', '--return', '--command',
                 'bash --noprofile --norc ' + shlex.quote(str(fixture)), '/dev/null'],
                input='', text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH': os.environ.get('PATH', os.defpath), 'LC_ALL': 'C'}, timeout=8,
            )
            output = result.stdout + result.stderr
            self.assertNotIn('FORBIDDEN:', output)
            return result.returncode, output, (root / 'effects').read_text().splitlines()

    def assert_refused_without_effects(self, **kwargs):
        rc, output, effects = self.scenario(**kwargs)
        self.assertEqual(rc, 1, output)
        self.assertEqual(effects, [], output)
        self.assertNotIn('Already disabled:', output)
        return output

    def test_already_disabled_without_staged_images(self):
        rc, output, effects = self.scenario()
        self.assertEqual(rc, 0, output)
        self.assertIn('Already disabled:', output)
        self.assertEqual(effects, [])

    def test_staged_image_known_to_have_no_key_remains_allowed(self):
        rc, output, effects = self.scenario(staged='no-key')
        self.assertEqual(rc, 0, output)
        self.assertIn('Already disabled:', output)
        self.assertEqual(effects, [])

    def test_known_staged_key_refuses_before_mutations(self):
        self.assertIn('holds the key', self.assert_refused_without_effects(staged='key'))

    def test_unreadable_staged_image_refuses_before_mutations(self):
        self.assertIn("couldn't be read", self.assert_refused_without_effects(staged='unreadable'))

    def test_unreadable_normal_images_refuse_even_with_current_live_key(self):
        for image in ('normal.efi', 'normal.img'):
            with self.subTest(image=image):
                self.assertIn("couldn't be read", self.assert_refused_without_effects(current='A', images={image: 'UNKNOWN'}))

    def test_unextractable_normal_key_refuses_without_pbkdf2_heuristic(self):
        self.assertIn("couldn't copy out", self.assert_refused_without_effects(current='A', images={'normal.efi': 'OPAQUE'}))

    def test_unknown_image_refuses_without_current_file_or_pbkdf2_slots(self):
        for label in ('UNKNOWN', 'OPAQUE'):
            with self.subTest(label=label):
                self.assert_refused_without_effects(images={'normal.efi': label}, active=(1, 7))

    def test_enable_current_key_in_each_image_is_already_enabled(self):
        rc, output, effects = self.scenario(action='enable', current='A', images={'normal.efi': 'A', 'normal.img': 'A'})
        self.assertEqual(rc, 0, output)
        self.assertIn('Already enabled:', output)
        self.assertEqual(effects, [])

    def test_enable_dead_key_at_same_filename_cannot_short_circuit(self):
        for image in ('normal.efi', 'normal.img'):
            for label in ('DEAD', 'B'):
                with self.subTest(image=image, label=label):
                    rc, output, effects = self.scenario(action='enable', current='A', images={image: label}, stop_confirm=True)
                    self.assertEqual(rc, 77, output)
                    self.assertNotIn('Already enabled:', output)
                    self.assertEqual(effects, [])

    def test_enable_post_rebuild_rejects_stale_key_contents(self):
        rc, output, effects = self.scenario(action='enable', current='A', images={'normal.efi': 'DEAD'}, rebuild_update=False)
        self.assertEqual(rc, 1, output)
        self.assertIn('rebuild', effects)
        self.assertNotIn('Enabled: key slot', output)

    def test_disable_checks_and_revokes_different_retained_live_key(self):
        rc, output, effects = self.scenario(current='A', images={'normal.efi': 'B'})
        self.assertEqual(rc, 0, output)
        self.assertIn('Disabled.', output)
        self.assertEqual([x for x in effects if x.startswith('remove ')], ['remove 5', 'remove 7'])
        self.assertLess(effects.index('remove 7'), effects.index('rm'))

    def test_disable_deduplicates_current_key_also_in_images(self):
        rc, output, effects = self.scenario(current='A', images={'normal.efi': 'A', 'normal.img': 'A'})
        self.assertEqual(rc, 0, output)
        self.assertEqual([x for x in effects if x.startswith('remove ')], ['remove 5'])

    def test_disable_refuses_owner_key_recovered_from_image(self):
        self.assertIn("owner's or recovery slot", self.assert_refused_without_effects(current='A', images={'normal.efi': 'OWNER'}))

    def test_disable_refuses_current_owner_key(self):
        self.assertIn("owner's or recovery slot", self.assert_refused_without_effects(current='OWNER'))

    def test_disable_refuses_removal_of_last_slot(self):
        self.assertIn('only key slot', self.assert_refused_without_effects(current='A', active=(5,), images={'normal.efi': 'A'}))

    def test_disable_refuses_removal_of_all_remaining_slots(self):
        self.assert_refused_without_effects(current='A', active=(5, 7), images={'normal.efi': 'B'})

    def test_disable_passphrase_must_open_a_slot_not_being_removed(self):
        rc, output, effects = self.scenario(current='A', images={'normal.efi': 'A'}, passphrase_slot=5)
        self.assertEqual(rc, 1, output)
        self.assertIn("couldn't confirm the passphrase", output)
        self.assertEqual(effects, ['confirm'])


if __name__ == '__main__':
    unittest.main()
