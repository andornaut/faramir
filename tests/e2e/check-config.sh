#!/bin/bash
# Changing an install's configuration, which is a flag plus a reload.
#
# There is one config file and faramir owns it, so nothing is hand-edited and
# there are no drop-ins to merge.  What makes this worth a suite is the property
# the whole arrangement rests on: `faramir init` rewrites the file from scratch
# every run, so a value set by a flag has to survive a later run that does not
# repeat that flag.  A value that does not survive is not a config option, it is
# a setting that silently reverts.
#
# The rest is what a wrong value does to a running host: refused by a fresh
# process before anything is applied, rather than taken and served.
#
# Run as root in the e2e container.
set -u
CFG=/etc/faramir/config.toml
CONFIG_DIR=/etc/faramir
. "$(dirname "$0")/lib.sh" || { echo "e2e: lib.sh is missing beside $0" >&2; exit 2; }

# check is the broker's own verdict on what is installed, as the broker's uid.
# JSON on stdout; the reasons go to stderr and are read separately by why().
check() { runuser -u faramir-broker -- /usr/local/bin/faramir broker -c $CFG --check 2>/dev/null; }
# shellcheck disable=SC2069  # stderr to the capture, stdout to null: reading the reasons, not the report
why()   { runuser -u faramir-broker -- /usr/local/bin/faramir broker -c $CFG --check 2>&1 >/dev/null; }
# reinit re-runs the installer with whatever flags it is given, and nothing else.
# --agent-user because this runs as root with no SUDO_USER to carry it, and
# --allow-sudo where the host already has a grant: that flag is a switch, so a
# re-run without it takes the grant away, and this suite is about config values
# rather than about removing the one thing later suites depend on.
GRANT=$(grep -q '^\[escalation\]' $CFG && echo --allow-sudo || true)
# shellcheck disable=SC2086  # GRANT is one flag or empty, deliberately unquoted
reinit() { /usr/local/bin/faramir init --agent-user op --config-dir "$CONFIG_DIR" $GRANT "$@" >/tmp/init.log 2>&1; }
# addkey puts a line inside a section that already exists.  Appending the header
# again would be a duplicate table, which TOML refuses before any of faramir's
# own rules are reached, so the test would pass on the wrong refusal.
# Replaces the key where the section already has one, and inserts it where it
# does not.  Appending a second copy is a duplicate key, which TOML refuses
# before any of faramir's own rules is reached, so the test would pass on the
# wrong refusal.
addkey() {
  local key=${2%% *}
  if sed -n "/^\[$1\]/,/^\[/p" $CFG | grep -q "^$key "; then
    sed -i "/^\[$1\]/,/^\[/{s/^$key = .*/$2/}" $CFG
  else
    sed -i "/^\[$1\]$/a $2" $CFG
  fi
}
# settle restarts onto whatever is on disk and waits for the broker to serve.
settle() {
  systemctl reset-failed 'faramir-*' >/dev/null 2>&1
  /usr/local/bin/faramir reload >/dev/null 2>&1
  waitfor 25 runuser -u op -- /usr/local/bin/faramir vault refs
}
# value reads one key out of the rendered config.
value() { sed -n "s/^$1 *= *\\(.*\\)/\\1/p" $CFG | head -1; }

echo "one config file: $CFG"

# --------------------------------------------------------------------------
head_ "1. a flag changes a default, and reload is what applies it"

reinit --secret-min-length 12 || bad "init refused --secret-min-length 12: $(tail -2 /tmp/init.log)"
[ "$(value min_length)" = "12" ] && ok "the flag is recorded in the config" \
  || bad "min_length = $(value min_length), want 12"
settle || bad "the host did not come back after reload"
# min_length 12 refuses a value that 8 admitted, which is how the change shows.
n=$(check | jq -r '.secrets.not_redactable | length' 2>/dev/null)
[ "${n:-0}" -ge 1 ] && ok "the new min_length is in force ($n ref(s) now refused)" \
  || bad "min_length = 12 had no effect (not_redactable = ${n:-?})"

# --------------------------------------------------------------------------
head_ "2. THE PROPERTY: a re-run without the flag keeps it"
#
# config.toml is rewritten from scratch every run, so this is the whole of what
# makes a flag a setting rather than a one-shot.  A value that reverts here is
# one a later `faramir init`, or a `faramir link add`, would silently undo.

reinit || bad "a bare re-run failed: $(tail -2 /tmp/init.log)"
[ "$(value min_length)" = "12" ] && ok "a bare re-run kept min_length = 12" \
  || bad "a bare re-run reverted min_length to $(value min_length)"

reinit --secret-min-length 8 || bad "init refused --secret-min-length 8"
[ "$(value min_length)" = "8" ] && ok "and naming the flag again changes it back" \
  || bad "min_length = $(value min_length), want 8"
settle || bad "the host did not come back"

# --------------------------------------------------------------------------
head_ "3. every tunable survives a bare re-run"
#
# One at a time would pass while the table that drives the round trip was
# missing an entry, so they are set together and read back after a run that
# names none of them.

reinit --command-timeout-sec 900 --command-max-timeout-sec 7200 \
  --command-concurrency 4 --secret-min-refresh-sec 30 \
  || bad "init refused the tunables: $(tail -2 /tmp/init.log)"
reinit || bad "the bare re-run failed"
for pair in "timeout_sec=900" "max_timeout_sec=7200" "concurrency=4" "min_refresh_sec=30"; do
  key=${pair%%=*}; want=${pair#*=}
  [ "$(value "$key")" = "$want" ] && ok "$key survived at $want" \
    || bad "$key = $(value "$key") after a bare re-run, want $want"
done

# --------------------------------------------------------------------------
head_ "4. no tunable takes zero"
#
# Zero is the signal an unset flag leaves, so a key that accepted it could not
# be told from one nobody typed: an operator asking for it would silently get
# the install's old value back.  Refused at the loader instead.

cp $CFG /tmp/config.good
addkey secret "min_refresh_sec = 0"
case "$(why)" in
  *"must be at least"*) ok "a zero refresh is refused rather than taken" ;;
  *) bad "min_refresh_sec = 0 was accepted: $(why | head -1)" ;;
esac
cp /tmp/config.good $CFG
settle || bad "the host did not come back"

# --------------------------------------------------------------------------
head_ "5. the environment adds rather than replaces"
#
# The table this replaced was all-or-nothing: naming one variable dropped the
# other four, so a file that set TERM left the broker resolving no bare program
# name at all.

reinit --command-env ANSIBLE_NOCOWS=1 || bad "init refused --command-env"
grep -q '^ANSIBLE_NOCOWS = "1"' $CFG && ok "the named variable is in the config" \
  || bad "--command-env did not land: $(grep -A6 '\[command.env\]' $CFG)"
grep -q '^PATH = ' $CFG && ok "and PATH is still there beside it" \
  || bad "naming one variable dropped PATH"
settle || bad "the host did not come back"
out=$(runuser -u op -- /usr/local/bin/faramir run -- printenv ANSIBLE_NOCOWS 2>/dev/null)
[ "$out" = "1" ] && ok "a brokered command gets it" || bad "the child did not get it: $out"

# --------------------------------------------------------------------------
head_ "6. a config.d beside the file is not read"
#
# There is no merge.  A file left over from an older install, or written by
# somebody expecting one, changes nothing rather than half-applying.

# Counted before and after: this host holds a value shorter than min_length of
# its own, so "none refused" is not the question.  Whether the number moves is.
was=$(check | jq -r '.secrets.not_redactable | length' 2>/dev/null)
mkdir -p $CONFIG_DIR/config.d
printf '[secret]\nmin_length = 30\n' > $CONFIG_DIR/config.d/50-stale.toml
settle || bad "the host did not come back with a stale drop-in present"
[ "$(value min_length)" = "8" ] && ok "the config still says 8" \
  || bad "min_length = $(value min_length)"
now=$(check | jq -r '.secrets.not_redactable | length' 2>/dev/null)
[ "${now:-0}" = "${was:-0}" ] && ok "and the drop-in refused nothing new (${now:-0} either way)" \
  || bad "a drop-in was applied: ${was:-0} ref(s) refused before, ${now:-0} after"
rm -rf $CONFIG_DIR/config.d

# --------------------------------------------------------------------------
head_ "7. a wrong value is refused by a fresh process"
#
# The daemons read this file at startup, so a bad one is caught before it is
# served rather than after.  --check is what init and doctor read.

cp $CFG /tmp/config.good
for case in "an unknown key:secret:nonsense = 1" \
            "a key in the wrong section:secret:timeout_sec = 30" \
            "a value under its floor:secret:min_length = 2" \
            "a key that stopped being one:command:max_output_bytes = 999"; do
  name=${case%%:*}; rest=${case#*:}
  addkey "${rest%%:*}" "${rest#*:}"
  out=$(why)
  case "$out" in
    *"unknown key"*|*"unknown section"*|*"must be at least"*)
      ok "$name is refused: $(printf '%s' "$out" | head -1 | cut -c1-72)" ;;
    *) bad "$name was accepted: ${out:-no reason given}" ;;
  esac
  cp /tmp/config.good $CFG
done
settle || bad "the host did not come back after the refusals"

# --------------------------------------------------------------------------
head_ "8. and the values that stopped being keys stay out"
#
# Each is a constant in the binary now.  Naming one is a mistake worth reporting
# rather than a setting that quietly does nothing.

for key in max_output_bytes term_cols kill_grace_sec max_request_bytes max_record_bytes; do
  grep -q "^$key" $CFG && bad "$key is still rendered into the config" \
    || ok "$key is not in the file"
done
printf '\n[exec]\ntimeout_sec = 30\n' >> $CFG
case "$(why)" in
  *"unknown section"*) ok "and a retired section is refused by name" ;;
  *) bad "a retired section was accepted: $(why | head -1)" ;;
esac
cp /tmp/config.good $CFG
settle || bad "the host did not come back"

# --------------------------------------------------------------------------
head_ "9. put the host back"
#
# Every section above changed a value, and the suites after this one run on
# whatever is left.  Restoring is not tidiness: a shorter refresh here would
# make a later suite's wait pass for the wrong reason, and a longer one would
# make it fail.

reinit --command-timeout-sec 600 --command-max-timeout-sec 3600 \
  --command-concurrency 10 --secret-min-refresh-sec 10 --secret-min-length 8 \
  || bad "could not restore the defaults: $(tail -2 /tmp/init.log)"
settle || bad "the host did not come back"
[ "$(value min_length)" = "8" ] && [ "$(value min_refresh_sec)" = "10" ] \
  && ok "the defaults are back" || bad "min_length=$(value min_length) min_refresh_sec=$(value min_refresh_sec)"

summary
