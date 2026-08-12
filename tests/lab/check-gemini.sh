#!/bin/bash
# Suite G: the Gemini CLI integration, both halves of it.
#
# The last agent whose enforcement path had never been driven, and the only one
# shaped this way: a BeforeTool hook for shell commands, and a separate deny
# policy for the file tools, which is a TOML of regexes Gemini matches against
# each call's arguments serialised as JSON.
#
# The policy is the half worth the suite.  faramir writes those regexes and
# nothing has ever checked that they match what they claim: a pattern that
# misses is a file tool reading an age key with no error anywhere.  They are
# matched here with node, Gemini's own flavour, against the paths they must
# refuse and against the ones they must not.
#
# Run as root in the lab container.
set -u
OP=op
PROJECT=/home/op/project
POLICY=/home/op/.gemini/policies/faramir.toml
SECRET='hunter2-correct-horse-battery'
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
head_() { printf '\n== %s\n' "$1"; }

# --------------------------------------------------------------------------
head_ "G1. what enrolment writes"

/usr/local/bin/faramir init-project --operator-user $OP --agent gemini "$PROJECT" >/dev/null 2>&1
/usr/local/bin/faramir init --operator-user $OP --agent gemini >/dev/null 2>&1

SETTINGS=$PROJECT/.gemini/settings.json
[ -f "$SETTINGS" ] && ok "the project settings are at .gemini/settings.json ($(stat -c %a $SETTINGS))" \
  || bad "no project settings at $SETTINGS"
jq -e . "$SETTINGS" >/dev/null 2>&1 && ok "and parse as JSON" || bad "the settings are not JSON"
[ -f "$POLICY" ] && ok "the account-wide policy is at ~/.gemini/policies/faramir.toml ($(stat -c %a $POLICY))" \
  || bad "no policy at $POLICY"
[ "$(stat -c %U "$POLICY" 2>/dev/null)" = "$OP" ] && ok "owned by the operator" \
  || bad "the policy is owned by $(stat -c %U "$POLICY" 2>/dev/null)"

# Valid TOML, or Gemini reads no rules at all and says nothing about it.
rules=$(python3 - "$POLICY" <<'PY' 2>/dev/null
import sys, tomllib, json
with open(sys.argv[1], "rb") as fh:
    doc = tomllib.load(fh)
print(json.dumps(doc.get("rule", [])))
PY
)
if [ -n "$rules" ]; then
  n=$(jq length <<<"$rules")
  ok "the policy is valid TOML with $n rule(s)"
else
  bad "the policy is not valid TOML"
fi
[ "$(jq -r '[.[] | select(.decision != "deny")] | length' <<<"$rules")" = 0 ] \
  && ok "and every rule denies rather than asking" || bad "a rule does not deny"
[ "$(jq -r '[.[] | select(.priority != 1000)] | length' <<<"$rules")" = 0 ] \
  && ok "at a priority a later allow cannot outrank" || bad "a rule is not priority 1000"
for tool in read_file read_many_files write_file replace; do
  jq -e --arg t "$tool" 'any(.[]; .toolName == $t)' <<<"$rules" >/dev/null \
    && ok "  $tool is covered" || bad "  $tool has no rule"
done

# --------------------------------------------------------------------------
head_ "G2. the hook it registers, run"

hook=$(jq -r '.hooks.BeforeTool[0].hooks[0].command' "$SETTINGS" 2>/dev/null)
matcher=$(jq -r '.hooks.BeforeTool[0].matcher' "$SETTINGS" 2>/dev/null)
[ "$matcher" = run_shell_command ] && ok "the hook matches run_shell_command" \
  || bad "the hook matches $matcher"
[ -n "$hook" ] && ok "and names: $hook" || bad "no hook command"

ask() { # command -> the hook's answer
  printf '{"tool_name":"run_shell_command","tool_input":{"command":%s}}' "$(jq -Rn --arg c "$1" '$c')" \
    | runuser -u $OP -- sh -c "cd $PROJECT && $hook" 2>/dev/null
}

out=$(ask 'cat /etc/faramir/age.key')
[ "$(jq -r .decision <<<"$out" 2>/dev/null)" = deny ] && ok "reading the age key is denied" \
  || bad "the age key was not denied: ${out:0:110}"
jq -r .reason <<<"$out" 2>/dev/null | grep -q 'faramir_run' && ok "and the reason names the tool to use instead" \
  || bad "no corrective reason: $(jq -r .reason <<<"$out" 2>/dev/null | head -c 70)"

out=$(ask 'echo hello')
jq -e '.hookSpecificOutput.tool_input.command' <<<"$out" >/dev/null 2>&1 \
  && ok "an ordinary command comes back rewritten under hookSpecificOutput" \
  || bad "not rewritten: ${out:0:110}"

# Gemini has no allow to return, so a hook that has not denied has not approved.
# An "allow" here would be faramir claiming an approval this host cannot grant.
grep -qi '"allow"\|permissionDecision' <<<"$out" \
  && bad "the gemini answer carries an approval it cannot grant: ${out:0:110}" \
  || ok "and carries no approval, this host having none to give"

# The rewrite merges over the model's arguments rather than replacing them.
out=$(printf '{"tool_name":"run_shell_command","tool_input":{"command":"echo hello","description":"say hi"}}' \
  | runuser -u $OP -- sh -c "cd $PROJECT && $hook" 2>/dev/null)
[ "$(jq -r '.hookSpecificOutput.tool_input.description' <<<"$out" 2>/dev/null)" = "say hi" ] \
  && ok "and keeps every other argument the model sent" \
  || bad "the rewrite dropped an argument: ${out:0:110}"

# What it hands back runs, and redacts.
cmd=$(ask 'echo hunter2-correct-horse-battery' | jq -r '.hookSpecificOutput.tool_input.command')
out=$(runuser -u $OP -- env XDG_RUNTIME_DIR="/run/user/$(id -u "$OP")" bash -c "cd $PROJECT && $cmd" 2>&1)
grep -qF "$SECRET" <<<"$out" && bad "running the rewrite printed the value" \
  || ok "running the rewrite does not print the value"
grep -q '«SECRET:db/password»' <<<"$out" && ok "it comes back as its token" \
  || bad "no token: $(head -c 90 <<<"$out")"

# A tool that is not the shell is left alone.
out=$(printf '{"tool_name":"read_file","tool_input":{"file_path":"/etc/faramir/age.key"}}' \
  | runuser -u $OP -- sh -c "cd $PROJECT && $hook" 2>/dev/null)
[ -z "$(tr -d '[:space:]' <<<"$out")" ] \
  && ok "a file tool is left to the policy rather than answered here" \
  || bad "the shell hook answered for read_file: ${out:0:110}"

# --------------------------------------------------------------------------
head_ "G3. the policy regexes, matched the way Gemini matches them"
#
# One rule per file tool, a regex against the call's arguments as JSON.  These
# are the only thing standing between a file tool and the key material, and
# nothing else in this repo tests them.

cat > /tmp/policy-match.mjs <<'EOF'
// usage: node policy-match.mjs '<rules json>' <toolName> '<args json>'
const [rulesRaw, toolName, args] = process.argv.slice(2)
const rules = JSON.parse(rulesRaw).filter((r) => r.toolName === toolName)
const hit = rules.some((r) => new RegExp(r.argsPattern).test(args))
process.stdout.write(hit ? "deny" : "allow")
EOF
chmod 0644 /tmp/policy-match.mjs

match() { node /tmp/policy-match.mjs "$rules" "$1" "$2" 2>/dev/null; }

denies() { # tool, path, why
  local got; got=$(match "$1" "$(jq -cn --arg p "$2" '{file_path:$p}')")
  [ "$got" = deny ] && ok "$1 refuses $2" || bad "$1 ALLOWS $2 ($3)"
}
allows() { # tool, path, why
  local got; got=$(match "$1" "$(jq -cn --arg p "$2" '{file_path:$p}')")
  [ "$got" = allow ] && ok "$1 still allows $2" || bad "$1 refuses $2, which it should not ($3)"
}

for tool in read_file write_file replace; do
  denies $tool /etc/faramir/age.key "the master key"
  denies $tool /etc/faramir/secrets/app.sops.yml "a managed store"
  denies $tool /home/op/.config/sops/age/keys.txt "the sops key file"
  denies $tool /home/op/.ssh/id_ed25519 "an ssh private key"
  denies $tool /home/op/.env "a dotfile of values"
  denies $tool /srv/app/vault.yml "an ansible vault"
  denies $tool /srv/app/secrets.yml "a secrets file"
  denies $tool /etc/ssl/private/server.pem "a private key by extension"
  denies $tool /home/op/.aws/credentials "a credentials file"
done

# The false positives that would break ordinary work.  faramir.env is named in
# the policy's own comment: it holds refs and is meant to be read.
allows read_file /srv/app/faramir.env "it holds refs, not values"
allows read_file /srv/app/README.md "an ordinary file"
allows read_file /srv/app/main.go "an ordinary file"
allows read_file /srv/app/environment.yml "not a dotfile"

# Reading a directory at once takes globs rather than a path, so a deny that
# covered only read_file would leave this open.
many() { node /tmp/policy-match.mjs "$rules" read_many_files "$1" 2>/dev/null; }
[ "$(many '{"include":["/etc/faramir/secrets/*.sops.yml"]}')" = deny ] \
  && ok "read_many_files refuses a glob over the store" \
  || bad "read_many_files ALLOWS a glob over the store"
[ "$(many '{"include":["/home/op/.ssh/id_ed25519"]}')" = deny ] \
  && ok "and one naming an ssh key" || bad "read_many_files ALLOWS an ssh key"
[ "$(many '{"include":["src/**/*.go"]}')" = allow ] \
  && ok "while an ordinary glob is still allowed" || bad "read_many_files refuses an ordinary glob"

# Whitespace: the serialiser promises only "a stable JSON string", so the
# patterns tolerate space around the colon.  If they did not, a pretty-printing
# Gemini release would open every rule at once.
[ "$(match read_file '{"file_path" : "/etc/faramir/age.key"}')" = deny ] \
  && ok "a space around the colon does not defeat a rule" \
  || bad "a rule matches only one spelling of the JSON"

# --------------------------------------------------------------------------
head_ "G4. this install's own directories, named rather than guessed"

for dir in /etc/faramir /etc/faramir/secrets /var/log/faramir /usr/local/libexec/faramir; do
  denies read_file "$dir/anything" "an install directory"
done
# regexQuote, so a directory whose name merely starts the same is not caught.
allows read_file /etc/faramir-notes/plan.md "a different directory"

# --------------------------------------------------------------------------
head_ "G5. and nothing here carries a value"

grep -qF "$SECRET" "$POLICY" "$SETTINGS" && bad "a value is written into the gemini configuration" \
  || ok "no value in the policy or the settings"
grep -q '/usr/local/bin/faramir' "$SETTINGS" && ok "the settings name the installed binary" \
  || bad "the settings do not name the binary"

# --------------------------------------------------------------------------
printf '\n== suite G: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
