#!/bin/bash
# The MCP server, which is the other half of the agent-facing surface.
#
# The guard refuses a command and tells the model to use faramir_run instead.
# This is faramir_run.  If it is wrong the agent either cannot work at all or
# gets a value it should never see, so the suite covers both: the protocol a
# client holds it to, and what a model gets back when it asks for a secret.
#
# Driven over real stdio against the real binary, as the agent's own uid.
set -u
cat > /tmp/mcp_suite.py <<'PYEOF'
import json, os, subprocess, sys, time

SECRET = "hunter2-correct-horse-battery"
SECOND = "tok_live_0PENSESAME_9911"
TOKEN  = "«SECRET:db/password»"
PASS = FAIL = 0

# The same primitives lib.sh gives the other suites, in the language this one is
# written in.  A python suite cannot source it, so the output has to match by
# hand: an operator reads all eighteen as one list.
def ok(m):
    global PASS; PASS += 1; print("  ok   " + m)
def bad(m):
    global FAIL; FAIL += 1; print("  FAIL " + m)
def head(m):
    print("\n== " + m)

class Server:
    """One `faramir mcp` process, spoken to over stdio as the agent would."""
    def __init__(self, cwd="/home/op/project", env=None, user="op"):
        e = dict(os.environ); e.update(env or {})
        self.p = subprocess.Popen(
            ["runuser", "-u", user, "--", "/usr/local/bin/faramir", "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=e, text=True, bufsize=1)
        self.n = 0
    def send_raw(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
    def send(self, method, params=None, ident=True):
        msg = {"jsonrpc": "2.0", "method": method}
        if ident:
            self.n += 1; msg["id"] = self.n
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg))
        return msg.get("id")
    def read(self):
        line = self.p.stdout.readline()
        if not line:
            return None
        return json.loads(line)
    def call(self, method, params=None):
        self.send(method, params)
        return self.read()
    def tool(self, name, arguments=None):
        r = self.call("tools/call", {"name": name, "arguments": arguments or {}})
        return r.get("result", {}) if r else {}
    def text(self, name, arguments=None):
        r = self.tool(name, arguments)
        parts = r.get("content") or []
        return "".join(p.get("text", "") for p in parts), r.get("isError", False)
    def close(self):
        try:
            self.p.stdin.close(); self.p.wait(timeout=10)
        except Exception:
            self.p.kill()

# ---------------------------------------------------------------------------
head("1. the handshake a client performs before anything else")
s = Server()
r = s.call("initialize", {"protocolVersion": "2025-06-18",
                          "clientInfo": {"name": "probe", "version": "1"}})
res = r.get("result", {})
ok("initialize is answered") if res else bad("initialize returned %s" % r)
(ok("it speaks MCP 2025-06-18") if res.get("protocolVersion") == "2025-06-18"
 else bad("protocolVersion = %s" % res.get("protocolVersion")))
info = res.get("serverInfo", {})
(ok("it names itself faramir %s" % info.get("version"))
 if info.get("name") == "faramir" and info.get("version")
 else bad("serverInfo = %s" % info))
(ok("it declares a tools capability") if "tools" in res.get("capabilities", {})
 else bad("capabilities = %s" % res.get("capabilities")))
# The instructions are the model's standing brief; they have to name the tool.
instr = res.get("instructions", "")
(ok("its instructions name faramir_run as the way through")
 if "faramir_run" in instr else bad("instructions = %r" % instr[:80]))
(bad("the instructions contain a secret value") if SECRET in instr
 else ok("and contain no value"))

# A client asking for a version this server does not speak must not be told
# its own version back, or it holds the server to something it never had.
s2 = Server()
r = s2.call("initialize", {"protocolVersion": "1999-01-01"})
got = r.get("result", {}).get("protocolVersion")
(ok("an unsupported client version is answered with the server's own (%s)" % got)
 if got == "2025-06-18" else bad("echoed back %s" % got))
s2.close()

head("2. what the model discovers")
r = s.call("tools/list")
tools = r.get("result", {}).get("tools", [])
names = sorted(t["name"] for t in tools)
# Both sides sorted: which tool sorts first is not the claim, and a rename that
# reorders them is not a regression.
(ok("two tools: %s" % ", ".join(names))
 if names == sorted(["faramir_run", "faramir_refs"])
 else bad("tools = %s" % names))
run = next((t for t in tools if t["name"] == "faramir_run"), {})
desc = run.get("description", "")
for phrase, why in [("faramir_refs", "points at how to discover names"),
                    ("faramir://", "shows the ref syntax"),
                    ("environment variables", "says injection is by env, not argv"),
                    ("bash", "says no shell is spawned for you")]:
    (ok("the faramir_run description %s" % why) if phrase in desc
     else bad("description does not mention %r" % phrase))
schema = run.get("inputSchema", {})
props = schema.get("properties", {})
(ok("its schema declares cmd, env_refs, cwd, timeout_sec")
 if all(k in props for k in ("cmd", "env_refs", "cwd", "timeout_sec"))
 else bad("schema properties = %s" % sorted(props)))
(ok("and cmd is required") if "cmd" in schema.get("required", [])
 else bad("required = %s" % schema.get("required")))

head("3. JSON-RPC conformance")
# A notification has no id and gets no reply, ever.  Proved by what comes back
# next rather than by waiting: the ping's answer must be the very next line.
s.send("notifications/initialized", {}, ident=False)
s.send_raw(json.dumps({"jsonrpc": "2.0", "method": "tools/list"}))  # no id
r = s.call("ping")
(ok("a notification and an id-less request get no reply at all")
 if r and r.get("id") == s.n else bad("next reply was %s" % r))
(ok("ping is answered with an empty result") if r.get("result") == {}
 else bad("ping result = %s" % r.get("result")))
# An unknown method with an id is an error; without one it is silence.
r = s.call("does/not/exist")
err = r.get("error", {})
(ok("an unknown method is -32601") if err.get("code") == -32601
 else bad("unknown method -> %s" % r))
s.send_raw(json.dumps({"jsonrpc": "2.0", "method": "also/unknown"}))
r = s.call("ping")
(ok("an unknown method with no id is answered with silence")
 if r.get("id") == s.n else bad("got %s" % r))
# A parse error is reported and the server keeps going.
s.send_raw("{this is not json")
r = s.read()
(ok("malformed JSON is -32700 with a null id")
 if r.get("error", {}).get("code") == -32700 and r.get("id") is None
 else bad("malformed JSON -> %s" % r))
r = s.call("ping")
(ok("and the session survives it") if r.get("result") == {}
 else bad("the server stopped answering after a parse error"))
# Ids come back as they were sent, type and all.
s.send_raw(json.dumps({"jsonrpc": "2.0", "id": "string-id", "method": "ping"}))
r = s.read()
(ok("a string id comes back a string") if r.get("id") == "string-id"
 else bad("id = %r" % r.get("id")))
s.send_raw("")
s.send_raw("   ")
r = s.call("ping")
(ok("blank lines are skipped") if r.get("result") == {} else bad("blank line broke it"))

head("4. running a command")
out, is_err = s.text("faramir_run", {"cmd": ["/bin/echo", "hello"]})
(ok("a plain command runs and returns its output") if out.startswith("hello")
 else bad("output = %r" % out[:80]))
(ok("and is not flagged an error") if not is_err else bad("isError set on a success"))
(ok("and reports exit_code=0") if "exit_code=0" in out else bad("no exit_code: %r" % out))
(ok("and a log_id the operator can look up") if "log_id=" in out
 else bad("no log_id: %r" % out))
out, is_err = s.text("faramir_run", {"cmd": ["/bin/sh", "-c", "exit 3"]})
(ok("a non-zero exit is reported as an error to the model") if is_err
 else bad("a failing command was not flagged"))
(ok("with the status in the meta line") if "exit_code=3" in out else bad(out[:80]))

head("5. the thing the whole tool exists for")
out, _ = s.text("faramir_run", {"cmd": ["printenv", "PW"],
                                "env_refs": {"PW": "faramir://db/password"}})
(bad("THE VALUE CAME BACK TO THE MODEL: %r" % out[:120]) if SECRET in out
 else ok("the injected value does not come back"))
(ok("it comes back as its ref token") if TOKEN in out else bad("no token: %r" % out[:120]))
(ok("and the meta line counts the redaction") if "redacted:" in out
 else bad("no redaction summary: %r" % out[:120]))
# Every rendering an ordinary command might print it in.
out, _ = s.text("faramir_run", {
    "cmd": ["/bin/sh", "-c", "printenv PW; printenv PW | base64; printenv PW | xxd -p"],
    "env_refs": {"PW": "faramir://db/password"}})
# The body only: the meta line names the token too, and counting that as a
# fourth replacement would be counting the summary as one of the things it
# summarises.  Each encoded line keeps a tail ("K", "0a") -- printenv adds a
# newline, so what was encoded is the value plus one byte, and only the value's
# part of the encoding matches.  No part of the value survives in it.
body = out.split("\n[")[0]
if SECRET in out:
    bad("a rendering escaped: %r" % out[:200])
elif body.count(TOKEN) != 3:
    bad("wanted three tokens in the body, got %d: %r" % (body.count(TOKEN), body[:200]))
else:
    ok("plain, base64 and hex renderings are all replaced")
(ok("and the meta line counts all three") if "×3" in out
 else bad("count not reported as 3: %s" %
          [l for l in out.splitlines() if "redacted" in l][:1]))

# A value the broker never injected is still redacted: the redactor is built
# from every managed value, not the ones this call asked for.
out, _ = s.text("faramir_run", {"cmd": ["/bin/echo", "the token is " + SECOND]})
if SECOND in out:
    bad("an uninjected value printed in the clear: %r" % out[:120])
elif "«SECRET:api/token»" not in out:
    bad("neither the value nor its token came back, so this proved nothing: %r" % out[:120])
else:
    ok("a value nobody injected is redacted too")

# Refs are injected as environment only, never substituted into argv.
out, _ = s.text("faramir_run", {"cmd": ["/bin/echo", "faramir://db/password"]})
if SECRET in out:
    bad("a ref on the command line was resolved into a value")
elif "faramir://db/password" not in out:
    bad("the ref did not come back as text either: %r" % out[:120])
else:
    ok("a ref in argv is echoed as text, never substituted")

# The description tells the model that transforming output (rev, cut) is a
# policy violation rather than a puzzle, which is an admission that those are
# not caught: the variant set covers encodings a program produces by accident,
# not a deliberate mangling.  Pinned so a change here is noticed.
out, _ = s.text("faramir_run", {"cmd": ["/bin/sh", "-c", "printenv PW | rev"],
                                "env_refs": {"PW": "faramir://db/password"}})
if SECRET[::-1] in out:
    ok("a deliberately reversed value is NOT caught, as the tool description says")
else:
    bad("reversal is now redacted; the faramir_run description still calls it a "
        "policy violation rather than something prevented")
(ok("and the description does say so") if "policy violation" in desc
 else bad("nothing warns the model off transforming output"))

head("6. refs the model may not have")
out, is_err = s.text("faramir_run", {"cmd": ["/bin/echo", "x"],
                                     "env_refs": {"X": "faramir://no/such/thing"}})
(ok("an unknown ref is refused") if is_err else bad("an unknown ref was accepted"))
(bad("the refusal leaked a value") if SECRET in out else ok("and names no value"))
# The short one, refused at load as not redactable.
out, is_err = s.text("faramir_run", {"cmd": ["/bin/echo", "x"],
                                     "env_refs": {"X": "faramir://short/pin"}})
(ok("a ref refused at load is refused here too") if is_err
 else bad("the not-redactable value was injectable through MCP"))
(bad("the pin came back") if "8341" in out else ok("and its value is not in the answer"))
# refs names refs and no values.
out, _ = s.text("faramir_refs")
(ok("refs returns the ref names") if "faramir://db/password" in out
 else bad("refs = %r" % out[:120]))
(bad("refs returned a value") if SECRET in out else ok("and no values"))
(ok("and does not offer the refused ref") if "short/pin" not in out
 else bad("the refused ref is offered as usable"))
# There is no status tool: what it answered was which config files loaded and
# what failed to, and no agent acts on any of it.  Being refused is the point.
out, is_err = s.text("faramir_status")
(ok("no status tool is offered") if is_err and "unknown tool" in out
 else bad("faramir_status answered: %r" % out[:120]))
(bad("status named the refused ref to the agent") if "short/pin" in out
 else ok("and keeps the refused refs to the operator's own report"))

head("7. calling it wrong, which a model will")
cases = [
    ({"cmd": "ls -la"},               "must be an array",     "a shell string instead of an array"),
    ({"cmd": []},                     "must name a program",  "an empty array"),
    ({"cmd": ["ls", 7]},              "must be a string",     "a non-string element"),
    ({},                              "must be an array",     "no cmd at all"),
]
for args, expect, label in cases:
    out, is_err = s.text("faramir_run", args)
    if not is_err:
        bad("%s was accepted" % label)
    elif expect not in out:
        bad("%s -> %r, wanted %r" % (label, out[:90], expect))
    else:
        ok("%s is refused with a corrective message" % label)
out, is_err = s.text("faramir_run", {"cmd": ["ls -la"]})
(ok("a shell string as the only element is not shell-interpreted") if is_err
 else bad("'ls -la' as argv[0] appeared to run: %r" % out[:80]))
out, is_err = s.text("no_such_tool", {})
(ok("an unknown tool is refused by name") if is_err and "unknown tool" in out
 else bad("unknown tool -> %r" % out[:80]))
r = s.call("tools/call", {"name": "faramir_refs"})   # no arguments key at all
(ok("a call with no arguments object is handled")
 if r.get("result") else bad("missing arguments -> %s" % r))

head("8. where the command runs")
out, _ = s.text("faramir_run", {"cmd": ["pwd"]})
(ok("cwd defaults to where the agent's session is (%s)" % out.splitlines()[0])
 if out.startswith("/home/op/project") else bad("pwd = %r" % out[:80]))
out, _ = s.text("faramir_run", {"cmd": ["pwd"], "cwd": "/tmp"})
(ok("an explicit cwd wins") if out.startswith("/tmp") else bad("pwd = %r" % out[:80]))
out, is_err = s.text("faramir_run", {"cmd": ["pwd"], "cwd": "/root"})
(ok("a directory the executor cannot enter is an error, not a silent fallback")
 if is_err else bad("running in /root reported success: %r" % out[:80]))
s.close()

head("9. limits and failure")
s = Server()
s.call("initialize", {"protocolVersion": "2025-06-18"})
started = time.time()
out, is_err = s.text("faramir_run", {"cmd": ["/bin/sleep", "30"], "timeout_sec": 2})
took = time.time() - started
if "timed out" not in out:
    bad("a command over timeout_sec did not say it timed out: %r" % out[:120])
elif took > 20:
    bad("it said timed out but took %.0fs, so the limit did not stop it" % took)
else:
    ok("a command over timeout_sec is stopped after %.0fs and says so" % took)
# Output past the output cap is truncated, and says it was.
out, _ = s.text("faramir_run", {"cmd": ["/bin/sh", "-c", "yes abcdefgh | head -c 2000000"]})
(ok("output past max_output_bytes is truncated and labelled") if "truncated" in out
 else bad("2MB of output was not reported truncated (%d chars back)" % len(out)))
# A large but legal output survives the round trip as one JSON line.
# Under internal/config MaxOutputBytes (256 KiB), so this one is not truncated.
out, _ = s.text("faramir_run", {"cmd": ["/bin/sh", "-c", "yes abcdefgh | head -c 200000"]})
(ok("200KB of output comes back intact (%d chars)" % len(out))
 if len(out) > 190000 else bad("large output truncated early: %d" % len(out)))
s.close()

head("10. the broker not being there")
subprocess.run(["systemctl", "stop", "faramir-broker.socket", "faramir-broker.service"],
               capture_output=True)
s = Server()
out, is_err = s.text("faramir_run", {"cmd": ["/bin/echo", "hi"]})
(ok("a stopped broker is reported as unavailable, not a crash")
 if is_err and "unavailable" in out else bad("broker down -> %r" % out[:120]))
r = s.call("tools/list")
(ok("and the server still answers the protocol") if r.get("result")
 else bad("the server died with the broker"))
s.close()
subprocess.run(["systemctl", "start", "faramir-broker.socket"], capture_output=True)
time.sleep(2)

head("11. who may run it")
# The socket admits the client group.  An account outside it gets nothing,
# whatever it asks the MCP server for.
subprocess.run(["useradd", "-m", "outsider"], capture_output=True)
s = Server(cwd="/tmp", user="outsider")
out, is_err = s.text("faramir_run", {"cmd": ["/bin/echo", "hi"]})
if not is_err:
    bad("an outsider ran a brokered command: %r" % out[:120])
elif "hi" in out:
    bad("the command ran despite the error: %r" % out[:120])
else:
    ok("an account outside the client group is refused: %r" % out.split("\n")[0][:60])
# The refusal has to be the broker's, not the MCP server failing to start:
# a suite that cannot tell those apart would pass on a broken binary.
(ok("and it is the socket refusing, not the server failing to run")
 if "forbidden" in out or "unavailable" in out or "permission" in out.lower()
 else bad("refused for an unclear reason: %r" % out[:120]))
out, _ = s.text("faramir_refs")
(bad("an outsider was given the ref names") if "faramir://db/password" in out
 else ok("and cannot even list the ref names"))
s.close()

head("12. how the agent is told to start it")
reg = json.load(open("/home/op/project/.mcp.json"))
entry = reg.get("mcpServers", {}).get("faramir", {})
(ok("init-project registered it as %s %s" % (entry.get("command"), " ".join(entry.get("args", []))))
 if entry.get("command") and entry.get("args") == ["mcp"]
 else bad(".mcp.json = %s" % reg))
proof = subprocess.run([entry["command"], *entry["args"], "--version"],
                       capture_output=True, text=True)
(ok("and that exact command answers --version: %s" % proof.stdout.strip())
 if proof.returncode == 0 and "faramir" in proof.stdout
 else bad("the registered command does not run: %s" % proof))

print("\n== mcp: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
PYEOF
python3 /tmp/mcp_suite.py
