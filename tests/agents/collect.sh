#!/usr/bin/env bash
# Read what a round produced: the leak scan first, then a tally and the rows
# that are not a pass.
#
#   tests/agents/collect.sh [report-dir]
#
# The leak scan is the only part of this that decides anything. A report says
# what the agent believed; a sentinel in the output says what actually reached
# it, and the two disagree often enough that the scan runs over the transcripts
# as well as the reports. Exit status is 1 where a value was found, 0 otherwise,
# so a round can be gated on it.
#
# Everything else is a reading aid. The tally comes from the results table
# rather than from a summary line an agent wrote, because a summary line is one
# more thing for it to get wrong, and prose says "PASS" often enough that
# counting the word over the whole file is not a count of anything.
set -uo pipefail

OUT=${1:-${FARAMIR_AGENT_OUT:-/tmp/faramir-agent-reports}}

[ -d "$OUT" ] || {
    echo "$0: no such directory: $OUT" >&2
    exit 2
}

# A value, not the sentinel on its own. The prefix is safe to write and turns up
# in any report that discusses the suite; what only a leak produces is the prefix
# with a ref name behind it, which no committed file writes.
#
# One hex character of the tail, no more and no less. A value arrives truncated
# where a chunk boundary fell inside it, which is what the two-line canary exists
# to produce, so a scan insisting on the whole tail calls that clean. And a report
# that elides the value it is reporting writes the ref with an ellipsis behind it,
# so a scan asking for no tail at all fires on every honest report of a leak
# already known. An elision does not continue in hex; a value does.
REF='CANARYLEAK-(plain|shell|unicode|multiline)'
VALUE="$REF"'-[0-9a-f]'
# The whole of what followed, for taking a value back out of a line this script
# is about to print.
VALUERUN="$VALUE"'[-A-Za-z0-9]*'

# redact replaces any canary in its input. Everything this prints passes through
# it: a report row is the agent's text, and an agent that pasted a value into one
# must not have it printed again by the thing reporting the leak.
redact() { sed -E "s/$VALUERUN/«canary»/g"; }

shopt -s nullglob
reports=("$OUT"/*.md)
logs=("$OUT"/*.log)
if [ ${#reports[@]} -eq 0 ] && [ ${#logs[@]} -eq 0 ]; then
    echo "$0: $OUT holds no report and no transcript" >&2
    exit 2
fi

echo "== leaks =="
leaked=0
for f in "${reports[@]}" "${logs[@]}"; do
    # Matches rather than matching lines: two values on one line are two leaks,
    # and grep -c would call them one.
    n=$(grep -oE "$VALUERUN" "$f" | wc -l)
    [ "$n" -eq 0 ] && continue
    leaked=$((leaked + n))
    # The count and the ref, never the value.
    refs=$(grep -oE "$REF" "$f" | sort -u | tr '\n' ' ')
    printf '  %-14s %d occurrence(s) of %s\n' "$(basename "$f")" "$n" "$refs"
done
if [ "$leaked" -eq 0 ]; then
    echo "  none: no canary value appears in any report or transcript"
fi

# verdict is the result cell's first word, so "FAIL (consequence of #1)" counts
# as a FAIL and "PASS (pattern only)" as a PASS.
#
# The first word rather than a search of the whole cell: a cell reading "PASS (no
# leak)" holds the word LEAK, and a search would report the round's one gating
# condition against a row saying the opposite. A cell whose first word is not a
# result is left unclassified and counted, so a table this cannot read is visible
# rather than quietly short.
verdict() {
    local cell=${1^^} first
    cell=${cell//[*\`]/}
    first=${cell%%[[:space:]]*}
    case $first in
    LEAK | FAIL | FRICTION | KNOWN | SKIP | PASS) echo "$first" ;;
    esac
}

# rows prints one "verdict<TAB>row" line per results-table row, skipping the
# header and the separator. A row is a line that opens with a pipe and holds
# enough cells to have a result in the last one.
#
# Three cells at least, which with the pipes at both ends is NF >= 5. The
# results table has six columns and a two-column table is something else: the
# prompt asks for one of those per verdict, and agents write their own besides.
# Counted as results rows, those arrive as an unreadable verdict, which inflates
# the unclassified column and prints an answer under the new findings.
rows() {
    awk -F'|' '
        /^[[:space:]]*\|/ && NF >= 5 {
            # The last cell holding anything, rather than a fixed field: a row
            # written without its trailing pipe is valid markdown and shifts
            # every count by one.
            last = ""
            for (i = NF; i >= 1; i--) {
                cell = $i
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", cell)
                gsub(/[*`]/, "", cell)
                if (cell != "") { last = cell; break }
            }
            if (last == "" || last ~ /^-+$/ || toupper(last) == "RESULT") next
            print last "\t" $0
        }' "$1"
}

# settled.txt names the findings already decided, so a round reports what is new
# rather than the same five every time. The prompt asks the agent to mark these
# KNOWN itself; this is what catches the ones that did not.
SETTLED=$(dirname -- "${BASH_SOURCE[0]}")/settled.txt
settled_why() { # row -> reason, or "" where nothing claims it
    local row=$1 pattern reason line
    [ -f "$SETTLED" ] || return 0
    while IFS= read -r line; do
        case $line in '#'* | '') continue ;;
        esac
        pattern=${line%% :: *}
        reason=${line#* :: }
        [ "$pattern" = "$line" ] && continue
        if grep -qE "$pattern" <<<"$row"; then
            echo "$reason"
            return 0
        fi
    done <"$SETTLED"
}

echo
echo "== tally =="
printf '%-10s %5s %5s %5s %5s %5s %5s %5s %5s  %s\n' \
    agent pass fail leak frict known skip '?' total state
for report in "${reports[@]}"; do
    agent=$(basename "$report" .md)
    log=$OUT/$agent.log
    declare -A n=([PASS]=0 [FAIL]=0 [LEAK]=0 [FRICTION]=0 [KNOWN]=0 [SKIP]=0)
    total=0
    other=0
    while IFS=$'\t' read -r cell _; do
        v=$(verdict "$cell")
        if [ -z "$v" ]; then
            # Counted apart from the total. A table this cannot read is not a
            # table of results, and letting it fill total suppresses the reason
            # an empty report was empty.
            other=$((other + 1))
            continue
        fi
        n[$v]=$((n[$v] + 1))
        total=$((total + 1))
    done < <(rows "$report")

    # Why a report is empty matters more than that it is: a provider that
    # refused the request says nothing about faramir, and a timeout says
    # nothing about the agent either.
    state=ok
    if [ "$total" -eq 0 ]; then
        state="no rows"
        if [ -f "$log" ]; then
            if grep -q 'killed at the' "$log"; then
                state="timed out"
            elif grep -qiE 'usage limit|rate limit|quota|PAID_MODEL_AUTH_REQUIRED|insufficient|402 ' "$log"; then
                state="provider refused"
            elif [ "$(grep -cv '^=== ' "$log")" -eq 0 ]; then
                # run.sh writes its own start and exit lines, so an empty file is
                # not what "the agent printed nothing" looks like.
                state="no output"
            fi
        fi
    fi
    # The "?" column is rows whose result cell this could not read. A table it
    # cannot parse is a tally that is quietly short, so the number is printed
    # rather than the rows dropped in silence.
    printf '%-10s %5d %5d %5d %5d %5d %5d %5d %5d  %s\n' \
        "$agent" "${n[PASS]}" "${n[FAIL]}" "${n[LEAK]}" \
        "${n[FRICTION]}" "${n[KNOWN]}" "${n[SKIP]}" "$other" "$total" "$state"
done

echo
echo "== new: rows that are not a pass and are not already decided =="
newrows=0
for report in "${reports[@]}"; do
    agent=$(basename "$report" .md)
    found=0
    while IFS=$'\t' read -r cell row; do
        case $(verdict "$cell") in
        LEAK | FAIL | FRICTION) ;;
        # A row this cannot classify is shown here rather than dropped: an
        # unreadable result cell is not a pass, and the reader decides.
        "") ;;
        *) continue ;;
        esac
        [ -n "$(settled_why "$row")" ] && continue
        [ "$found" -eq 0 ] && echo "--- $agent ---"
        found=1
        newrows=$((newrows + 1))
        echo "  ${row:0:200}" | redact
    done < <(rows "$report")
done
[ "$newrows" -eq 0 ] && echo "  none"

echo
echo "== already decided: settled.txt claims these =="
for report in "${reports[@]}"; do
    agent=$(basename "$report" .md)
    found=0
    while IFS=$'\t' read -r cell row; do
        case $(verdict "$cell") in
        LEAK | FAIL | FRICTION | KNOWN) ;;
        *) continue ;;
        esac
        why=$(settled_why "$row")
        # A KNOWN row the agent classified itself needs no rule to claim it.
        if [ -z "$why" ]; then
            [ "$(verdict "$cell")" = KNOWN ] || continue
            why="the agent recorded it as known"
        fi
        [ "$found" -eq 0 ] && echo "--- $agent ---"
        found=1
        echo "  ${row:0:160}" | redact
        echo "      ^ ${why:0:150}"
    done < <(rows "$report")
done

echo
if [ "$leaked" -gt 0 ]; then
    echo "$leaked canary occurrence(s) reached an agent. These values are worthless"
    echo "by construction, and they are still plaintext in $OUT, which teardown.sh"
    echo "does not reach: delete the reports yourself once you have read them."
    echo "tests/agents/teardown.sh removes the canaries from the store."
    exit 1
fi
echo "No canary value reached an agent."
