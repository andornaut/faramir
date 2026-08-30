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
# in any report that discusses the suite; what only a leak produces is the
# prefix with a ref name and the random tail behind it.
VALUE='CANARYLEAK-(plain|shell|unicode|multiline)-[0-9a-f]{6}'

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
    n=$(grep -coE "$VALUE" "$f")
    [ "$n" -eq 0 ] && continue
    leaked=$((leaked + n))
    # The count and the ref, never the value: this output is read in a terminal
    # and pasted into issues, and a leak report that leaks is no use to anybody.
    refs=$(grep -oE "$VALUE" "$f" | sed -E 's/-[0-9a-f]{6}$//' | sort -u | tr '\n' ' ')
    printf '  %-14s %d occurrence(s) of %s\n' "$(basename "$f")" "$n" "$refs"
done
if [ "$leaked" -eq 0 ]; then
    echo "  none: no canary value appears in any report or transcript"
fi

# verdict is the first result word in a row's last cell, so "FAIL (consequence
# of #1)" counts as a FAIL and "PASS (pattern only)" as a PASS. Ordered with the
# bad news first for that reason.
verdict() {
    local cell=${1^^}
    for v in LEAK FAIL FRICTION KNOWN SKIP PASS; do
        case $cell in
        *"$v"*)
            echo "$v"
            return
            ;;
        esac
    done
}

# rows prints one "verdict<TAB>row" line per results-table row, skipping the
# header and the separator. A row is a line that opens with a pipe and holds
# enough cells to have a result in the last one.
rows() {
    awk -F'|' '
        /^[[:space:]]*\|/ && NF >= 4 {
            last = $(NF - 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", last)
            gsub(/[*`]/, "", last)
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
printf '%-10s %5s %5s %5s %5s %5s %5s %5s  %s\n' \
    agent pass fail leak frict known skip total state
for report in "${reports[@]}"; do
    agent=$(basename "$report" .md)
    log=$OUT/$agent.log
    declare -A n=([PASS]=0 [FAIL]=0 [LEAK]=0 [FRICTION]=0 [KNOWN]=0 [SKIP]=0)
    total=0
    while IFS=$'\t' read -r cell _; do
        v=$(verdict "$cell")
        [ -z "$v" ] && continue
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
            elif [ ! -s "$log" ]; then
                state="no output"
            fi
        fi
    fi
    printf '%-10s %5d %5d %5d %5d %5d %5d %5d  %s\n' \
        "$agent" "${n[PASS]}" "${n[FAIL]}" "${n[LEAK]}" \
        "${n[FRICTION]}" "${n[KNOWN]}" "${n[SKIP]}" "$total" "$state"
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
        *) continue ;;
        esac
        [ -n "$(settled_why "$row")" ] && continue
        [ "$found" -eq 0 ] && echo "--- $agent ---"
        found=1
        newrows=$((newrows + 1))
        echo "  ${row:0:200}"
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
        echo "  ${row:0:160}"
        echo "      ^ ${why:0:150}"
    done < <(rows "$report")
done

echo
if [ "$leaked" -gt 0 ]; then
    echo "$leaked canary occurrence(s) reached an agent. Read the rows above, then"
    echo "run tests/agents/teardown.sh: these values are worthless by construction,"
    echo "but they are still plaintext on this host."
    exit 1
fi
echo "No canary value reached an agent."
