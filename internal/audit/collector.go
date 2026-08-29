package audit

// The streaming half of bounding a record: what holds a run's output while it
// is still being written.

import (
	"strings"
)

// Measure prices text in the unit a budget is counted in and cuts one chunk to
// fit it. The record cap is counted in encoded bytes and the executor's
// response cap in raw ones; the head-and-tail ring between them is the same.
type Measure interface {
	Len(s string) int
	Prefix(s string, budget int) string
	Suffix(s string, budget int) string
}

// Encoded prices what json.Marshal will spend; Raw, what the bytes are.
var (
	Encoded Measure = encodedMeasure{}
	Raw     Measure = rawMeasure{}
)

type encodedMeasure struct{}

func (encodedMeasure) Len(s string) int                   { return encodedLen(s) }
func (encodedMeasure) Prefix(s string, budget int) string { return prefixWithin(s, budget) }
func (encodedMeasure) Suffix(s string, budget int) string { return suffixWithin(s, budget) }

type rawMeasure struct{}

func (rawMeasure) Len(s string) int                   { return len(s) }
func (rawMeasure) Prefix(s string, budget int) string { return cutAtRune(s, budget) }
func (rawMeasure) Suffix(s string, budget int) string { return tailAtRune(s, budget) }

// Bounded keeps the head and the tail of a stream within a budget, counting
// what it drops between them in raw bytes whatever the Measure prices the
// budget in.
//
// Bounded as it goes rather than at the end: a run that prints for an hour is
// held in the broker's memory while it does, and what is kept is the same size
// whether the command wrote a kilobyte or a gigabyte.
type Bounded struct {
	budget  int
	m       Measure
	head    strings.Builder
	headLen int // in the Measure's unit, so the budget means one thing throughout
	// headShut is set by the first chunk that goes to the tail. Without it the
	// head keeps taking whatever still fits, so a chunk too large for the room
	// left goes to the tail and a smaller one after it lands in the head, ahead of
	// it: the output then reads out of the order the command wrote it, which is
	// worse than reading less of it.
	headShut bool
	tail     []string
	tailLen  int
	dropped  int
}

func NewBounded(budget int, m Measure) *Bounded {
	return &Bounded{budget: budget, m: m}
}

func (b *Bounded) half() int { return halfBudget(b.budget) }

func (b *Bounded) Add(text string) {
	if text == "" {
		return
	}
	// Fill the head first, then treat everything after it as tail, dropping from
	// the front of the tail as it overflows. A ring of chunks rather than of
	// bytes: chunks arrive small, and the one that overshoots is trimmed once.
	if !b.headShut && b.headLen < b.half() {
		keep := b.m.Prefix(text, b.half()-b.headLen)
		if keep != "" {
			b.head.WriteString(keep)
			b.headLen += b.m.Len(keep)
			text = text[len(keep):]
		}
		if text == "" {
			return
		}
	}
	// Whatever did not fit the head ends it: from here the output is kept in
	// the order the run wrote it, or it is not worth reading.
	b.headShut = true
	b.tail = append(b.tail, text)
	b.tailLen += b.m.Len(text)
	for b.tailLen > b.half() && len(b.tail) > 1 {
		b.dropped += len(b.tail[0])
		b.tailLen -= b.m.Len(b.tail[0])
		b.tail = b.tail[1:]
	}
	// One chunk longer than the whole tail budget: keep its own tail.
	if b.tailLen > b.half() {
		keep := b.m.Suffix(b.tail[0], b.half())
		b.dropped += len(b.tail[0]) - len(keep)
		b.tail[0] = keep
		b.tailLen = b.m.Len(keep)
	}
}

// Result is what was kept, the marker between the two ends where anything was
// not, and how many raw bytes were dropped. The marker must fit the reserve
// halfBudget leaves for it.
func (b *Bounded) Result(marker func(dropped int) string) (string, int) {
	head, tail := b.head.String(), strings.Join(b.tail, "")
	if b.dropped == 0 {
		return head + tail, 0
	}
	return head + marker(b.dropped) + tail, b.dropped
}

// Collector accumulates the redacted stream for one invocation, bounded in
// the encoded bytes a record is written in.
type Collector struct {
	Bounded
}

func NewCollector(budget int) *Collector {
	return &Collector{Bounded{budget: max(budget, minOutputBudget), m: Encoded}}
}

// Output is what was kept and how much was not.
func (c *Collector) Output() Output {
	text, dropped := c.Result(marker)
	return Output{Text: text, Dropped: dropped}
}
