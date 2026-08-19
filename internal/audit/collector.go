package audit

// The streaming half of bounding a record: what holds a run's output while it
// is still being written.

import (
	"strings"
)

// Collector accumulates the redacted stream for one invocation, keeping the head
// and the tail and counting what it drops between them.
//
// Bounded as it goes rather than at the end: a run that prints for an hour is
// held in the broker's memory while it does, and the record is the same size
// whether the command wrote a kilobyte or a gigabyte.
type Collector struct {
	budget  int
	head    strings.Builder
	headLen int // encoded, so the budget means the same here as in the record
	// headShut is set by the first chunk that goes to the tail. Without it the
	// head keeps taking whatever still fits, so a chunk too large for the room
	// left goes to the tail and a smaller one after it lands in the head, ahead of
	// it: the record then shows a run's own output out of the order it was
	// written, which is worse than showing less of it.
	headShut bool
	tail     []string
	tailLen  int
	dropped  int
}

func NewCollector(budget int) *Collector {
	return &Collector{budget: max(budget, minOutputBudget)}
}

func (c *Collector) half() int { return halfBudget(c.budget) }

func (c *Collector) Add(text string) {
	if text == "" {
		return
	}
	// Fill the head first, then treat everything after it as tail, dropping from
	// the front of the tail as it overflows. A ring of chunks rather than of
	// bytes: chunks arrive small, and the one that overshoots is trimmed once.
	if !c.headShut && c.headLen < c.half() {
		keep := prefixWithin(text, c.half()-c.headLen)
		if keep != "" {
			c.head.WriteString(keep)
			c.headLen += encodedLen(keep)
			text = text[len(keep):]
		}
		if text == "" {
			return
		}
	}
	// Whatever did not fit the head ends it: from here the record is written in
	// the order the run wrote it, or it is not worth reading.
	c.headShut = true
	c.tail = append(c.tail, text)
	c.tailLen += encodedLen(text)
	for c.tailLen > c.half() && len(c.tail) > 1 {
		c.dropped += len(c.tail[0])
		c.tailLen -= encodedLen(c.tail[0])
		c.tail = c.tail[1:]
	}
	// One chunk longer than the whole tail budget: keep its own tail.
	if c.tailLen > c.half() {
		keep := suffixWithin(c.tail[0], c.half())
		c.dropped += len(c.tail[0]) - len(keep)
		c.tail[0] = keep
		c.tailLen = encodedLen(keep)
	}
}

// Output is what was kept and how much was not.
func (c *Collector) Output() Output {
	head, tail := c.head.String(), strings.Join(c.tail, "")
	if c.dropped == 0 {
		return Output{Text: head + tail}
	}
	return Output{Text: head + marker(c.dropped) + tail, Dropped: c.dropped}
}
