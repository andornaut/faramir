// Package auditview reads the broker's audit log and renders a record for a
// person.
//
// Reading it is not just decoding JSON. The log is appended to while it is being
// read and rotated out from under a reader, so following it means noticing that
// the file it holds open is no longer the file at the path; and a record may be
// truncated mid-write, so a line that does not parse is counted rather than
// fatal.
//
// Rendering it is not just printing fields. Every value in a record came from
// somewhere else -- a command line, a peer's name, a path -- and a terminal
// obeys what it is sent, so what reaches one goes through internal/termui
// first. The «SECRET:ref» markers are the exception worth painting: they say
// where a credential was used without being one.
package auditview

import (
	"fmt"

	"github.com/andornaut/faramir/internal/termui"
)

// Printer is the listing's rows and the date header above the first row of
// each day. The day it last printed is state, so a watcher left running prints
// a new header when the day turns under it.
type Printer struct {
	Paint termui.Palette
	day   string
}

func (p *Printer) Row(record map[string]any) {
	if at := StartedAt(record); !at.IsZero() && at.Format(dateLayout) != p.day {
		p.day = at.Format(dateLayout)
		fmt.Println(p.Paint.Dim(p.day))
	}
	fmt.Println(Summarise(record, p.Paint))
}
