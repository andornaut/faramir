// Package termuitest builds the two palettes rendering tests assert against.
// Imported only from _test.go files.
//
// One pair rather than a copy per package that prints: an assertion about
// content is made with colour off, and one about escapes with it on, and
// every package that paints makes both kinds.
package termuitest

import (
	"testing"

	"github.com/andornaut/faramir/internal/termui"
)

// Plain is colour off, so the assertions are about content rather than
// escapes.
func Plain(t *testing.T) termui.Palette {
	t.Helper()
	return Palette(t, "never")
}

// Always is colour on whatever stdout is, so the escapes can be asserted.
func Always(t *testing.T) termui.Palette {
	t.Helper()
	return Palette(t, "always")
}

// Palette is the palette --color=when selects, or a fatal test.
func Palette(t *testing.T, when string) termui.Palette {
	t.Helper()
	paint, err := termui.NewPalette(when)
	if err != nil {
		t.Fatal(err)
	}
	return paint
}
