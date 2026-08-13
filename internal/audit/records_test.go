package audit

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The terminal reduction exists for a record whose field set is too large, and a
// record's fields are named in the code and never by a caller, so this asks the
// question of the tree itself: every record literal is found here rather than
// listed here, a list being the same thing it guards against, something a person
// has to remember to update.
//
// It asserts that [config.MinRecordBytes], the smallest cap an operator can set,
// is larger than the widest record needs.  Add a field anywhere and this
// recomputes; if the floor no longer covers it, the failure says by how much.

// recordShapes is every map[string]any literal in the tree that carries a
// log_id, which is what makes a literal a record: the audit log is the only
// thing that field is for.
func recordShapes(t *testing.T) map[string][]string {
	t.Helper()
	root := repoRoot(t)
	shapes := map[string][]string{}
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		switch {
		case err != nil:
			return err
		case info.IsDir():
			// The module's own source only.  Anything vendored or checked out under
			// the tree is somebody else's records.
			if name := info.Name(); name == ".git" || name == "vendor" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		case !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go"):
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok || !isMapStringAny(lit.Type) {
				return true
			}
			keys := literalKeys(lit)
			if len(keys) == 0 || !contains(keys, "log_id") {
				return true
			}
			where := fset.Position(lit.Pos())
			rel, _ := filepath.Rel(root, where.Filename)
			shapes[rel+":"+strconv.Itoa(where.Line)] = keys
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return shapes
}

func isMapStringAny(expr ast.Expr) bool {
	mapType, ok := expr.(*ast.MapType)
	if !ok {
		return false
	}
	key, ok := mapType.Key.(*ast.Ident)
	if !ok || key.Name != "string" {
		return false
	}
	value, ok := mapType.Value.(*ast.Ident)
	return ok && (value.Name == "any" || value.Name == "interface{}")
}

func literalKeys(lit *ast.CompositeLit) []string {
	var keys []string
	for _, element := range lit.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return nil
		}
		name, ok := pair.Key.(*ast.BasicLit)
		if !ok || name.Kind != token.STRING {
			return nil
		}
		text, err := strconv.Unquote(name.Value)
		if err != nil {
			return nil
		}
		keys = append(keys, text)
	}
	return keys
}

func contains(haystack []string, needle string) bool {
	for _, straw := range haystack {
		if straw == needle {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("cannot find the module root from %s: %v", dir, err)
	}
	return dir
}

// The number of record literals below which this test is not looking at the
// records any more.  A refactor that builds a record some other way (a struct, a
// helper, a map assembled key by key) takes it out of this test's sight, and a
// guard that has stopped looking must say so rather than pass.
const knownRecordShapes = 10

func TestEveryRecordThisTreeWritesFitsTheSmallestCap(t *testing.T) {
	shapes := recordShapes(t)
	if len(shapes) < knownRecordShapes {
		t.Fatalf("found %d record literals, expected at least %d: records are being "+
			"built in a way this no longer sees, so it is not checking them",
			len(shapes), knownRecordShapes)
	}

	for where, keys := range shapes {
		t.Run(where, func(t *testing.T) {
			// Every field as large as reduction will ever have to make it, so what is
			// measured is the field *count* rather than one run's values.
			record := map[string]any{}
			for _, key := range keys {
				record[key] = strings.Repeat("<", 4096)
			}
			// audit.Write adds its own, and they count too.
			path := filepath.Join(t.TempDir(), "audit.log")
			NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: config.MinRecordBytes}).
				Write(record, Output{Text: strings.Repeat("x", 100_000), Dropped: 900_000})

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > config.MinRecordBytes {
				t.Fatalf("%d bytes for a floor of %d", len(data), config.MinRecordBytes)
			}
			for _, key := range keys {
				if !strings.Contains(string(data), strconv.Quote(key)+":") {
					t.Errorf("%q is missing: this record has %d fields and no longer fits "+
						"[audit] max_record_bytes at its floor of %d, so a host set that low "+
						"records identities in place of records. Raise config.MinRecordBytes",
						key, len(keys), config.MinRecordBytes)
				}
			}
		})
	}
}

// What config.MinRecordBytes buys, reported rather than asserted.
//
// The floor is not sized by what a record's fields need, which survive far below
// it, cut down to nothing much.  It is sized by the smallest cap at which
// an ordinary record is written *normally*: not reduced, and with enough of the
// command's output left to be worth reading.  Those are different numbers and
// the first one is the misleading one, so this reports both.
func TestReportWhatTheFloorBuys(t *testing.T) {
	// It writes below the cap that fits, on purpose: that is the boundary it is
	// looking for.
	defer unstrict()()

	widest, widestAt := 0, ""
	for where, keys := range recordShapes(t) {
		if len(keys) > widest {
			widest, widestAt = len(keys), where
		}
	}

	// A record of the widest shape, with a run's worth of output behind it.
	record := func() map[string]any {
		out := map[string]any{}
		for i := range widest - 1 {
			out["field_"+strconv.Itoa(i)] = "an ordinary value"
		}
		out["log_id"] = "2026-08-11T06:00:00Z-abcd000001"
		return out
	}
	output := Output{Text: strings.Repeat("ok: [host.example.com]\n", 100_000)}

	fieldsSurviveAt, normalAt, keptAtFloor := 0, 0, 0
	for cap := 256; cap <= 16*config.MinRecordBytes; cap += 64 {
		path := filepath.Join(t.TempDir(), "audit.log")
		NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: cap}).Write(record(), output)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if fieldsSurviveAt == 0 && strings.Count(string(data), "field_") == widest-1 {
			fieldsSurviveAt = cap
		}
		if normalAt == 0 && got["record_reduced"] != true {
			normalAt = cap
		}
		if cap >= config.MinRecordBytes && keptAtFloor == 0 {
			kept, _ := got["output"].(string)
			keptAtFloor = len(kept)
		}
		if fieldsSurviveAt > 0 && normalAt > 0 && keptAtFloor > 0 {
			break
		}
	}
	t.Logf("widest record: %d fields at %s", widest, widestAt)
	t.Logf("its fields survive from a cap of %d, which is not the number to judge "+
		"the floor by: everything is cut to nothing much down there", fieldsSurviveAt)
	t.Logf("it is written unreduced from a cap of %d, and config.MinRecordBytes is %d",
		normalAt, config.MinRecordBytes)
	t.Logf("at the floor a record keeps %d bytes of a command's output", keptAtFloor)
	if normalAt > config.MinRecordBytes {
		t.Errorf("an ordinary record is reduced at the floor: raise config.MinRecordBytes "+
			"to at least %d", normalAt)
	}
}
