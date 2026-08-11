package audit

import (
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
// record's fields are named in the code and never by a caller.  So the question
// "are there too many of them?" is one this repository can answer about itself,
// and it answers it by reading itself: every record literal in the tree is found
// here, not listed here.
//
// A list would be the same failure it is meant to catch -- something a person
// has to remember to update -- and the thing being guarded is exactly what
// happens when nobody does.
//
// What it asserts is that [config.MinRecordBytes], the smallest cap an operator
// can set, is larger than the widest record needs.  Add a field anywhere and
// this recomputes; if the floor no longer covers it, the failure says by how
// much.

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
// records any more.  A refactor that builds a record some other way -- a struct,
// a helper, a map assembled key by key -- takes it out of this test's sight, and
// a guard that has stopped looking must say so rather than pass.
const knownRecordShapes = 8

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

// What the floor would have to be for the widest record in the tree, reported
// rather than asserted: it is the number to raise config.MinRecordBytes to when
// the test above starts failing, and it is worth seeing before it does.
func TestReportTheFloorTheWidestRecordNeeds(t *testing.T) {
	widest, widestAt := 0, ""
	for where, keys := range recordShapes(t) {
		if len(keys) > widest {
			widest, widestAt = len(keys), where
		}
	}
	// Bisect on the cap: the smallest one at which the widest record still comes
	// out whole.
	record := map[string]any{}
	for i := range widest {
		record["field_"+strconv.Itoa(i)] = strings.Repeat("<", 4096)
	}
	needed := config.MinRecordBytes
	for cap := 256; cap <= config.MinRecordBytes; cap += 64 {
		path := filepath.Join(t.TempDir(), "audit.log")
		fresh := map[string]any{}
		for key, value := range record {
			fresh[key] = value
		}
		NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: cap}).Write(fresh, Output{})
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), "field_") == widest {
			needed = cap
			break
		}
	}
	t.Logf("widest record: %d fields at %s; it fits from a cap of %d, and the floor is %d (%.1fx)",
		widest, widestAt, needed, config.MinRecordBytes, float64(config.MinRecordBytes)/float64(needed))
}
