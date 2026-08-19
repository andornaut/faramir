package secretlink

import (
	"strings"
	"testing"
)

// A credential need not be a string in the file that holds it: a PIN, an
// account number or a port written without quotes decodes to a number, and each
// decoder has a number type of its own. All of them come back as the text the
// file spelled, which is what gets injected and what the redactor is given.
func TestANumericValueIsReadAsTheTextItWasWritten(t *testing.T) {
	for _, tc := range []struct{ kind, body, want string }{
		{KindJSON, `{"pin": 90210}`, "90210"},
		{KindYAML, "pin: 90210\n", "90210"},
		{KindTOML, "pin = 90210\n", "90210"},
		{KindINI, "pin = 90210\n", "90210"},
		{KindJSON, `{"pin": 1.5}`, "1.5"},
		{KindYAML, "pin: 1.5\n", "1.5"},
		{KindTOML, "pin = 1.5\n", "1.5"},
	} {
		t.Run(tc.kind+" "+tc.want, func(t *testing.T) {
			got, err := Extract(tc.kind, "pin", []byte(tc.body))
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// What is never a credential is refused rather than injected: a null is a key
// the tool has not written yet, and an empty string is one it cleared. Either
// injected would put nothing where a secret was expected, and a value set
// holding "" would match everywhere.
func TestAValueThatIsNotThereIsRefusedRatherThanInjected(t *testing.T) {
	for _, tc := range []struct{ kind, body, wantErr string }{
		{KindJSON, `{"token": null}`, "is null"},
		{KindYAML, "token:\n", "is null"},
		{KindJSON, `{"token": ""}`, "is empty"},
		{KindYAML, "token: \"\"\n", "is empty"},
		{KindTOML, "token = \"\"\n", "is empty"},
		{KindINI, "token =\n", "is empty"},
	} {
		t.Run(tc.kind+" "+tc.wantErr, func(t *testing.T) {
			got, err := Extract(tc.kind, "token", []byte(tc.body))
			if err == nil {
				t.Fatalf("got %q, want an error containing %q", got, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// A file whose top level is not a table selects nothing, and the error names
// the file rather than an empty prefix: there is no parent to name, the first
// segment being the one that ran out. It carries nothing of the contents, as
// every error here does.
func TestASelectorAgainstATopLevelScalarNamesTheFile(t *testing.T) {
	_, err := Extract(KindJSON, "token", []byte(`"a-long-secret-value"`))
	if err == nil {
		t.Fatal("a walk into a file that is one scalar was accepted")
	}
	if !strings.Contains(err.Error(), "the file") {
		t.Errorf("err = %v, want it to name the file as the parent", err)
	}
	if strings.Contains(err.Error(), "a-long-secret-value") {
		t.Errorf("the error carries the value: %v", err)
	}
}

// Only "/" and the escape itself are special in a selector, so a backslash
// before anything else is the character it is. A key holding one is written by
// tools that never expected to be selected out of, and an operator copying its
// name out of the file has to be able to paste it as it stands.
func TestABackslashBeforeAnOrdinaryCharacterIsLiteral(t *testing.T) {
	data := []byte(`{"back\\slash": "a-long-secret-value"}`)
	for _, key := range []string{`back\slash`, `back\\slash`} {
		got, err := Extract(KindJSON, key, data)
		if err != nil {
			t.Errorf("Extract(%q): %v", key, err)
			continue
		}
		if got != "a-long-secret-value" {
			t.Errorf("Extract(%q) = %q", key, got)
		}
	}
	// And the separator still separates, so the escape is not a way to spell one
	// away by accident.
	if _, err := Extract(KindJSON, `back/slash`, data); err == nil {
		t.Error("an unescaped slash selected a key that holds a backslash")
	}
}

// An INI file that is not text is refused rather than scanned: the line split
// would run over whatever the bytes happen to be, and the entry it matched
// would be a substring of binary.
func TestAnINIFileThatIsNotTextIsRefused(t *testing.T) {
	_, err := Extract(KindINI, "token", []byte("token = \xff\xfe\n"))
	if err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("err = %v, want a refusal naming the encoding", err)
	}
}
