package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestUninstallReportsRetainedStateOnFailure(t *testing.T) {
	for _, failure := range []error{nil, errors.Join(errors.New("stop failed"), errors.New("PAM removal failed"))} {
		t.Run(failureName(failure), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			previous := os.Stderr
			os.Stderr = w
			code := reportUninstall([]string{"retained config", "retained log"}, failure)
			os.Stderr = previous
			_ = w.Close()
			out, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			wantCode := 0
			if failure != nil {
				wantCode = 1
				for _, want := range []string{"faramir uninstall:", "stop failed", "PAM removal failed"} {
					if !strings.Contains(string(out), want) {
						t.Errorf("output = %q, want %q", out, want)
					}
				}
			}
			if code != wantCode {
				t.Errorf("exit = %d, want %d", code, wantCode)
			}
			if !strings.HasSuffix(string(out), "kept:\n  retained config\n  retained log\n") {
				t.Errorf("missing retained state: %q", out)
			}
		})
	}
}

func failureName(err error) string {
	if err == nil {
		return "success"
	}
	return "failure"
}
