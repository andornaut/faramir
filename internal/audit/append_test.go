package audit

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/config"
)

func writeRecord(t *testing.T, l *Log, record map[string]any, output Output) {
	t.Helper()
	if err := l.Write(record, output); err != nil {
		t.Errorf("Write: %v", err)
	}
}

func TestWriteReturnsOpenFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLog(config.AuditConfig{LogPath: filepath.Join(blocker, "audit.log")})
	if err := l.Write(map[string]any{"op": "run_started"}, Output{}); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("Write error = %v, want ENOTDIR", err)
	}
}

func TestAppendLineReturnsFileFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readonly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readonly.Close() })
	closed, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	for _, tc := range []struct {
		name  string
		file  *os.File
		want  error
		stage string
	}{
		{"lock", closed, syscall.EBADF, "cannot lock"},
		{"seek", writer, syscall.ESPIPE, "cannot measure"},
		{"write", readonly, syscall.EBADF, "cannot append"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := appendLine(tc.file, []byte("next\n"), path)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.stage) {
				t.Fatalf("appendLine error = %v, want %s: %v", err, tc.stage, tc.want)
			}
		})
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing\n" {
		t.Fatalf("existing log = %q, %v", data, err)
	}
}

func TestAppendLineRollsBackPartialWrite(t *testing.T) {
	const helper = "FARAMIR_TEST_AUDIT_PARTIAL_WRITE"
	if os.Getenv(helper) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestAppendLineRollsBackPartialWrite$")
		cmd.Env = append(os.Environ(), helper+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("partial-write subprocess: %v\n%s", err, output)
		}
		return
	}

	path := filepath.Join(t.TempDir(), "audit.log")
	const prefix = "existing\n"
	if err := os.WriteFile(path, []byte(prefix), 0o600); err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fh.Close() })
	// Limit only this subprocess, allowing part of the next line to land.
	signal.Ignore(syscall.SIGXFSZ)
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
			t.Errorf("restore file-size limit: %v", err)
		}
	})
	limited := original
	limited.Cur = uint64(len(prefix) + 4)
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatal(err)
	}
	if err := appendLine(fh, []byte("a record exceeding the file limit\n"), path); !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("partial append error = %v, want EFBIG", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != prefix {
		t.Fatalf("log after rollback = %q, %v; want %q", data, err, prefix)
	}
	l := NewLog(config.AuditConfig{LogPath: path})
	if err := l.Write(map[string]any{"op": "run_started"}, Output{}); !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("Write error = %v, want EFBIG", err)
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != prefix {
		t.Fatalf("log after Write rollback = %q, %v; want %q", data, err, prefix)
	}
}
