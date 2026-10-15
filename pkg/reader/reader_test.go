package reader

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func readLineTimeout(t *testing.T, ch <-chan types.SourcedLine, timeout time.Duration) (types.SourcedLine, bool) {
	t.Helper()
	select {
	case line, ok := <-ch:
		return line, ok
	case <-time.After(timeout):
		return types.SourcedLine{}, false
	}
}

func TestFileReaderReadsAllLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	r := FromSource(types.LogSource{Type: types.SourceFile, Path: path})
	ctx := context.Background()
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	var got []string
	for line := range lines {
		if line.Source != filepath.Clean(path) {
			t.Errorf("line %q source = %q, want %q", line.Text, line.Source, filepath.Clean(path))
		}
		got = append(got, line.Text)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(got), got)
	}
	if got[0] != "line1" || got[2] != "line3" {
		t.Errorf("unexpected lines: %v", got)
	}
}

func TestFileReaderReadsLargeLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	line := strings.Repeat("x", 2*1024*1024)
	if err := os.WriteFile(path, []byte(line+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	lines, err := FromSource(types.LogSource{Type: types.SourceFile, Path: path}).Read(context.Background())
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	got, ok := <-lines
	if !ok {
		t.Fatal("expected large line")
	}
	if got.Text != line {
		t.Fatalf("large line length = %d, want %d", len(got.Text), len(line))
	}
	if got.Source != filepath.Clean(path) {
		t.Fatalf("large line source = %q, want %q", got.Source, filepath.Clean(path))
	}
}

func TestFileReaderGlobExpansion(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.log")
	pathB := filepath.Join(dir, "b.log")
	if err := os.WriteFile(pathA, []byte("a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte("b\n"), 0644); err != nil {
		t.Fatal(err)
	}

	pattern := filepath.Join(dir, "*.log")
	r := FromSource(types.LogSource{Type: types.SourceFile, Path: pattern})
	ctx := context.Background()
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	bySource := map[string]string{}
	for line := range lines {
		bySource[line.Source] = line.Text
	}
	if bySource[filepath.Clean(pathA)] != "a" || bySource[filepath.Clean(pathB)] != "b" {
		t.Errorf("glob expansion did not attribute lines to concrete files, got %v", bySource)
	}
}

func TestFileReaderFollowAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("line1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := FromSourceFollow(types.LogSource{Type: types.SourceFile, Path: path})
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if line, ok := readLineTimeout(t, lines, 2*time.Second); !ok || line.Text != "line1" || line.Source != filepath.Clean(path) {
		t.Fatalf("expected initial line1 from %s, got %+v ok=%v", filepath.Clean(path), line, ok)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("line2\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if line, ok := readLineTimeout(t, lines, 2*time.Second); !ok || line.Text != "line2" || line.Source != filepath.Clean(path) {
		t.Fatalf("expected appended line2 from %s, got %+v ok=%v", filepath.Clean(path), line, ok)
	}
}

func TestFileReaderFollowRotation(t *testing.T) {
	// Windows cannot rename a file that another handle has open (no
	// FILE_SHARE_DELETE on os.Open), so the rename-while-open rotation
	// pattern used here is Unix-only. The reader still detects truncation
	// (size < pos) and replacement on all platforms.
	if runtime.GOOS == "windows" {
		t.Skip("rename of an open file is not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("old1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := FromSourceFollow(types.LogSource{Type: types.SourceFile, Path: path})
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if line, ok := readLineTimeout(t, lines, 2*time.Second); !ok || line.Text != "old1" {
		t.Fatalf("expected old1, got %+v ok=%v", line, ok)
	}

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new1\nnew2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"new1", "new2"} {
		line, ok := readLineTimeout(t, lines, 3*time.Second)
		if !ok || line.Text != want || line.Source != filepath.Clean(path) {
			t.Fatalf("expected %s after rotation, got %+v ok=%v", want, line, ok)
		}
	}
}

func TestParseSourceSchemes(t *testing.T) {
	tests := []struct {
		raw       string
		want      types.LogSource
		canonical string
	}{
		{"-", types.LogSource{Type: types.SourceStdin}, "stdin"},
		{"/var/log/caddy/access.log", types.LogSource{Type: types.SourceFile, Path: "/var/log/caddy/access.log"}, "/var/log/caddy/access.log"},
		{"docker://my-caddy", types.LogSource{Type: types.SourceDocker, Path: "my-caddy"}, "docker://my-caddy"},
		{"k8s://my-pod", types.LogSource{Type: types.SourceK8s, Path: "my-pod"}, "k8s://default/my-pod"},
		{"k8s://kube-system/coredns-abc", types.LogSource{Type: types.SourceK8s, Namespace: "kube-system", Path: "coredns-abc"}, "k8s://kube-system/coredns-abc"},
		{"journalctl://caddy", types.LogSource{Type: types.SourceJournalctl, Path: "caddy"}, "journalctl://caddy"},
	}
	for _, tt := range tests {
		got := ParseSource(tt.raw)
		if got.Type != tt.want.Type || got.Path != tt.want.Path || got.Namespace != tt.want.Namespace {
			t.Errorf("ParseSource(%q) = %+v, want %+v", tt.raw, got, tt.want)
		}
		if got.Canonical() != tt.canonical {
			t.Errorf("Canonical(%q) = %q, want %q", tt.raw, got.Canonical(), tt.canonical)
		}
	}
}

func TestStdinReaderName(t *testing.T) {
	r := &StdinReader{}
	if !strings.Contains(r.Name(), "stdin") {
		t.Errorf("unexpected name %q", r.Name())
	}
}
