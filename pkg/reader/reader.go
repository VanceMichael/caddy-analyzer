package reader

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type LogReader interface {
	Read(ctx context.Context) (<-chan types.SourcedLine, error)
	Name() string
}

// MaxLineSize is the largest log line accepted from any source.
const MaxLineSize = 16 * 1024 * 1024

func FromSource(src types.LogSource) LogReader {
	return fromSource(src, false)
}

func FromSourceFollow(src types.LogSource) LogReader {
	return fromSource(src, true)
}

func fromSource(src types.LogSource, follow bool) LogReader {
	switch src.Type {
	case types.SourceStdin:
		return &StdinReader{}
	case types.SourceDocker:
		return &DockerReader{container: src.Path, follow: follow}
	case types.SourceK8s:
		return &K8sReader{pod: src.Path, namespace: src.Namespace, follow: follow}
	case types.SourceJournalctl:
		return &JournalctlReader{unit: src.Path, follow: follow}
	default:
		return &FileReader{paths: expandPaths(src.Path), follow: follow}
	}
}

func ParseSource(raw string) types.LogSource {
	if raw == "-" {
		return types.LogSource{Type: types.SourceStdin}
	}

	parts := strings.SplitN(raw, "://", 2)
	if len(parts) == 2 {
		switch parts[0] {
		case "docker":
			return types.LogSource{Type: types.SourceDocker, Path: parts[1]}
		case "k8s":
			// Accept both k8s://pod and k8s://namespace/pod. Pod names
			// cannot contain "/", so the first segment is unambiguous.
			pod := parts[1]
			ns := ""
			if idx := strings.Index(pod, "/"); idx >= 0 {
				ns, pod = pod[:idx], pod[idx+1:]
			}
			return types.LogSource{Type: types.SourceK8s, Path: pod, Namespace: ns}
		case "journalctl":
			return types.LogSource{Type: types.SourceJournalctl, Path: parts[1]}
		}
	}

	return types.LogSource{Type: types.SourceFile, Path: raw}
}

func expandPaths(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return []string{pattern}
	}
	return matches
}

// sourceID returns the canonical statistics key for a concrete file path.
func sourceID(path string) string {
	return filepath.Clean(path)
}

func newLineChannel() chan types.SourcedLine {
	return make(chan types.SourcedLine, 1000)
}

// emitLine sends one tagged line, honoring cancellation.
func emitLine(ctx context.Context, out chan<- types.SourcedLine, source, line string) error {
	select {
	case out <- types.SourcedLine{Source: source, Text: line}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type StdinReader struct{}

func (r *StdinReader) Name() string { return "stdin" }

func (r *StdinReader) Read(ctx context.Context) (<-chan types.SourcedLine, error) {
	// Defense-in-depth: resolveSources already refuses the stdin fallback
	// when stdin is a TTY, but a caller can still construct a StdinReader
	// directly (e.g. explicit "-"). Reading from a TTY with bufio.Scanner
	// blocks forever with no prompt, so reject it here with a clear error.
	if isTerminal() {
		return nil, fmt.Errorf("stdin is a terminal; pipe log lines (e.g. `tail -f access.log | caddy-analyze -`) or specify a file/docker://k8s://journalctl:// source")
	}
	out := newLineChannel()
	go func() {
		defer close(out)
		fmt.Fprintln(os.Stderr, "reading log lines from stdin... (Ctrl+D to end)")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), MaxLineSize)
		for scanner.Scan() {
			if err := emitLine(ctx, out, "stdin", scanner.Text()); err != nil {
				return
			}
		}
	}()
	return out, nil
}

type FileReader struct {
	paths  []string
	follow bool
}

func (r *FileReader) Name() string {
	if len(r.paths) == 1 {
		return r.paths[0]
	}
	return fmt.Sprintf("%d files", len(r.paths))
}

func (r *FileReader) Read(ctx context.Context) (<-chan types.SourcedLine, error) {
	out := newLineChannel()
	if r.follow && len(r.paths) > 1 {
		// In follow mode with multiple files, read them concurrently
		// so all files are tailed in parallel. Without this, the first
		// file blocks forever and the rest are never read.
		var wg sync.WaitGroup
		for _, path := range r.paths {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				if err := readFileAndFollow(ctx, p, out); err != nil {
					printReadError(p, err)
				}
			}(path)
		}
		go func() {
			wg.Wait()
			close(out)
		}()
		return out, nil
	}
	go func() {
		defer close(out)
		for _, path := range r.paths {
			if r.follow {
				if err := readFileAndFollow(ctx, path, out); err != nil {
					printReadError(path, err)
				}
			} else {
				if err := readFileLines(ctx, path, out); err != nil {
					printReadError(path, err)
				}
			}
		}
	}()
	return out, nil
}

func readFileLines(ctx context.Context, path string, out chan<- types.SourcedLine) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	source := sourceID(path)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), MaxLineSize)
	for scanner.Scan() {
		if err := emitLine(ctx, out, source, scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func readFileAndFollow(ctx context.Context, path string, out chan<- types.SourcedLine) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	source := sourceID(path)
	initialInfo, err := f.Stat()
	if err != nil {
		return err
	}

	initialReader := bufio.NewReaderSize(f, 1024*1024)
	for {
		line, err := initialReader.ReadString('\n')
		if err != nil {
			if len(line) > 0 {
				pos, _ := f.Seek(0, io.SeekCurrent)
				if _, err := f.Seek(pos-int64(len(line)), io.SeekStart); err != nil {
					return err
				}
			}
			break
		}
		line = strings.TrimRight(line, "\n")
		if err := emitLine(ctx, out, source, line); err != nil {
			return err
		}
	}

	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			if !os.SameFile(initialInfo, info) || info.Size() < pos {
				if err := f.Close(); err != nil {
					return err
				}
				f, err = os.Open(path)
				if err != nil {
					return err
				}
				initialInfo, err = f.Stat()
				if err != nil {
					return err
				}
			} else if info.Size() == pos {
				continue
			}

			reader := bufio.NewReader(f)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if len(line) > 0 {
						pos, _ := f.Seek(0, io.SeekCurrent)
						if _, err := f.Seek(pos-int64(len(line)), io.SeekStart); err != nil {
							return err
						}
					}
					break
				}
				line = strings.TrimRight(line, "\n")
				if err := emitLine(ctx, out, source, line); err != nil {
					return err
				}
			}

			pos, _ = f.Seek(0, io.SeekCurrent)
		}
	}
}

type DockerReader struct {
	container string
	follow    bool
}

func (r *DockerReader) Name() string { return "docker:" + r.container }

// Source returns the canonical source identity for statistics.
func (r *DockerReader) Source() string { return "docker://" + r.container }

func (r *DockerReader) Read(ctx context.Context) (<-chan types.SourcedLine, error) {
	out := newLineChannel()
	args := []string{"logs"}
	if r.follow {
		args = append(args, "-f")
		if !isTerminal() {
			args = append(args, "--tail=all")
		}
	} else {
		args = append(args, "--tail=all")
	}
	args = append(args, r.container)

	cmd := exec.CommandContext(ctx, "docker", args...)
	return execLines(ctx, cmd, r.Source(), out)
}

type K8sReader struct {
	pod       string
	namespace string
	follow    bool
}

func (r *K8sReader) namespaceOrDefault() string {
	if r.namespace == "" {
		return types.DefaultK8sNamespace
	}
	return r.namespace
}

func (r *K8sReader) Name() string {
	return fmt.Sprintf("k8s:%s (ns:%s)", r.pod, r.namespaceOrDefault())
}

// Source returns the canonical source identity (namespace + pod).
func (r *K8sReader) Source() string {
	return fmt.Sprintf("k8s://%s/%s", r.namespaceOrDefault(), r.pod)
}

func (r *K8sReader) Read(ctx context.Context) (<-chan types.SourcedLine, error) {
	out := newLineChannel()
	args := []string{"logs", "--tail=-1"}
	if r.follow {
		args = append(args, "--follow")
	}
	if r.namespace != "" {
		args = append(args, "-n", r.namespace)
	}
	args = append(args, r.pod)

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	return execLines(ctx, cmd, r.Source(), out)
}

type JournalctlReader struct {
	unit   string
	follow bool
}

func (r *JournalctlReader) Name() string { return "journalctl:" + r.unit }

// Source returns the canonical source identity for statistics.
func (r *JournalctlReader) Source() string { return "journalctl://" + r.unit }

func (r *JournalctlReader) Read(ctx context.Context) (<-chan types.SourcedLine, error) {
	out := newLineChannel()
	args := []string{"-u", r.unit, "--output=cat"}
	if r.follow {
		args = append(args, "--follow")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	return execLines(ctx, cmd, r.Source(), out)
}

func execLines(ctx context.Context, cmd *exec.Cmd, source string, out chan types.SourcedLine) (<-chan types.SourcedLine, error) {
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	go func() {
		_ = cmd.Wait()
		_ = pw.Close()
	}()

	go func() {
		defer close(out)
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 64*1024), MaxLineSize)
		for scanner.Scan() {
			if err := emitLine(ctx, out, source, scanner.Text()); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return
			}
		}
	}()

	return out, nil
}

func isTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func printReadError(path string, err error) {
	// Suppress "context canceled" errors — these are normal during graceful shutdown.
	if ctxErr := context.Canceled; errors.Is(err, ctxErr) {
		return
	}
	if os.IsPermission(err) || strings.Contains(err.Error(), "permission denied") {
		fmt.Fprintf(os.Stderr, "error: permission denied reading %s\n", path)
		fmt.Fprintf(os.Stderr, "💡 Hint: Run with sudo: sudo caddy-analyze %s\n", path)
		fmt.Fprintf(os.Stderr, "💡 Or add your user to the caddy group: sudo usermod -aG caddy $USER\n")
	} else {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
	}
}
