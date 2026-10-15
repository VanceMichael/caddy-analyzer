package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// TestFanInFollowMultipleSources verifies the multi-source fan-in: lines from
// ALL sources must be delivered, not just the first one. This is the regression
// test for the bug where runFollowMode/runTail iterated sources sequentially
// and blocked forever on the first follow reader (which only closes on
// ctx.Done), silently dropping every subsequent source.
//
// Every delivered line must also carry the canonical identity of the concrete
// file it came from: after fan-in, attribution must survive intact.
func TestFanInFollowMultipleSources(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.log")
	f2 := filepath.Join(dir, "b.log")
	if err := os.WriteFile(f1, []byte("a1\na2\na3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("b1\nb2\nb3\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sources := []types.LogSource{
		{Type: types.SourceFile, Path: f1},
		{Type: types.SourceFile, Path: f2},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := fanInFollow(ctx, sources)

	// Collect until we have all 6 lines or time out. Follow readers deliver
	// existing content first, so all 6 should arrive quickly.
	bySource := map[string]map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(bySource[filepath.Clean(f1)])+len(bySource[filepath.Clean(f2)]) < 6 {
		select {
		case line, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed before collecting all lines; got %v", bySource)
			}
			if bySource[line.Source] == nil {
				bySource[line.Source] = map[string]bool{}
			}
			if line.Source != filepath.Clean(f1) && line.Source != filepath.Clean(f2) {
				t.Errorf("line %q has unexpected source %q", line.Text, line.Source)
			}
			bySource[line.Source][line.Text] = true
		case <-deadline:
			t.Fatalf("timeout: collected %v", bySource)
		}
	}

	// Cancel and confirm the merged channel closes.
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed after context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("channel did not close after context cancellation")
	}

	// The fix's whole point: lines from BOTH sources must be present with
	// the right source label on every line.
	for text, wantSource := range map[string]string{
		"a1": filepath.Clean(f1), "a2": filepath.Clean(f1), "a3": filepath.Clean(f1),
		"b1": filepath.Clean(f2), "b2": filepath.Clean(f2), "b3": filepath.Clean(f2),
	} {
		if !bySource[wantSource][text] {
			t.Errorf("missing or mislabeled line %q (want source %s); got %v", text, wantSource, bySource)
		}
	}
}

// TestFanInFollowBadSourceSkipped ensures a failing source does not abort the
// fan-in: remaining sources must still be delivered with their own identity.
func TestFanInFollowBadSourceSkipped(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.log")
	if err := os.WriteFile(good, []byte("g1\ng2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sources := []types.LogSource{
		{Type: types.SourceFile, Path: filepath.Join(dir, "does-not-exist.log")},
		{Type: types.SourceFile, Path: good},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := fanInFollow(ctx, sources)

	got := make(map[string]bool)
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case line, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed early; got %v", got)
			}
			if line.Source != filepath.Clean(good) {
				t.Errorf("line %q source = %q, want %q", line.Text, line.Source, filepath.Clean(good))
			}
			got[line.Text] = true
		case <-deadline:
			t.Fatalf("timeout: got %v", got)
		}
	}

	if !got["g1"] || !got["g2"] {
		t.Errorf("expected g1 and g2 from the good source; got %v", got)
	}
}

type errorFollowReader struct{}

func (errorFollowReader) Name() string { return "broken" }

func (errorFollowReader) Read(context.Context) (<-chan types.SourcedLine, error) {
	return nil, os.ErrNotExist
}

var _ reader.LogReader = errorFollowReader{}

func TestFanInFollowErrorPolicyStopsAndCleansUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := fanInFollowReaders(ctx, []reader.LogReader{errorFollowReader{}}, func(name string, err error) error {
		if name != "broken" {
			t.Errorf("unexpected reader name %q", name)
		}
		return err
	})
	if err == nil {
		t.Fatal("expected source error")
	}
}
