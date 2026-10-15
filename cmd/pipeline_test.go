package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestProcessParsedLinesPreservesInputOrder(t *testing.T) {
	lines := make(chan types.SourcedLine, 3)
	lines <- types.SourcedLine{Source: "stdin", Text: `{"level":"info","ts":1,"msg":"first"}`}
	lines <- types.SourcedLine{Source: "stdin", Text: `{"level":"info","ts":2,"msg":"second"}`}
	lines <- types.SourcedLine{Source: "stdin", Text: `{"level":"info","ts":3,"msg":"third"}`}
	close(lines)

	var got []string
	processParsedLines(context.Background(), lines, 4, func(source string, entry types.Entry, err error) {
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if source != "stdin" {
			t.Errorf("source = %q, want stdin", source)
		}
		op, ok := entry.(*types.OperationalEntry)
		if !ok {
			t.Fatalf("entry type = %T, want operational entry", entry)
		}
		if op.Source != "stdin" {
			t.Errorf("tagged entry source = %q, want stdin", op.Source)
		}
		got = append(got, op.Msg)
	})

	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestProcessParsedLinesKeepsSourceLabels mixes two sources with parse
// failures and verifies every result (including errors) is attributed to the
// source of its own line while global input order is preserved.
func TestProcessParsedLinesKeepsSourceLabels(t *testing.T) {
	lines := make(chan types.SourcedLine, 6)
	lines <- types.SourcedLine{Source: "a.log", Text: `{"level":"info","ts":1,"msg":"a1"}`}
	lines <- types.SourcedLine{Source: "b.log", Text: "not json"}
	lines <- types.SourcedLine{Source: "b.log", Text: `{"level":"info","ts":2,"msg":"b2"}`}
	lines <- types.SourcedLine{Source: "a.log", Text: "garbage"}
	close(lines)

	type result struct {
		source string
		msg    string
		err    bool
	}
	var got []result
	processParsedLines(context.Background(), lines, 4, func(source string, entry types.Entry, err error) {
		r := result{source: source, err: err != nil}
		if op, ok := entry.(*types.OperationalEntry); ok {
			r.msg = op.Msg
			if op.Source != source {
				t.Errorf("entry label %q != callback source %q", op.Source, source)
			}
		}
		got = append(got, r)
	})

	want := []result{
		{source: "a.log", msg: "a1"},
		{source: "b.log", err: true},
		{source: "b.log", msg: "b2"},
		{source: "a.log", err: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCountTotalLinesForLocalSources(t *testing.T) {
	path := t.TempDir() + "/access.log"
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := countTotalLines([]types.LogSource{{Type: types.SourceFile, Path: path}})
	if got != 3 {
		t.Fatalf("countTotalLines() = %d, want 3", got)
	}
}
