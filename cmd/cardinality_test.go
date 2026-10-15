package cmd

import (
	"strconv"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// TestNewWindowEnginesCardinality is the cmd-level guard for the invariant
// that every analysis window builds both engines with the global
// --max-cardinality configuration: once/follow/interval/top/watch and every
// reset create engines through newWindowEngines.
func TestNewWindowEnginesCardinality(t *testing.T) {
	origCard, origDetect := flagMaxCard, flagDetect
	defer func() { flagMaxCard, flagDetect = origCard, origDetect }()
	flagDetect = false

	flagMaxCard = 2
	eng, opEng := newWindowEngines(types.Filters{})
	if eng.Stats().MaxCardinality != 2 {
		t.Errorf("HTTP engine MaxCardinality = %d, want 2", eng.Stats().MaxCardinality)
	}
	if opEng.Stats().MaxCardinality != 2 {
		t.Errorf("operational engine MaxCardinality = %d, want 2", opEng.Stats().MaxCardinality)
	}

	for i, p := range []string{"/a", "/b", "/c"} {
		eng.Process(&types.LogEntry{URI: p, Status: 200, Size: int64(10 + i)})
	}
	for i := 0; i < 3; i++ {
		opEng.Process(&types.OperationalEntry{Level: "info", Logger: "tls", Msg: "msg-" + strconv.Itoa(i)})
	}
	if len(eng.Stats().PathCounts) != 2 {
		t.Errorf("HTTP PathCounts = %d keys, want 2", len(eng.Stats().PathCounts))
	}
	if len(opEng.Stats().MsgCounts) != 2 {
		t.Errorf("operational MsgCounts = %d keys, want 2", len(opEng.Stats().MsgCounts))
	}
	if eng.Stats().TotalRequests != 3 || opEng.Stats().TotalEvents != 3 {
		t.Errorf("global totals must stay exact: http=%d ops=%d", eng.Stats().TotalRequests, opEng.Stats().TotalEvents)
	}

	// Simulate a follow/interval/TUI window boundary: rebuilt engines keep
	// the same configuration but get fresh, empty capacity.
	eng, opEng = newWindowEngines(types.Filters{})
	if eng.Stats().MaxCardinality != 2 || opEng.Stats().MaxCardinality != 2 {
		t.Fatal("rebuilt engines must keep the configured limit")
	}
	if len(eng.Stats().PathCounts) != 0 || len(opEng.Stats().MsgCounts) != 0 {
		t.Fatal("rebuilt engines must start with fresh (empty) capacity")
	}
	eng.Process(&types.LogEntry{URI: "/new", Status: 200})
	if eng.Stats().PathCounts["/new"] != 1 {
		t.Error("fresh window must admit keys again")
	}

	// 0 keeps meaning unlimited.
	flagMaxCard = 0
	eng, _ = newWindowEngines(types.Filters{})
	for i := 0; i < 100; i++ {
		eng.Process(&types.LogEntry{URI: "/p" + strconv.Itoa(i), Status: 200})
	}
	if len(eng.Stats().PathCounts) != 100 {
		t.Errorf("MaxCardinality=0 must be unlimited, got %d keys", len(eng.Stats().PathCounts))
	}
}
