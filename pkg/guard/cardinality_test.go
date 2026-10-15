package guard

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// TestGuardCardinalityAppliedAndKeptAfterTick verifies the global
// --max-cardinality setting reaches the guard's per-window analysis engine
// and is applied again to the rebuilt engine after the tick reset, while
// global request totals stay exact.
func TestGuardCardinalityAppliedAndKeptAfterTick(t *testing.T) {
	g := New(Config{Window: time.Minute, Blocker: newFakeBlocker(), MaxCardinality: 50})
	if got := g.Engine().Stats().MaxCardinality; got != 50 {
		t.Fatalf("engine cap after New = %d, want 50", got)
	}
	for i := 0; i < 75; i++ {
		g.Engine().Process(&types.LogEntry{URI: "/p" + strconv.Itoa(i), Status: 200})
	}
	s := g.Engine().Stats()
	if got := len(s.PathCounts); got != 50 {
		t.Errorf("PathCounts = %d keys, want 50", got)
	}
	if s.TotalRequests != 75 {
		t.Errorf("TotalRequests = %d, want 75", s.TotalRequests)
	}

	// Tick resets the window: the rebuilt engine must carry the same cap
	// and start with fresh capacity.
	g.Tick(context.Background())
	rs := g.Engine().Stats()
	if got := rs.MaxCardinality; got != 50 {
		t.Fatalf("engine cap after Tick = %d, want 50", got)
	}
	if got := len(rs.PathCounts); got != 0 {
		t.Errorf("fresh window must start empty, got %d keys", got)
	}
}

// TestGuardZeroCardinalityLeavesEngineUnlimited preserves the zero-value
// Config behavior for library callers/tests (0 = unlimited engine, detector
// keeps its own built-in LRU cap).
func TestGuardZeroCardinalityLeavesEngineUnlimited(t *testing.T) {
	g := New(Config{Window: time.Minute, Blocker: newFakeBlocker()})
	if got := g.Engine().Stats().MaxCardinality; got != 0 {
		t.Errorf("zero Config value must leave engine unlimited, got %d", got)
	}
}
