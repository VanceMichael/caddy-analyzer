package analysis

import (
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestSourceStatsMergeOrderAndSkipEmpty(t *testing.T) {
	requests := map[string]int64{"a.log": 5, "b.log": 2, "": 9}
	events := map[string]int64{"k8s://default/pod": 4, "a.log": 1}
	errors := map[string]int64{"b.log": 10}

	rows := SourceStats(requests, events, errors)

	// Empty key must never produce a phantom row.
	for _, r := range rows {
		if r.Source == "" {
			t.Fatalf("empty source produced a row: %+v", rows)
		}
	}

	// Deterministic order: total activity desc, source name asc on ties.
	want := []types.SourceStat{
		{Source: "b.log", Requests: 2, ParseErrors: 10},      // total 12
		{Source: "a.log", Requests: 5, OperationalEvents: 1}, // total 6
		{Source: "k8s://default/pod", OperationalEvents: 4},  // total 4
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestSourceStatsTieBreakByName(t *testing.T) {
	rows := SourceStats(
		map[string]int64{"z.log": 1, "a.log": 1},
		nil, nil,
	)
	if len(rows) != 2 || rows[0].Source != "a.log" || rows[1].Source != "z.log" {
		t.Fatalf("tie break wrong: %+v", rows)
	}

	// Nil/empty maps → no rows.
	if rows := SourceStats(nil, nil, nil); len(rows) != 0 {
		t.Fatalf("expected no rows, got %+v", rows)
	}
}

func TestEngineAttributesRequestsToSource(t *testing.T) {
	engine := New(types.Filters{})
	engine.Process(&types.LogEntry{Source: "a.log", Method: "GET", URI: "/", Status: 200})
	engine.Process(&types.LogEntry{Source: "a.log", Method: "GET", URI: "/", Status: 200})
	engine.Process(&types.LogEntry{Source: "b.log", Method: "GET", URI: "/", Status: 200})
	// Directly constructed entry without source: not attributed.
	engine.Process(&types.LogEntry{Method: "GET", URI: "/", Status: 200})

	s := engine.Stats()
	if s.SourceCounts["a.log"] != 2 || s.SourceCounts["b.log"] != 1 {
		t.Fatalf("source counts = %v, want a.log=2 b.log=1", s.SourceCounts)
	}
	if _, ok := s.SourceCounts[""]; ok {
		t.Fatal("untagged entry must not create an empty-source key")
	}
	if s.TotalRequests != 4 {
		t.Fatalf("global total = %d, want 4", s.TotalRequests)
	}
}
