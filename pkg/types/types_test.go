package types

import (
	"strconv"
	"testing"
)

func TestEffectiveClientIP_NotTrusted(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "8.8.8.8",
		ForwardedFor: []string{"1.1.1.1"},
		RealIP:       "9.9.9.9",
	}
	if got := e.EffectiveClientIP(false); got != "8.8.8.8" {
		t.Fatalf("not trusted: want RemoteIP 8.8.8.8, got %s", got)
	}
}

// TestEffectiveClientIP_LastHopSelected: the rightmost public hop is the one
// added by the trusted reverse proxy; the leftmost is client-controlled and
// must NOT be returned or an attacker can spoof it (rate-limit evasion,
// third-party ban DoS).
func TestEffectiveClientIP_LastHopSelected(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1", // Caddy's direct peer (the reverse proxy)
		ForwardedFor: []string{"8.8.8.8", "203.0.113.5"},
	}
	// 203.0.113.5 is the rightmost public hop → the trusted one.
	if got := e.EffectiveClientIP(true); got != "203.0.113.5" {
		t.Fatalf("trusted: want last public hop 203.0.113.5, got %s", got)
	}
}

// TestEffectiveClientIP_SpoofedFirstHopIgnored: regression test for the
// XFF spoofing bug — the first hop is client-controlled and must be ignored.
func TestEffectiveClientIP_SpoofedFirstHopIgnored(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: []string{"8.8.8.8", "203.0.113.5"}, // 8.8.8.8 spoofed by client
	}
	if got := e.EffectiveClientIP(true); got == "8.8.8.8" {
		t.Fatalf("spoofed first hop must NOT be returned (got %s) — this reopens CVE-style XFF spoofing", got)
	}
}

func TestEffectiveClientIP_FallsBackToRealIP(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: nil,
		RealIP:       "198.51.100.7",
	}
	if got := e.EffectiveClientIP(true); got != "198.51.100.7" {
		t.Fatalf("want RealIP 198.51.100.7, got %s", got)
	}
}

func TestEffectiveClientIP_FallsBackToRemoteIP(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: []string{"127.0.0.1", "10.0.0.2"}, // all private
		RealIP:       "127.0.0.1",
	}
	if got := e.EffectiveClientIP(true); got != "10.0.0.1" {
		t.Fatalf("want RemoteIP 10.0.0.1, got %s", got)
	}
}

func TestEffectiveClientIP_Empty(t *testing.T) {
	e := LogEntry{}
	if got := e.EffectiveClientIP(true); got != "" {
		t.Fatalf("want empty, got %s", got)
	}
}

func TestDefaultTopSections(t *testing.T) {
	s := DefaultTopSections()
	if !s.Path || !s.IP || !s.UA || !s.Method || !s.Status || !s.Host || !s.Country || !s.ASN {
		t.Errorf("expected all sections enabled, got %+v", s)
	}
}

func TestLogEntryPath(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/api/v1", "/api/v1"},
		{"/api/v1?q=1", "/api/v1"},
		{"/", "/"},
		{"", ""},
	}
	for _, tt := range tests {
		e := LogEntry{URI: tt.uri}
		if got := e.Path(); got != tt.want {
			t.Errorf("Path(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

func TestNewStats(t *testing.T) {
	s := NewStats()
	if s == nil {
		t.Fatal("NewStats returned nil")
	}
	if s.StatusCounts == nil || s.PathCounts == nil || s.RemoteIPCounts == nil {
		t.Error("expected initialized maps")
	}
	if s.MinDuration != 1<<63-1 {
		t.Errorf("MinDuration = %v, want max int64", s.MinDuration)
	}
}

func TestIncStrCount(t *testing.T) {
	s := NewStats()
	if !s.IncStrCount(s.PathCounts, "/a") {
		t.Error("new key under cap must be admitted")
	}
	if !s.IncStrCount(s.PathCounts, "/a") {
		t.Error("existing key must stay admitted after cap reached")
	}
	if s.PathCounts["/a"] != 2 {
		t.Errorf("expected 2, got %d", s.PathCounts["/a"])
	}
	// cap reached → new key dropped
	s.MaxCardinality = 1
	if s.IncStrCount(s.PathCounts, "/b") {
		t.Error("new key should be dropped when cap reached")
	}
	if _, ok := s.PathCounts["/b"]; ok {
		t.Error("new key should be dropped when cap reached")
	}
	// ... and it must not evict the old key.
	if s.PathCounts["/a"] != 2 {
		t.Errorf("rejected new key must not evict old key, got %d", s.PathCounts["/a"])
	}
}

func TestIncStrCountCompanionsShareAdmission(t *testing.T) {
	s := NewStats()
	s.MaxCardinality = 1
	if !s.IncStrCount(s.PathCounts, "/a") {
		t.Fatal("/a must be admitted")
	}
	// Companion counters/bytes/values follow the primary's admission.
	s.IncStrCountFor(s.PathCounts, s.PathErrorCounts, "/a")
	s.IncStrCountFor(s.PathCounts, s.PathErrorCounts, "/a")
	s.AddStrBytesFor(s.PathCounts, s.PathBytesMap, "/a", 100)
	s.AddStrBytesFor(s.PathCounts, s.PathBytesMap, "/a", 50)
	SetValueFor(s.PathCounts, s.CityLocations, "/a", GeoLocation{Latitude: 1})
	if s.PathErrorCounts["/a"] != 2 || s.PathBytesMap["/a"] != 150 {
		t.Errorf("companion state for admitted key missing: errs=%d bytes=%d", s.PathErrorCounts["/a"], s.PathBytesMap["/a"])
	}
	// Rejected primary key must not create any orphan companion entry.
	s.IncStrCountFor(s.PathCounts, s.PathErrorCounts, "/b")
	s.AddStrBytesFor(s.PathCounts, s.PathBytesMap, "/b", 999)
	SetValueFor(s.PathCounts, s.CityLocations, "/b", GeoLocation{Latitude: 2})
	if _, ok := s.PathErrorCounts["/b"]; ok {
		t.Error("PathErrorCounts must not contain rejected key")
	}
	if _, ok := s.PathBytesMap["/b"]; ok {
		t.Error("PathBytesMap must not contain rejected key")
	}
	if _, ok := s.CityLocations["/b"]; ok {
		t.Error("companion value map must not contain rejected key")
	}
}

func TestOperationalStatsIncStrCountCap(t *testing.T) {
	s := NewOperationalStats()
	s.MaxCardinality = 1
	s.IncStrCount(s.MsgCounts, "started")
	s.IncStrCount(s.MsgCounts, "started")
	s.IncStrCount(s.MsgCounts, "reloaded")
	if s.MsgCounts["started"] != 2 {
		t.Errorf("existing key must accumulate, got %d", s.MsgCounts["started"])
	}
	if _, ok := s.MsgCounts["reloaded"]; ok {
		t.Error("new operational key must be dropped after cap")
	}
	// 0 keeps the unlimited behavior.
	s0 := NewOperationalStats()
	for i := 0; i < 50; i++ {
		s0.IncStrCount(s0.MsgCounts, "k"+strconv.Itoa(i))
	}
	if len(s0.MsgCounts) != 50 {
		t.Errorf("MaxCardinality=0 must be unlimited, got %d keys", len(s0.MsgCounts))
	}
}

func TestAddStrBytes(t *testing.T) {
	s := NewStats()
	s.AddStrBytes(s.PathBytesMap, "/a", 100)
	s.AddStrBytes(s.PathBytesMap, "/a", 50)
	if s.PathBytesMap["/a"] != 150 {
		t.Errorf("expected 150, got %d", s.PathBytesMap["/a"])
	}
	s.MaxCardinality = 1
	s.AddStrBytes(s.PathBytesMap, "/b", 10)
	if _, ok := s.PathBytesMap["/b"]; ok {
		t.Error("new key should be dropped when cap reached")
	}
}

func TestAddDurationAndPercentiles(t *testing.T) {
	s := NewStats()
	for _, d := range []float64{0.001, 0.002, 0.003, 0.004, 0.005} {
		s.AddDuration(d)
	}
	s.ComputePercentiles()
	if s.Percentile50 <= 0 || s.Percentile95 <= 0 || s.Percentile99 <= 0 {
		t.Errorf("percentiles not computed: p50=%v p95=%v p99=%v",
			s.Percentile50, s.Percentile95, s.Percentile99)
	}
}
