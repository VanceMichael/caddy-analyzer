package analysis

import (
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// newCappedEngine builds an engine whose every string-keyed dimension shares
// the given MaxCardinality, optionally with the detector enabled.
func newCappedEngine(maxCard int, detect bool) *Engine {
	e := New(types.Filters{})
	e.Stats().MaxCardinality = maxCard
	if detect {
		e.SetDetector(NewDetector())
	}
	return e
}

func keys(m map[string]int64) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// TestMaxCardinalityPathDimensionSharedAdmission verifies that path counts,
// path bytes and path error counts share one admission decision; rejected
// keys create no orphan companions, admitted keys keep accumulating, and the
// global request/byte/error counters stay exact.
func TestMaxCardinalityPathDimensionSharedAdmission(t *testing.T) {
	e := newCappedEngine(2, false)
	entries := []*types.LogEntry{
		{Method: "GET", URI: "/a", Host: "h", RemoteIP: "1.1.1.1", Status: 200, Size: 100},
		{Method: "GET", URI: "/b", Host: "h", RemoteIP: "1.1.1.1", Status: 500, Size: 200},
		{Method: "GET", URI: "/c", Host: "h", RemoteIP: "1.1.1.1", Status: 500, Size: 300}, // rejected path, 5xx
		{Method: "GET", URI: "/d", Host: "h", RemoteIP: "1.1.1.1", Status: 200, Size: 400}, // rejected path
		{Method: "GET", URI: "/a", Host: "h", RemoteIP: "1.1.1.1", Status: 500, Size: 50},  // admitted key keeps accumulating
	}
	for _, en := range entries {
		e.Process(en)
	}
	s := e.Stats()

	if s.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", s.TotalRequests)
	}
	if s.TotalBytes != 1050 {
		t.Errorf("TotalBytes = %d, want 1050 (global bytes must stay exact)", s.TotalBytes)
	}
	if s.Errors != 3 || s.Status5xx != 3 {
		t.Errorf("Errors = %d, Status5xx = %d, want 3/3", s.Errors, s.Status5xx)
	}
	if len(s.PathCounts) != 2 {
		t.Fatalf("PathCounts len = %d, want 2: %v", len(s.PathCounts), s.PathCounts)
	}
	if s.PathCounts["/a"] != 2 || s.PathCounts["/b"] != 1 {
		t.Errorf("admitted paths must keep accumulating: %v", s.PathCounts)
	}
	if _, ok := s.PathCounts["/c"]; ok || s.PathCounts["/d"] != 0 {
		t.Error("rejected new paths must not be admitted, nor evict old keys")
	}
	// Companion maps stay in lockstep with the primary dimension.
	if len(s.PathBytesMap) != 2 {
		t.Errorf("PathBytesMap len = %d, want 2", len(s.PathBytesMap))
	}
	if s.PathBytesMap["/a"] != 150 || s.PathBytesMap["/b"] != 200 {
		t.Errorf("path bytes for admitted paths wrong: %v", s.PathBytesMap)
	}
	if len(s.PathErrorCounts) != 2 {
		t.Errorf("PathErrorCounts len = %d, want 2 (rejected /c must be absent)", len(s.PathErrorCounts))
	}
	if s.PathErrorCounts["/a"] != 1 || s.PathErrorCounts["/b"] != 1 {
		t.Errorf("PathErrorCounts = %v", s.PathErrorCounts)
	}
	paths := keys(s.PathCounts)
	for k := range s.PathBytesMap {
		if !paths[k] {
			t.Errorf("orphan byte entry %q without parent PathCounts", k)
		}
	}
	for k := range s.PathErrorCounts {
		if !paths[k] {
			t.Errorf("orphan error entry %q without parent PathCounts", k)
		}
	}
}

// TestMaxCardinalityIPDimensionSharedAdmission covers the IP counter and its
// byte companion.
func TestMaxCardinalityIPDimensionSharedAdmission(t *testing.T) {
	e := newCappedEngine(2, false)
	for _, en := range []*types.LogEntry{
		{URI: "/", Status: 200, Size: 10, RemoteIP: "1.1.1.1"},
		{URI: "/", Status: 200, Size: 20, RemoteIP: "2.2.2.2"},
		{URI: "/", Status: 200, Size: 30, RemoteIP: "3.3.3.3"}, // rejected
		{URI: "/", Status: 200, Size: 40, RemoteIP: "1.1.1.1"}, // existing
	} {
		e.Process(en)
	}
	s := e.Stats()
	if len(s.RemoteIPCounts) != 2 || s.RemoteIPCounts["1.1.1.1"] != 2 {
		t.Errorf("RemoteIPCounts = %v", s.RemoteIPCounts)
	}
	if len(s.IPBytesMap) != 2 || s.IPBytesMap["1.1.1.1"] != 50 || s.IPBytesMap["2.2.2.2"] != 20 {
		t.Errorf("IPBytesMap = %v", s.IPBytesMap)
	}
	if _, ok := s.IPBytesMap["3.3.3.3"]; ok {
		t.Error("rejected IP must not create a byte entry")
	}
}

// TestMaxCardinalityGeoCompanions verifies country names and city locations
// cannot outgrow their primary counter.
func TestMaxCardinalityGeoCompanions(t *testing.T) {
	e := newCappedEngine(1, false)
	for _, en := range []*types.LogEntry{
		{URI: "/", Status: 200, Geo: types.GeoInfo{CountryCode: "US", CountryName: "United States", City: "New York", Latitude: 40.7}},
		{URI: "/", Status: 200, Geo: types.GeoInfo{CountryCode: "DE", CountryName: "Germany", City: "Berlin", Latitude: 52.5}},
		{URI: "/", Status: 200, Geo: types.GeoInfo{CountryCode: "IT", CountryName: "Italy", City: "Rome", Latitude: 41.9}},
	} {
		e.Process(en)
	}
	s := e.Stats()
	if len(s.CountryCounts) != 1 || len(s.CountryNames) != 1 {
		t.Errorf("country dimension = counts %d names %d, want 1/1", len(s.CountryCounts), len(s.CountryNames))
	}
	if s.CountryNames["US"] != "United States" {
		t.Errorf("admitted country name missing: %v", s.CountryNames)
	}
	for code := range s.CountryNames {
		if _, ok := s.CountryCounts[code]; !ok {
			t.Errorf("orphan country name %q without parent count", code)
		}
	}
	if len(s.CityCounts) != 1 || len(s.CityLocations) != 1 {
		t.Errorf("city dimension = counts %d locations %d, want 1/1", len(s.CityCounts), len(s.CityLocations))
	}
	if s.CityLocations["New York"].Latitude != 40.7 {
		t.Errorf("admitted city location missing: %v", s.CityLocations)
	}
	for city := range s.CityLocations {
		if _, ok := s.CityCounts[city]; !ok {
			t.Errorf("orphan city location %q without parent count", city)
		}
	}
}

// TestMaxCardinalityProtoAndTLS covers the two dimensions that previously
// bypassed the cap via direct map writes.
func TestMaxCardinalityProtoAndTLS(t *testing.T) {
	e := newCappedEngine(1, false)
	for _, en := range []*types.LogEntry{
		{URI: "/", Status: 200, Proto: "HTTP/1.1", TLSVersion: "TLS 1.2"},
		{URI: "/", Status: 200, Proto: "HTTP/2.0", TLSVersion: "TLS 1.3"},
		{URI: "/", Status: 200, Proto: "HTTP/3.0"}, // plain HTTP fallback key
	} {
		e.Process(en)
	}
	s := e.Stats()
	if len(s.ProtoCounts) != 1 {
		t.Errorf("ProtoCounts = %v, want exactly 1 admitted protocol", s.ProtoCounts)
	}
	if len(s.TLSVersionCounts) != 1 {
		t.Errorf("TLSVersionCounts = %v, want exactly 1 admitted TLS value", s.TLSVersionCounts)
	}
}

// TestMaxCardinalitySuspiciousDetails verifies detection detail companions
// share the SuspiciousIPs admission decision.
func TestMaxCardinalitySuspiciousDetails(t *testing.T) {
	e := newCappedEngine(3, true)
	for i, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		e.Process(&types.LogEntry{
			Method:     "GET",
			URI:        "/?id=" + string(rune('a'+i)) + " UNION SELECT username,password FROM users",
			Status:     200,
			RemoteIP:   ip,
			RemoteAddr: ip + ":1234",
		})
	}
	s := e.Stats()
	if len(s.SuspiciousIPs) != 3 {
		t.Fatalf("SuspiciousIPs len = %d, want 3: %v", len(s.SuspiciousIPs), s.SuspiciousIPs)
	}
	if len(s.SuspiciousDetails) != 3 {
		t.Errorf("SuspiciousDetails len = %d, want 3", len(s.SuspiciousDetails))
	}
	if len(s.SuspiciousDetections) != 3 {
		t.Errorf("SuspiciousDetections len = %d, want 3", len(s.SuspiciousDetections))
	}
	parents := keys(s.SuspiciousIPs)
	for ip := range s.SuspiciousDetails {
		if !parents[ip] {
			t.Errorf("orphan detection detail for IP %q without SuspiciousIPs parent", ip)
		}
	}
	for ip := range s.SuspiciousDetections {
		if !parents[ip] {
			t.Errorf("orphan detection record for IP %q without SuspiciousIPs parent", ip)
		}
	}
	if _, ok := s.SuspiciousDetails["4.4.4.4"]; ok {
		t.Error("rejected suspicious IP must not carry details")
	}
}

// TestMaxCardinalityInterleavedHTTPAndOperational drives both engines with
// interleaved HTTP and operational entries and asserts both caps hold while
// their global totals stay exact.
func TestMaxCardinalityInterleavedHTTPAndOperational(t *testing.T) {
	httpEng := newCappedEngine(2, false)
	opEng := NewOperationalEngine(types.Filters{})
	opEng.Stats().MaxCardinality = 2

	for i := 0; i < 5; i++ {
		httpEng.Process(&types.LogEntry{
			URI:    "/p" + string(rune('0'+i)),
			Status: 200,
			Size:   int64(10 + i),
		})
		opEng.Process(&types.OperationalEntry{
			Level:  "info",
			Logger: "tls",
			Msg:    "message-" + string(rune('0'+i)),
		})
	}
	hs := httpEng.Stats()
	os := opEng.Stats()
	if hs.TotalRequests != 5 || hs.TotalBytes != 60 {
		t.Errorf("HTTP globals wrong: requests=%d bytes=%d", hs.TotalRequests, hs.TotalBytes)
	}
	if len(hs.PathCounts) != 2 || len(hs.PathBytesMap) != 2 {
		t.Errorf("HTTP dimension not capped: paths=%d bytes=%d", len(hs.PathCounts), len(hs.PathBytesMap))
	}
	if os.TotalEvents != 5 {
		t.Errorf("operational TotalEvents = %d, want 5", os.TotalEvents)
	}
	if len(os.MsgCounts) != 2 {
		t.Errorf("MsgCounts len = %d, want 2", len(os.MsgCounts))
	}
	if os.LoggerCounts["tls"] != 5 {
		t.Errorf("admitted logger must keep accumulating: %v", os.LoggerCounts)
	}
}

// TestOperationalEngineMaxCardinality covers the level/logger/message maps
// directly, including the 0 = unlimited default.
func TestOperationalEngineMaxCardinality(t *testing.T) {
	eng := NewOperationalEngine(types.Filters{})
	eng.Stats().MaxCardinality = 2
	for _, en := range []*types.OperationalEntry{
		{Level: "info", Logger: "tls", Msg: "m1"},
		{Level: "error", Logger: "http", Msg: "m2"},
		{Level: "warn", Logger: "admin", Msg: "m3"},
		{Level: "info", Logger: "tls", Msg: "m4"},
		{Level: "info", Logger: "tls", Msg: "m1"},
	} {
		eng.Process(en)
	}
	s := eng.Stats()
	if s.TotalEvents != 5 || s.Errors != 1 {
		t.Errorf("global operational totals must stay exact: events=%d errors=%d", s.TotalEvents, s.Errors)
	}
	if len(s.LevelCounts) != 2 || len(s.LoggerCounts) != 2 || len(s.MsgCounts) != 2 {
		t.Errorf("operational dimensions not capped: levels=%d loggers=%d msgs=%d",
			len(s.LevelCounts), len(s.LoggerCounts), len(s.MsgCounts))
	}
	if s.LoggerCounts["tls"] != 3 {
		t.Errorf("admitted logger must accumulate: %v", s.LoggerCounts)
	}

	unlimited := NewOperationalEngine(types.Filters{})
	for i := 0; i < 50; i++ {
		unlimited.Process(&types.OperationalEntry{Level: "info", Logger: "l", Msg: "m" + string(rune('A'+i%26)) + string(rune('a'+i/26))})
	}
	if len(unlimited.Stats().MsgCounts) != 50 {
		t.Errorf("MaxCardinality=0 must stay unlimited, got %d keys", len(unlimited.Stats().MsgCounts))
	}
}
