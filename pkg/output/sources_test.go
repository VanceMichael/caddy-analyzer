package output

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// multiSourceFixture builds engines with traffic split across two sources
// plus operational events and parse errors attributed to each.
func multiSourceFixture(t *testing.T) (*analysis.Engine, *analysis.OperationalEngine) {
	t.Helper()
	engine := analysis.New(types.Filters{})
	// b.log has more traffic → it must rank first in every format.
	for i := 0; i < 5; i++ {
		engine.Process(&types.LogEntry{Source: "b.log", Method: "GET", URI: "/b", Host: "h", Status: 200, Size: 10})
	}
	engine.Process(&types.LogEntry{Source: "a.log", Method: "GET", URI: "/a", Host: "h", Status: 200, Size: 10})
	s := engine.Stats()
	s.ParseErrors = 3
	s.RecordSourceParseError("a.log")
	s.RecordSourceParseError("a.log")
	s.RecordSourceParseError("b.log")
	engine.Finalize()

	op := analysis.NewOperationalEngine(types.Filters{})
	op.Process(&types.OperationalEntry{Source: "a.log", Level: "info", Msg: "started"})

	return engine, op
}

func TestReportSourcesAllFormatsConsistent(t *testing.T) {
	engine, op := multiSourceFixture(t)

	wantOrder := []string{"b.log", "a.log"}
	for _, format := range []Format{FormatTable, FormatJSON, FormatCSV, FormatHTML} {
		t.Run(string(format), func(t *testing.T) {
			var buf bytes.Buffer
			report := NewReport(engine, format, 5)
			report.SetWriter(&buf)
			report.SetOperationalStats(op.Stats())
			if err := report.Print(); err != nil {
				t.Fatalf("Print failed: %v", err)
			}
			out := buf.String()

			switch format {
			case FormatTable:
				if !strings.Contains(out, "Sources Breakdown") {
					t.Errorf("table report missing Sources Breakdown:\n%s", out)
				}
			case FormatCSV:
				if !strings.Contains(out, "sources:source,requests,operational_events,parse_errors") {
					t.Errorf("csv report missing sources section:\n%s", out)
				}
			case FormatHTML:
				if !strings.Contains(out, "<h2>Sources</h2>") {
					t.Errorf("html report missing sources card:\n%s", out)
				}
			case FormatJSON:
				var data map[string]json.RawMessage
				if err := json.Unmarshal([]byte(out), &data); err != nil {
					t.Fatalf("invalid json: %v", err)
				}
				raw, ok := data["sources"]
				if !ok {
					t.Fatal("json report missing sources key")
				}
				var rows []types.SourceStat
				if err := json.Unmarshal(raw, &rows); err != nil {
					t.Fatalf("decode sources: %v", err)
				}
				if len(rows) != 2 {
					t.Fatalf("sources rows = %d, want 2", len(rows))
				}
				for i, want := range wantOrder {
					if rows[i].Source != want {
						t.Errorf("json source rank %d = %q, want %q", i, rows[i].Source, want)
					}
				}
				if rows[0].Requests != 5 || rows[1].Requests != 1 {
					t.Errorf("unexpected request counts: %+v", rows)
				}
				if rows[1].OperationalEvents != 1 || rows[1].ParseErrors != 2 {
					t.Errorf("a.log row reconciliation wrong: %+v", rows[1])
				}
				if rows[0].ParseErrors != 1 {
					t.Errorf("b.log parse errors = %d, want 1", rows[0].ParseErrors)
				}
			}

			// Both sources must be named in every format.
			for _, name := range wantOrder {
				if !strings.Contains(out, name) {
					t.Errorf("%s output missing source %q", format, name)
				}
			}
		})
	}
}

// TestReportSingleSourceOmitsBreakdown guarantees single-source sessions keep
// byte-identical default behavior: no sources section in any format.
func TestReportSingleSourceOmitsBreakdown(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{Source: "only.log", Method: "GET", URI: "/", Host: "h", Status: 200, Size: 1})
	engine.Finalize()

	for _, format := range []Format{FormatTable, FormatJSON, FormatCSV, FormatHTML} {
		t.Run(string(format), func(t *testing.T) {
			var buf bytes.Buffer
			report := NewReport(engine, format, 5)
			report.SetWriter(&buf)
			if err := report.Print(); err != nil {
				t.Fatalf("Print failed: %v", err)
			}
			out := buf.String()
			for _, marker := range []string{"Sources Breakdown", `"sources"`, "sources:source", "<h2>Sources</h2>"} {
				if strings.Contains(out, marker) {
					t.Errorf("single-source %s output unexpectedly contains %q", format, marker)
				}
			}
		})
	}
}

// TestReportRemoteExportsCarrySources verifies the same sources array reaches
// Elasticsearch/OpenSearch bulk documents and Loki pushes, so remote formats
// agree with the local formats.
func TestReportRemoteExportsCarrySources(t *testing.T) {
	engine, op := multiSourceFixture(t)

	for _, tc := range []struct {
		name   string
		format Format
		build  func(url string) (RemoteExporter, error)
	}{
		{"elasticsearch", FormatElasticsearch, func(url string) (RemoteExporter, error) {
			return NewElasticsearchExporter(RemoteConfig{URL: url, Index: "ix"})
		}},
		{"loki", FormatLoki, func(url string) (RemoteExporter, error) {
			return NewLokiExporter(RemoteConfig{URL: url, Index: "ix"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				body.Write(b)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer ts.Close()

			exporter, err := tc.build(ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			report := NewReport(engine, tc.format, 5)
			report.SetOperationalStats(op.Stats())
			report.SetRemoteExporter(exporter)
			if err := report.Print(); err != nil {
				t.Fatalf("Print failed: %v", err)
			}
			payload := body.String()
			// Loki embeds the report document as an escaped JSON string
			// inside its "values" array; ES/OpenSearch send raw NDJSON.
			hasArray := strings.Contains(payload, `"sources":[`) || strings.Contains(payload, `\"sources\":[`)
			if !hasArray || !strings.Contains(payload, "b.log") || !strings.Contains(payload, "a.log") {
				t.Fatalf("%s payload missing sources array:\n%s", tc.name, payload)
			}
		})
	}
}

// TestReportDetectTableIncludesSources covers the --detect table path, which
// has its own renderer.
func TestReportDetectTableIncludesSources(t *testing.T) {
	engine, op := multiSourceFixture(t)
	var buf bytes.Buffer
	report := NewReport(engine, FormatTable, 5)
	report.SetDetect(true)
	report.SetWriter(&buf)
	report.SetOperationalStats(op.Stats())
	if err := report.Print(); err != nil {
		t.Fatalf("Print failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Sources:") || !strings.Contains(out, "b.log") || !strings.Contains(out, "a.log") {
		t.Errorf("detect table missing sources block:\n%s", out)
	}
}
