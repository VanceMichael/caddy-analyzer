package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestPlanSourcesExpandsGlobAndDedupes(t *testing.T) {
	dir := t.TempDir()
	fA := filepath.Join(dir, "a.log")
	fB := filepath.Join(dir, "b.log")
	for _, p := range []string{fA, fB} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	in := []types.LogSource{
		// Glob expands to concrete, sorted file identities.
		{Type: types.SourceFile, Path: filepath.Join(dir, "*.log")},
		// Same file via a different spelling must merge into one key.
		{Type: types.SourceFile, Path: fA},
		// Repeated scheme source merges too.
		{Type: types.SourceDocker, Path: "caddy"},
		{Type: types.SourceDocker, Path: "caddy"},
	}
	got := planSources(in)
	if len(got) != 3 {
		t.Fatalf("planned %d sources %v, want 3 (a.log, b.log, docker)", len(got), got)
	}
	if got[0].Path != fA || got[1].Path != fB {
		t.Errorf("glob matches must be concrete files in sorted order, got %v %v", got[0].Path, got[1].Path)
	}
	for _, s := range got {
		if s.Type == types.SourceDocker && s.Canonical() != "docker://caddy" {
			t.Errorf("docker canonical = %q", s.Canonical())
		}
	}
}

func TestPlanSourcesKeepsUnmatchedPattern(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.log")
	got := planSources([]types.LogSource{{Type: types.SourceFile, Path: missing}})
	if len(got) != 1 || got[0].Path != missing {
		t.Fatalf("unmatched pattern must be preserved for an accurate open error, got %+v", got)
	}
}

func TestPlanSourcesK8sDefaultNamespaceMerges(t *testing.T) {
	got := planSources([]types.LogSource{
		{Type: types.SourceK8s, Path: "pod"},
		{Type: types.SourceK8s, Namespace: types.DefaultK8sNamespace, Path: "pod"},
	})
	if len(got) != 1 {
		t.Fatalf("k8s default-namespace spellings must merge, got %+v", got)
	}
	if got[0].Canonical() != "k8s://default/pod" {
		t.Fatalf("canonical = %q", got[0].Canonical())
	}
}

func TestPlanSourcesStdinIdentity(t *testing.T) {
	got := planSources([]types.LogSource{
		{Type: types.SourceStdin},
		{Type: types.SourceStdin},
	})
	if len(got) != 1 || got[0].Canonical() != "stdin" {
		t.Fatalf("stdin must dedupe to one key, got %+v", got)
	}
}

func TestTopSourceDimension(t *testing.T) {
	s := types.NewStats()
	s.SourceCounts["b.log"] = 3
	s.SourceCounts["a.log"] = 5

	if field, ok := topFieldForDimension("source"); !ok || field != types.TopSource {
		t.Fatalf("source dimension lookup = %v, %v", field, ok)
	}
	items := topItems("source", s, 10)
	if len(items) != 2 || items[0].Key != "a.log" || items[0].Count != 5 || items[1].Key != "b.log" {
		t.Fatalf("top source items = %+v, want a.log(5), b.log(3)", items)
	}
	if topTitle("sources") != "Sources" {
		t.Errorf("source title = %q", topTitle("sources"))
	}
	for _, name := range []string{"source", "sources"} {
		if !isSupportedDimension(name) {
			t.Errorf("%s must be a supported dimension", name)
		}
	}
}
