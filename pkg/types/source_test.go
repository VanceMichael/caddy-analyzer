package types

import "testing"

func TestLogSourceCanonical(t *testing.T) {
	tests := []struct {
		name string
		src  LogSource
		want string
	}{
		{"stdin", LogSource{Type: SourceStdin}, "stdin"},
		{"file cleaned", LogSource{Type: SourceFile, Path: "./dir/../access.log"}, "access.log"},
		{"docker", LogSource{Type: SourceDocker, Path: "caddy"}, "docker://caddy"},
		{"k8s explicit ns", LogSource{Type: SourceK8s, Namespace: "kube-system", Path: "pod-x"}, "k8s://kube-system/pod-x"},
		{"k8s default ns", LogSource{Type: SourceK8s, Path: "pod-x"}, "k8s://default/pod-x"},
		{"journalctl", LogSource{Type: SourceJournalctl, Path: "caddy.service"}, "journalctl://caddy.service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.src.Canonical(); got != tt.want {
				t.Errorf("Canonical() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalStableAcrossEquivalentSpellings(t *testing.T) {
	a := LogSource{Type: SourceFile, Path: "a.log"}
	b := LogSource{Type: SourceFile, Path: "./a.log"}
	if a.Canonical() != b.Canonical() {
		t.Errorf("equivalent file spellings produced different keys: %q vs %q", a.Canonical(), b.Canonical())
	}
	k1 := LogSource{Type: SourceK8s, Path: "p"}
	k2 := LogSource{Type: SourceK8s, Namespace: DefaultK8sNamespace, Path: "p"}
	if k1.Canonical() != k2.Canonical() {
		t.Errorf("default and explicit default namespace produced different keys: %q vs %q", k1.Canonical(), k2.Canonical())
	}
}
