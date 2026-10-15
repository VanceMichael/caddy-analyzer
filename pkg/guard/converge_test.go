package guard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// scriptedBlocker is an in-memory Blocker + RuleExister with injectable
// failures for compensation tests.
type scriptedBlocker struct {
	mu                    sync.Mutex
	rules                 map[string]bool
	blockErr              error
	unblockErr            error
	existsErr             error
	blockCalls, unblockCt int
}

func newScriptedBlocker() *scriptedBlocker {
	return &scriptedBlocker{rules: make(map[string]bool)}
}

func (s *scriptedBlocker) Block(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockCalls++
	if s.blockErr != nil {
		return s.blockErr
	}
	s.rules[ip] = true
	return nil
}

func (s *scriptedBlocker) Unblock(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unblockCt++
	if s.unblockErr != nil {
		return s.unblockErr
	}
	delete(s.rules, ip)
	return nil
}

func (s *scriptedBlocker) RuleExists(ip string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.existsErr != nil {
		return false, s.existsErr
	}
	return s.rules[ip], nil
}

func (s *scriptedBlocker) has(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rules[ip]
}

func (s *scriptedBlocker) snapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.rules))
	for k, v := range s.rules {
		out[k] = v
	}
	return out
}

func readStateIPs(t *testing.T, path string) []string {
	t.Helper()
	entries, err := newStateFile(path).load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	ips := make([]string, 0, len(entries))
	for _, e := range entries {
		ips = append(ips, e.IP)
	}
	sort.Strings(ips)
	return ips
}

func asOpErr(t *testing.T, err error) *OpError {
	t.Helper()
	var opErr *OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected *OpError, got %T: %v", err, err)
	}
	return opErr
}

func TestMergeBlockState(t *testing.T) {
	perm := time.Time{}
	future1 := time.Now().Add(time.Hour)
	future2 := future1.Add(time.Hour)

	type m = map[string]time.Time
	tests := []struct {
		name            string
		base, disk, mem m
		want            map[string]time.Time
	}{
		{
			name: "external add adopted when guard idle",
			base: m{}, disk: m{"B": perm}, mem: m{},
			want: m{"B": perm},
		},
		{
			name: "external delete adopted over unchanged guard view",
			base: m{"A": perm}, disk: m{}, mem: m{"A": perm},
			want: m{},
		},
		{
			name: "guard own new block written",
			base: m{}, disk: m{}, mem: m{"A": perm},
			want: m{"A": perm},
		},
		{
			name: "guard expiry delete propagates when disk unchanged",
			base: m{"A": future1}, disk: m{"A": future1}, mem: m{},
			want: m{},
		},
		{
			name: "external permanent supersedes guard expiry removal",
			base: m{"A": future1}, disk: m{"A": perm}, mem: m{},
			want: m{"A": perm},
		},
		{
			name: "manual permanent promotes guard temporary ban",
			base: m{"A": future1}, disk: m{"A": perm}, mem: m{"A": future1},
			want: m{"A": perm},
		},
		{
			name: "guard reban and external permanent both land: permanent wins",
			base: m{"A": future1}, disk: m{"A": perm}, mem: m{"A": future2},
			want: m{"A": perm},
		},
		{
			name: "both deleted stays deleted",
			base: m{"A": perm}, disk: m{}, mem: m{},
			want: m{},
		},
		{
			name: "guard new temp merges with concurrent external temp, later wins",
			base: m{}, disk: m{"A": future1}, mem: m{"A": future2},
			want: m{"A": future2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeBlockState(tt.base, tt.disk, tt.mem)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, wv := range tt.want {
				gv, ok := got[k]
				if !ok || !gv.Equal(wv) {
					t.Fatalf("key %s: got %v, want %v (full: %v)", k, gv, wv, got)
				}
			}
		})
	}
}

func TestManualBlockConverges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	b := newScriptedBlocker()

	if err := ManualBlock(path, "1.1.1.1", b); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !b.has("1.1.1.1") {
		t.Fatal("firewall rule missing after committed block")
	}
	if got := readStateIPs(t, path); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("state = %v", got)
	}

	// Idempotent duplicate: no error, still one entry.
	if err := ManualBlock(path, "1.1.1.1", b); err != nil {
		t.Fatalf("duplicate block: %v", err)
	}
	if got := readStateIPs(t, path); len(got) != 1 {
		t.Fatalf("duplicate block duplicated state: %v", got)
	}

	// Manual block promotes a temporary entry to permanent.
	sf := newStateFile(path)
	if err := sf.saveEntries([]stateEntry{
		{IP: "1.1.1.1", When: time.Now().Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ManualBlock(path, "1.1.1.1", b); err != nil {
		t.Fatalf("promote: %v", err)
	}
	entries, _ := sf.load()
	if !entries[0].When.IsZero() {
		t.Fatalf("manual block must promote temp entry to permanent, got %v", entries[0].When)
	}
}

func TestManualBlockFirewallFailureLeavesStateUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	b := newScriptedBlocker()
	b.blockErr = errors.New("xtables lock held")
	err := ManualBlock(path, "2.2.2.2", b)
	opErr := asOpErr(t, err)
	if opErr.Stage != "firewall" || opErr.Unconverged {
		t.Fatalf("unexpected error: %+v", opErr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state file must not be created when firewall failed")
	}
}

func TestManualBlockStateWriteFailureRollsBackNewRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")
	// First transaction creates the state file and its lock file.
	if err := AddPermanentBlockToState(path, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	b := newScriptedBlocker()
	err := ManualBlock(path, "3.3.3.3", b)
	opErr := asOpErr(t, err)
	if opErr.Stage != "state-write" || opErr.Unconverged {
		t.Fatalf("expected compensated state-write failure, got %+v", opErr)
	}
	if opErr.Compensation == "" {
		t.Fatal("expected compensation description")
	}
	if b.has("3.3.3.3") {
		t.Fatal("newly added rule must be rolled back after state failure")
	}
}

func TestManualBlockWriteFailureKeepsPreExistingRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")
	b := newScriptedBlocker()
	if err := ManualBlock(path, "4.4.4.4", b); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	// 4.4.4.4 is tracked: a later write failure must not remove its rule.
	err := ManualBlock(path, "4.4.4.4", b)
	opErr := asOpErr(t, err)
	if !opErr.Unconverged {
		t.Fatalf("expected unconverged write failure, got %+v", opErr)
	}
	if b.unblockCt != 0 {
		t.Fatal("pre-existing rule must never be rolled back")
	}
	if !b.has("4.4.4.4") {
		t.Fatal("pre-existing rule removed despite unconverged failure")
	}
}

func TestManualBlockRollbackFailureReportedUnconverged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")
	if err := AddPermanentBlockToState(path, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	b := newScriptedBlocker()
	b.unblockErr = errors.New("cannot remove rule")
	err := ManualBlock(path, "5.5.5.5", b)
	opErr := asOpErr(t, err)
	if !opErr.Unconverged || opErr.CompensationErr == nil {
		t.Fatalf("expected unconverged + compensation error, got %+v", opErr)
	}
	if !b.has("5.5.5.5") {
		t.Fatal("rule remains installed while stores disagree")
	}
}

func TestManualUnbanConverges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	b := newScriptedBlocker()
	if err := ManualBlock(path, "6.6.6.6", b); err != nil {
		t.Fatal(err)
	}
	if err := ManualUnban(path, "6.6.6.6", b); err != nil {
		t.Fatalf("unban: %v", err)
	}
	if b.has("6.6.6.6") {
		t.Fatal("rule still installed after unban")
	}
	if got := readStateIPs(t, path); len(got) != 0 {
		t.Fatalf("state not cleared: %v", got)
	}

	// Idempotent: unban an address that is already gone.
	if err := ManualUnban(path, "6.6.6.6", b); err != nil {
		t.Fatalf("repeat unban must succeed: %v", err)
	}
}

func TestManualUnbanRemovesStaleStateWithoutRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	b := newScriptedBlocker() // no rule installed
	if err := AddPermanentBlockToState(path, "7.7.7.7"); err != nil {
		t.Fatal(err)
	}
	if err := ManualUnban(path, "7.7.7.7", b); err != nil {
		t.Fatalf("unban: %v", err)
	}
	if got := readStateIPs(t, path); len(got) != 0 {
		t.Fatalf("stale entry must be removed: %v", got)
	}
}

func TestManualUnbanFirewallFailureKeepsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	b := newScriptedBlocker()
	if err := ManualBlock(path, "8.8.8.8", b); err != nil {
		t.Fatal(err)
	}
	b.unblockErr = errors.New("permission denied")
	err := ManualUnban(path, "8.8.8.8", b)
	opErr := asOpErr(t, err)
	if opErr.Stage != "firewall" || opErr.Unconverged {
		t.Fatalf("unexpected: %+v", opErr)
	}
	if !b.has("8.8.8.8") {
		t.Fatal("rule missing after failed unban")
	}
	if got := readStateIPs(t, path); len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("state must be preserved: %v", got)
	}
}

func TestManualUnbanWriteFailureRestoresProtection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")
	b := newScriptedBlocker()
	if err := ManualBlock(path, "9.9.9.10", b); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	err := ManualUnban(path, "9.9.9.10", b)
	opErr := asOpErr(t, err)
	if opErr.Unconverged || opErr.Compensation == "" {
		t.Fatalf("expected compensated failure, got %+v", opErr)
	}
	if !b.has("9.9.9.10") {
		t.Fatal("protection must be restored after state write failure")
	}
	// The persistent entry survived (nothing could be written).
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if got := readStateIPs(t, path); len(got) != 1 || got[0] != "9.9.9.10" {
		t.Fatalf("state entry must survive: %v", got)
	}
}

func TestManualUnbanCompensationFailureUnconverged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")
	b := newScriptedBlocker()
	if err := ManualBlock(path, "9.9.9.11", b); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()
	b.blockErr = errors.New("cannot restore rule")

	err := ManualUnban(path, "9.9.9.11", b)
	opErr := asOpErr(t, err)
	if !opErr.Unconverged || opErr.CompensationErr == nil {
		t.Fatalf("expected unconverged with compensation error, got %+v", opErr)
	}
}

func TestManualOpsConcurrentNoLostUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	b := newScriptedBlocker()

	const workers = 12
	const perWorker = 40
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", id, i/256, i%256)
				if err := ManualBlock(path, ip, b); err != nil {
					t.Errorf("block %s: %v", ip, err)
					return
				}
				// Every 5th IP gets a duplicate decision (must stay one entry).
				if i%5 == 0 {
					if err := ManualBlock(path, ip, b); err != nil {
						t.Errorf("dup block %s: %v", ip, err)
					}
				}
			}
		}(w)
	}
	wg.Wait()

	want := workers * perWorker
	if got := readStateIPs(t, path); len(got) != want {
		t.Fatalf("lost updates: file has %d entries, want %d", len(got), want)
	}
	if len(b.snapshot()) != want {
		t.Fatalf("firewall has %d rules, want %d", len(b.snapshot()), want)
	}
}

func newReconcileGuard(t *testing.T, path string, b Blocker, duration time.Duration) *Guard {
	t.Helper()
	cfg := Config{
		Window:        time.Minute,
		BlockDuration: duration,
		StatePath:     path,
		Blocker:       b,
	}
	return New(cfg)
}

func TestGuardSyncAdoptsManualAddsAndDeletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	fb := newFakeBlocker()
	g := newReconcileGuard(t, path, fb, time.Hour)

	// Guard's own decision commits firewall + memory + file atomically.
	committed := g.commitBlockDecisions([]Candidate{{IP: "20.0.0.1", Why: "test"}}, time.Now())
	if len(committed) != 1 {
		t.Fatal("guard decision did not commit")
	}

	// Manual block from another process while the guard runs.
	if err := ManualBlock(path, "20.0.0.2", fb); err != nil {
		t.Fatal(err)
	}
	g.syncState()
	if !g.IsBlocked("20.0.0.1") || !g.IsBlocked("20.0.0.2") {
		t.Fatal("guard must adopt the manual block without losing its own")
	}
	got := readStateIPs(t, path)
	if len(got) != 2 {
		t.Fatalf("file should hold both IPs, got %v", got)
	}

	// Manual unban of the guard's own IP: memory must converge with the
	// file instead of resurrecting the rule on the next flush.
	if err := ManualUnban(path, "20.0.0.1", fb); err != nil {
		t.Fatal(err)
	}
	g.syncState()
	g.syncState() // second flush must not resurrect anything
	if g.IsBlocked("20.0.0.1") {
		t.Fatal("manual unban was not adopted into guard memory")
	}
	if fb.blocked["20.0.0.1"] {
		t.Fatal("firewall rule was resurrected after manual unban")
	}
	if got := readStateIPs(t, path); len(got) != 1 || got[0] != "20.0.0.2" {
		t.Fatalf("unexpected state after unban: %v", got)
	}
}

func TestGuardSyncPromotesTempToPermanent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	fb := newFakeBlocker()
	g := newReconcileGuard(t, path, fb, time.Hour)

	g.commitBlockDecisions([]Candidate{{IP: "21.0.0.1"}}, time.Now())
	g.mu.Lock()
	_, stillTemp := g.expiries["21.0.0.1"]
	g.mu.Unlock()
	if !stillTemp {
		t.Fatal("expected temporary ban in guard memory")
	}

	// External permanent decision for the same IP.
	if err := ManualBlock(path, "21.0.0.1", fb); err != nil {
		t.Fatal(err)
	}
	g.syncState()

	g.mu.Lock()
	_, hasExpiry := g.expiries["21.0.0.1"]
	g.mu.Unlock()
	if hasExpiry {
		t.Fatal("manual permanent block must clear the guard's expiry")
	}
	entries, _ := newStateFile(path).load()
	for _, e := range entries {
		if e.IP == "21.0.0.1" && !e.When.IsZero() {
			t.Fatalf("entry must be permanent, got %v", e.When)
		}
	}
}

func TestGuardExpiryLosesToConcurrentPermanentBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	fb := newFakeBlocker()
	g := newReconcileGuard(t, path, fb, time.Hour)

	now := time.Now()
	g.commitBlockDecisions([]Candidate{{IP: "22.0.0.1"}, {IP: "22.0.0.2"}}, now)

	// A manual permanent block for .1 lands before the expiry transaction.
	if err := ManualBlock(path, "22.0.0.1", fb); err != nil {
		t.Fatal(err)
	}
	if res := g.commitUnblockDecision("22.0.0.1", "expired", false); res != unblockRetained {
		t.Fatalf("external permanent block must retain the ban, got %v", res)
	}
	if !g.IsBlocked("22.0.0.1") || !fb.blocked["22.0.0.1"] {
		t.Fatal("retained ban must stay blocked in memory and firewall")
	}
	g.mu.Lock()
	_, hasExpiry := g.expiries["22.0.0.1"]
	g.mu.Unlock()
	if hasExpiry {
		t.Fatal("retained ban must be promoted to permanent")
	}

	// The other expiry commits normally.
	if res := g.commitUnblockDecision("22.0.0.2", "expired", false); res != unblockCommitted {
		t.Fatalf("normal expiry must commit, got %v", res)
	}
	if g.IsBlocked("22.0.0.2") || fb.blocked["22.0.0.2"] {
		t.Fatal("expired ban must be removed everywhere")
	}
	got := readStateIPs(t, path)
	if len(got) != 1 || got[0] != "22.0.0.1" {
		t.Fatalf("state = %v", got)
	}
}

func TestGuardExternalProtectedBlockRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	fb := newFakeBlocker()
	g := New(Config{
		Window: time.Minute, NeverBlock: []string{"23.0.0.1"},
		StatePath: path, Blocker: fb,
	})
	if err := ManualBlock(path, "23.0.0.1", fb); err != nil {
		t.Fatal(err)
	}
	if !fb.blocked["23.0.0.1"] {
		t.Fatal("setup: rule expected")
	}
	g.syncState()
	if g.IsBlocked("23.0.0.1") || fb.blocked["23.0.0.1"] {
		t.Fatal("external block of a protected address must be removed")
	}
	if got := readStateIPs(t, path); len(got) != 0 {
		t.Fatalf("protected entry must be purged: %v", got)
	}
}

func TestGuardExternalExpiredTempCleaned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	fb := newFakeBlocker()
	g := newReconcileGuard(t, path, fb, time.Hour)
	fb.blocked["24.0.0.1"] = true
	if err := newStateFile(path).saveEntries([]stateEntry{
		{IP: "24.0.0.1", When: time.Now().Add(-time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	g.syncState()
	if g.IsBlocked("24.0.0.1") || fb.blocked["24.0.0.1"] {
		t.Fatal("externally expired temporary ban must be cleaned")
	}
	if got := readStateIPs(t, path); len(got) != 0 {
		t.Fatalf("expired entry must be purged: %v", got)
	}
}

func TestEmptyStateFileAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var loadErr error
	g := New(Config{
		Window: time.Minute, StatePath: path,
		Blocker: newFakeBlocker(),
		OnError: func(err error) { loadErr = err },
	})
	if loadErr != nil {
		t.Fatalf("empty state file must not error: %v", loadErr)
	}
	if g.Count() != 0 {
		t.Fatalf("expected no blocks, got %d", g.Count())
	}
	b := newScriptedBlocker()
	if err := ManualBlock(path, "25.0.0.1", b); err != nil {
		t.Fatalf("block on empty file: %v", err)
	}
	if got := readStateIPs(t, path); len(got) != 1 || got[0] != "25.0.0.1" {
		t.Fatalf("state = %v", got)
	}
}

func TestCorruptStateFileBlocksManualDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	b := newScriptedBlocker()
	err := ManualBlock(path, "26.0.0.1", b)
	opErr := asOpErr(t, err)
	if opErr.Stage != "state-read" {
		t.Fatalf("expected state-read failure, got %+v", opErr)
	}
	if b.blockCalls != 0 {
		t.Fatal("firewall must not be touched when state cannot be read")
	}
	if err := ManualUnban(path, "26.0.0.1", b); err == nil {
		t.Fatal("unban must also fail on corrupt state")
	}
}

// TestGuardRunningVsManualOps hammers a running guard with manual
// operations and asserts firewall rules and persistent state never
// disagree after quiescence and shutdown.
func TestGuardRunningVsManualOps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	fb := newScriptedBlocker()
	cfg := Config{
		Limit: 1, AuthLimit: 10, NotFoundLimit: 50,
		Window:        20 * time.Millisecond,
		BlockDuration: 0, // permanent: decisions survive until unban
		StatePath:     path,
		Blocker:       fb,
		IPValidator:   func(string) error { return nil },
	}
	g := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	linesCh := make(chan string, 256)
	done := make(chan struct{})
	go func() {
		g.Run(ctx, linesCh, func(string, ...interface{}) {})
		close(done)
	}()

	// Guard-driven blocks.
	for i := 0; i < 30; i++ {
		linesCh <- caddyLine(fmt.Sprintf("30.0.0.%d", i), "/api", "GET", 200)
		linesCh <- caddyLine(fmt.Sprintf("30.0.0.%d", i), "/api", "GET", 200)
	}

	// Concurrent manual churn on a disjoint IP pool.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ip := fmt.Sprintf("31.%d.%d.%d", id, i/256, i%256)
				_ = ManualBlock(path, ip, fb)
				if i%3 == 0 {
					_ = ManualUnban(path, ip, fb)
				}
			}
		}(w)
	}
	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Let two windows pass without new traffic, then shut down.
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
	g.FlushState()

	// Persistent state must be valid JSON and exactly match the firewall.
	fileIPs := map[string]bool{}
	for _, ip := range readStateIPs(t, path) {
		fileIPs[ip] = true
	}
	rules := fb.snapshot()
	if len(fileIPs) != len(rules) {
		t.Fatalf("convergence mismatch: %d state entries vs %d firewall rules", len(fileIPs), len(rules))
	}
	for ip := range rules {
		if !fileIPs[ip] {
			t.Fatalf("firewall rule %s missing from state", ip)
		}
	}
	for ip := range fileIPs {
		if !rules[ip] {
			t.Fatalf("state entry %s missing firewall rule", ip)
		}
	}
}
