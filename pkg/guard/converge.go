package guard

import (
	"fmt"
	"time"
)

// RuleExister is an optional Blocker capability used by the manual block
// transaction to decide whether it created the firewall rule itself. On a
// persistent-state failure the rule may only be rolled back when this
// transaction created it; pre-existing rules must never be removed.
type RuleExister interface {
	RuleExists(ip string) (bool, error)
}

// SystemBlocker adapts the package-level iptables/ip6tables operations for
// use by the manual block/unban commands.
type SystemBlocker struct{}

func (SystemBlocker) Block(ip string) error   { return BlockIP(ip) }
func (SystemBlocker) Unblock(ip string) error { return UnblockIP(ip) }
func (SystemBlocker) RuleExists(ip string) (bool, error) {
	return ruleExists(ip)
}

// OpError reports the outcome of a manual block/unban decision when the
// firewall and the persistent state could not be committed to the same
// result.
type OpError struct {
	// Op is "block" or "unban".
	Op string
	// IP is the target address.
	IP string
	// Stage is "state-read", "firewall" or "state-write".
	Stage string
	// Err is the failure at Stage.
	Err error
	// Compensation describes a successful compensating firewall action
	// ("rule removed" after a failed block commit, "rule restored" after
	// a failed unban commit). Empty when no compensation was attempted.
	Compensation string
	// CompensationErr is set when the compensating action also failed.
	CompensationErr error
	// Unconverged is true when firewall rules and persistent state now
	// disagree; an operator must reconcile.
	Unconverged bool
}

func (e *OpError) Error() string {
	msg := fmt.Sprintf("%s %s: %s: %v", e.Op, e.IP, e.Stage, e.Err)
	if e.Compensation != "" {
		msg += "; compensation: " + e.Compensation
	}
	if e.CompensationErr != nil {
		msg += fmt.Sprintf("; compensation failed: %v", e.CompensationErr)
	}
	if e.Unconverged {
		msg += "; STATE NOT CONVERGED: firewall rule and persistent state disagree"
	}
	return msg
}

// ManualBlock converges one permanent manual block across the firewall and
// the state file at path. The whole decision (read → validate → firewall →
// durable replace) runs under the cross-process state lock, so concurrent
// guard saves and other manual commands are serialized against it.
//
// Success (nil) means the firewall rule exists AND the state file records
// the block. On state-write failure the freshly added rule is rolled back;
// if rollback also fails the error is flagged Unconverged. No success is
// reported (and therefore no audit event must be emitted) on any error.
func ManualBlock(path, ip string, b Blocker) error {
	if b == nil {
		b = iptablesBlocker{}
	}
	if path == "" {
		if err := b.Block(ip); err != nil {
			return &OpError{Op: "block", IP: ip, Stage: "firewall", Err: err}
		}
		return nil
	}
	sf := newStateFile(path)
	return sf.withLock(func() error {
		entries, err := sf.loadLocked()
		if err != nil {
			return &OpError{Op: "block", IP: ip, Stage: "state-read", Err: err}
		}
		disk := entriesToMap(entries)
		_, tracked := disk[ip]

		// Determine whether the rule pre-existed so a later rollback only
		// removes what this call added. The state file tracking the IP is
		// sufficient evidence; otherwise ask the firewall when possible.
		preExists := tracked
		if !preExists {
			if rc, ok := b.(RuleExister); ok {
				exists, err := rc.RuleExists(ip)
				if err != nil {
					return &OpError{Op: "block", IP: ip, Stage: "firewall", Err: err}
				}
				preExists = exists
			}
		}

		if err := b.Block(ip); err != nil {
			// State untouched.
			return &OpError{Op: "block", IP: ip, Stage: "firewall", Err: err}
		}

		// Manual blocks are permanent; this also promotes a temporary
		// entry to permanent.
		disk[ip] = time.Time{}
		if err := sf.writeLocked(mapToEntries(disk)); err != nil {
			if preExists {
				// The rule existed before this call: do not remove it,
				// but the file commit failed — the two stores disagree.
				return &OpError{Op: "block", IP: ip, Stage: "state-write", Err: err, Unconverged: true}
			}
			if rbErr := b.Unblock(ip); rbErr != nil {
				return &OpError{Op: "block", IP: ip, Stage: "state-write", Err: err,
					CompensationErr: rbErr, Unconverged: true}
			}
			return &OpError{Op: "block", IP: ip, Stage: "state-write", Err: err,
				Compensation: "newly added firewall rule removed"}
		}
		return nil
	})
}

// ManualUnban converges one manual unban across the firewall and the state
// file at path. The firewall removal is idempotent (an already absent rule
// is success). When the firewall removal fails the state file is kept
// untouched. When the firewall removal succeeds but the durable state
// update fails, protection is restored by re-adding the rule; if that
// compensation also fails the error is flagged Unconverged.
func ManualUnban(path, ip string, b Blocker) error {
	if b == nil {
		b = iptablesBlocker{}
	}
	if path == "" {
		if err := b.Unblock(ip); err != nil {
			return &OpError{Op: "unban", IP: ip, Stage: "firewall", Err: err}
		}
		return nil
	}
	sf := newStateFile(path)
	return sf.withLock(func() error {
		entries, err := sf.loadLocked()
		if err != nil {
			return &OpError{Op: "unban", IP: ip, Stage: "state-read", Err: err}
		}
		disk := entriesToMap(entries)
		_, tracked := disk[ip]

		if err := b.Unblock(ip); err != nil {
			// Keep the original state; nothing was deleted.
			return &OpError{Op: "unban", IP: ip, Stage: "firewall", Err: err}
		}

		if !tracked {
			// Rule gone (or was already gone) and nothing tracked it:
			// idempotent repeat, no file change needed.
			return nil
		}
		delete(disk, ip)
		if err := sf.writeLocked(mapToEntries(disk)); err != nil {
			if rbErr := b.Block(ip); rbErr != nil {
				return &OpError{Op: "unban", IP: ip, Stage: "state-write", Err: err,
					CompensationErr: rbErr, Unconverged: true}
			}
			return &OpError{Op: "unban", IP: ip, Stage: "state-write", Err: err,
				Compensation: "firewall rule restored to keep protection"}
		}
		return nil
	})
}

// mergeBlockState performs a three-way merge keyed by IP. Values are ban
// expiries; the zero time means permanent.
//
//	base: the last on-disk view the guard observed and committed
//	disk: the current file contents (manual block/unban commits land here)
//	mem:  the guard's current in-memory intent
//
// Rules:
//   - guard unchanged (mem == base for an IP): disk wins, so manual adds
//     and deletes are adopted verbatim;
//   - guard deleted (in base, absent in mem): the deletion propagates
//     unless the disk entry was itself changed since base, in which case
//     the newer external decision wins;
//   - guard changed (mem differs from base): the guard decision wins
//     unless the disk entry was also changed, then the stronger/longer
//     ban wins (a permanent manual block always outranks a temporary one);
//   - brand-new guard decisions (absent in base) merge with concurrent
//     external additions using the same stronger/longer rule.
func mergeBlockState(base, disk, mem map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(mem)+len(disk))
	seen := make(map[string]bool, len(mem)+len(disk))
	for ip := range base {
		seen[ip] = true
	}
	for ip := range disk {
		seen[ip] = true
	}
	for ip := range mem {
		seen[ip] = true
	}
	for ip := range seen {
		bv, bOk := base[ip]
		dv, dOk := disk[ip]
		mv, mOk := mem[ip]
		switch {
		case !bOk:
			switch {
			case mOk && dOk:
				out[ip] = strongerBan(mv, dv)
			case mOk:
				out[ip] = mv
			case dOk:
				out[ip] = dv
			}
		case !mOk:
			// Guard deleted its own decision; an external modification
			// since base supersedes the deletion.
			if dOk && !dv.Equal(bv) {
				out[ip] = dv
			}
		case !mv.Equal(bv):
			if dOk && !dv.Equal(bv) {
				out[ip] = strongerBan(mv, dv)
			} else {
				out[ip] = mv
			}
		default:
			// Guard holds the same intent as at base: disk is authoritative.
			if dOk {
				out[ip] = dv
			}
		}
	}
	return out
}

// strongerBan returns the more protective of two ban expiries: a permanent
// ban (zero time) always wins, otherwise the later expiry wins.
func strongerBan(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if a.After(b) {
		return a
	}
	return b
}

// AddPermanentBlockToState records ip as a permanent block in the state
// file at path. File-only helper; manual commands should use ManualBlock
// so the firewall decision and persistence converge. Idempotent.
func AddPermanentBlockToState(path, ip string) error {
	if path == "" {
		return nil
	}
	sf := newStateFile(path)
	return sf.withLock(func() error {
		entries, err := sf.loadLocked()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IP == ip {
				return nil
			}
		}
		entries = append(entries, stateEntry{IP: ip, When: time.Time{}})
		return sf.writeLocked(entries)
	})
}

// RemoveBlockFromState removes ip from the state file at path. File-only
// helper; manual commands should use ManualUnban so the firewall decision
// and persistence converge.
func RemoveBlockFromState(path, ip string) error {
	if path == "" {
		return nil
	}
	sf := newStateFile(path)
	return sf.withLock(func() error {
		entries, err := sf.loadLocked()
		if err != nil {
			return err
		}
		out := entries[:0]
		for _, e := range entries {
			if e.IP != ip {
				out = append(out, e)
			}
		}
		return sf.writeLocked(out)
	})
}
