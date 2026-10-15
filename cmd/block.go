package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

var blockAuditLog string
var blockStateFile string
var blockNotify auditNotifyFlags

// systemBlocker is the real firewall backend shared by the manual
// block/unban commands.
var systemBlocker guard.SystemBlocker

var blockCmd = &cobra.Command{
	Use:   "block <ip> [ip...]",
	Short: "Block IP via iptables",
	Long: `Block one or more IPs via iptables.

Manual blocks are also written to the guard state file (if --state-file is
set) so they survive guard restarts. For each IP the firewall rule and the
persistent state are committed as one cross-process serialized decision:
success (and the audit event) is reported only after both stores agree. If
the state commit fails the new rule is rolled back; if rollback also fails
the IP is reported as not converged and the command exits non-zero.

Examples:
  caddy-analyze block 10.0.0.1
  caddy-analyze block 192.168.1.1 10.0.0.2
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("requires root: run with sudo")
		}
		blockNotify.auditLog = blockAuditLog
		dispatcher, err := blockNotify.dispatcher()
		if err != nil {
			return err
		}
		defer func() { _ = dispatcher.Close() }()
		failed := 0
		for _, ip := range args {
			if err := validateIP(ip); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
				failed++
				continue
			}
			if err := guard.ManualBlock(blockStateFile, ip, systemBlocker); err != nil {
				var opErr *guard.OpError
				if errors.As(err, &opErr) && opErr.Unconverged {
					fmt.Fprintf(os.Stderr, "  ✗ %s: NOT CONVERGED: %v\n", ip, err)
				} else {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
				}
				failed++
				continue
			}
			// Report and audit only after firewall rule and persistent
			// state are both committed.
			fmt.Printf("  ✓ %s blocked\n", ip)
			dispatcher.Log("block", ip, "manual block", "permanent")
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d IP(s) failed to converge", failed, len(args))
		}
		return nil
	},
}

func init() {
	blockCmd.Flags().StringVarP(&blockAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	blockNotify.addRest(blockCmd)
	blockCmd.Flags().StringVarP(&blockStateFile, "state-file", "", "/var/lib/caddy-analyzer/blocked.json", "Guard state file to sync manual blocks (empty to disable)")
	rootCmd.AddCommand(blockCmd)
}
