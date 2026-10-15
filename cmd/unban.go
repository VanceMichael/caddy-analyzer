package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

var unbanCmd = &cobra.Command{
	Use:   "unban <ip> [ip...]",
	Short: "Remove IP from firewall",
	Long: `Remove one or more IPs from the firewall (iptables).

Manual unbans are also reflected in the guard state file (if --state-file
is set) so the guard does not re-block the IP on restart. For each IP the
firewall removal and the persistent state update are committed as one
cross-process serialized decision:
  - firewall removal failure keeps the original state untouched;
  - if the state commit fails after the rule was removed, protection is
    restored (or an explicit failure with the compensation result is
    returned);
  - any non-converged IP makes the command exit non-zero.
Removing an IP that is not blocked is a successful no-op (idempotent).

Examples:
  caddy-analyze unban 192.168.1.1
  caddy-analyze unban 10.0.0.1 10.0.0.2
  caddy-analyze unban --all
  caddy-analyze unban --list
`,
	RunE: runUnban,
}

var (
	unbanAll       bool
	unbanList      bool
	unbanAuditLog  string
	unbanStateFile string
	unbanNotify    auditNotifyFlags
)

func init() {
	unbanCmd.Flags().BoolVarP(&unbanAll, "all", "A", false, "Unblock all currently blocked IPs")
	unbanCmd.Flags().BoolVarP(&unbanList, "list", "l", false, "Show currently blocked IPs")
	unbanCmd.Flags().StringVarP(&unbanAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	unbanNotify.addRest(unbanCmd)
	unbanCmd.Flags().StringVarP(&unbanStateFile, "state-file", "", "/var/lib/caddy-analyzer/blocked.json", "Guard state file to sync manual unbans (empty to disable)")
	rootCmd.AddCommand(unbanCmd)
}

func runUnban(cmd *cobra.Command, args []string) error {
	if unbanAll && unbanList {
		return fmt.Errorf("--all and --list are mutually exclusive")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("requires root: run with sudo")
	}
	unbanNotify.auditLog = unbanAuditLog
	dispatcher, err := unbanNotify.dispatcher()
	if err != nil {
		return err
	}
	defer func() { _ = dispatcher.Close() }()
	if unbanList {
		return listBlocked()
	}
	if unbanAll {
		return unblockAll(dispatcher)
	}
	if len(args) == 0 {
		return fmt.Errorf("specify at least one IP to unblock, or use --all")
	}
	return unblockIPs(args, dispatcher)
}

func unblockIPs(ips []string, al interface {
	Log(string, string, string, string)
}) error {
	failed := 0
	for _, ip := range ips {
		if err := validateIP(ip); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			failed++
			continue
		}
		if err := guard.ManualUnban(unbanStateFile, ip, systemBlocker); err != nil {
			var opErr *guard.OpError
			if errors.As(err, &opErr) && opErr.Unconverged {
				fmt.Fprintf(os.Stderr, "  ✗ %s: NOT CONVERGED: %v\n", ip, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			}
			failed++
			continue
		}
		fmt.Printf("  ✓ %s unblocked\n", ip)
		if al != nil {
			al.Log("unblock", ip, "manual unban", "")
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d IP(s) failed to converge", failed, len(ips))
	}
	return nil
}

func unblockAll(al interface {
	Log(string, string, string, string)
}) error {
	ips, err := guard.ListBlockedIPs()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	return unblockIPs(ips, al)
}

func listBlocked() error {
	ips, err := guard.ListBlockedIPs()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	fmt.Println("Blocked IPs:")
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
	return nil
}
