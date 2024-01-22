//go:generate sh ../generate_bpf.sh
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "hide-pid",
	Short: "An eBPF proof of concept to show case how to hide any directory or PID on the linux kernel",
	Long: `The aim of this project is to demonstrate how to hide the existence of a PID or directory ` +
		`from a user by deleting its entry from the getdents64 syscall using eBPF.`,
	Example: "./bin/hide-pid [directory|PID]\n./bin/hide-pid myDir (or ./bin/hide-pid 1337)",
	Args:    cobra.MinimumNArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		hideDir(args[0])
	},
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
