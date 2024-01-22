package main

import "log"

// This function bootstrap the eBPF programs, load them in the kernel
// and wait to receive events from the kernel and then print it in the console
func hideDir(dirname string) {
	bpfManager, err := BootstrapBPF(dirname)

	if err != nil {
		log.Fatal("Failed to bootstrap BPF:", err)
		return
	}

	bpfManager.handlePerfEvent()

	bpfManager.waitUntilExitCall()
}
