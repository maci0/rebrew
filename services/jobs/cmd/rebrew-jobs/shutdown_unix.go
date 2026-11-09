//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// shutdownSignals returns the signals that trigger graceful shutdown.
// SIGTERM is the standard container/systemd stop signal and must drain
// queued work like SIGINT does; both are delivered on Unix.
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// notifyShutdown registers the shutdown signals on ch.
func notifyShutdown(ch chan<- os.Signal) {
	signal.Notify(ch, shutdownSignals()...)
}
