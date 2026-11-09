//go:build windows

package main

import (
	"os"
	"os/signal"
)

// shutdownSignals returns the signals that trigger graceful shutdown.
// Windows has no SIGTERM; only os.Interrupt (Ctrl+C) is available.
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// notifyShutdown registers the shutdown signals on ch.
func notifyShutdown(ch chan<- os.Signal) {
	signal.Notify(ch, shutdownSignals()...)
}
