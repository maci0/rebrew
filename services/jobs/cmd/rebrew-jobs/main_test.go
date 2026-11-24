package main

import (
	"net/http"
	"os"
	"testing"
)

func TestServeJobsReturnsAfterGracefulShutdown(t *testing.T) {
	shutdown := make(chan os.Signal, 1)
	shutdown <- os.Interrupt
	err := serveJobs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "127.0.0.1:0", shutdown)
	if err != nil {
		t.Fatalf("graceful shutdown returned a server error: %v", err)
	}
}
