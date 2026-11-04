// Command rebrew-jobs serves one local workspace's durable job owner.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	jobs "github.com/relumea/rebrew/services/jobs"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "workspace-digest" {
		digest, err := jobs.WorkspaceDigest(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(digest)
		return
	}
	if len(os.Args) != 1 {
		log.Fatal("usage: rebrew-jobs [workspace-digest PATH]")
	}
	var o *jobs.Owner
	var err error
	if image := os.Getenv("REBREW_JOB_DOCKER_IMAGE"); image != "" {
		o, err = jobs.OpenDocker(os.Getenv("REBREW_WORKSPACE"), os.Getenv("REBREW_JOB_DIR"), jobs.DockerProvider{Binary: os.Getenv("REBREW_DOCKER_BINARY"), Image: image})
	} else {
		o, err = jobs.Open(os.Getenv("REBREW_WORKSPACE"), os.Getenv("REBREW_JOB_DIR"), os.Getenv("REBREW_BINARY"))
	}
	if err != nil {
		log.Fatal(err)
	}
	defer o.Close()
	if upstream := os.Getenv("REBREW_MANAGED_RECOMPILE_URL"); upstream != "" {
		max, err := strconv.Atoi(os.Getenv("REBREW_MANAGED_COMPILE_LIMIT"))
		if err != nil {
			log.Fatal("invalid managed compile limit")
		}
		if err := o.ConfigureManagedCompile(upstream, max, strings.Split(os.Getenv("REBREW_MANAGED_COMPILERS"), ",")); err != nil {
			log.Fatal(err)
		}
	}
	h, err := o.Handler(os.Getenv("REBREW_JOB_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("REBREW_JOBS_ADDR")
	if addr != "" && !strings.HasPrefix(addr, "127.0.0.1:") && !strings.HasPrefix(addr, "[::1]:") && !strings.HasPrefix(addr, "localhost:") {
		log.Println("warning: rebrew-jobs bound to non-loopback address;", addr)
	}
	if addr == "" {
		addr = "127.0.0.1:8089"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	// Bounded timeouts (mirroring the compile mediator's socket server) keep
	// a slow or idle loopback client from holding a connection forever; the
	// streaming /events handler sets its own write deadline per frame.
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 180 * time.Second}
	// Graceful shutdown on SIGTERM/SIGINT so Close() drains queued work
	// instead of the process being killed mid-receipt.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	log.Fatal(server.Serve(ln))
}
