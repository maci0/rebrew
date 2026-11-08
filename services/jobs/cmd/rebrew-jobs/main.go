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

// isLoopbackAddr reports whether addr binds a loopback interface only:
//
//	127.0.0.1:<port>, [::1]:<port>, localhost:<port>
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

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
	// Fail fast on missing required env vars: the README names workspace, job
	// dir and token (≥32 bytes, checked in Handler) as required, and the
	// token/workspaces are passed as empty strings to Open/OpenDocker if unset,
	// which would otherwise surface as a confusing downstream error.
	for _, name := range []string{"REBREW_WORKSPACE", "REBREW_JOB_DIR"} {
		if os.Getenv(name) == "" {
			log.Fatalf("%s is required", name)
		}
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
		limitRaw := os.Getenv("REBREW_MANAGED_COMPILE_LIMIT")
		compilersRaw := os.Getenv("REBREW_MANAGED_COMPILERS")
		if limitRaw == "" {
			log.Fatal("REBREW_MANAGED_COMPILE_LIMIT is required with REBREW_MANAGED_RECOMPILE_URL")
		}
		if compilersRaw == "" {
			log.Fatal("REBREW_MANAGED_COMPILERS is required with REBREW_MANAGED_RECOMPILE_URL")
		}
		max, err := strconv.Atoi(limitRaw)
		if err != nil {
			log.Fatalf("invalid REBREW_MANAGED_COMPILE_LIMIT %q: %v", limitRaw, err)
		}
		compilers := strings.Split(compilersRaw, ",")
		for i, c := range compilers {
			compilers[i] = strings.TrimSpace(c)
			if compilers[i] == "" {
				log.Fatal("REBREW_MANAGED_COMPILERS must list at least one compiler")
			}
		}
		if err := o.ConfigureManagedCompile(upstream, max, compilers); err != nil {
			log.Fatal(err)
		}
	}
	h, err := o.Handler(os.Getenv("REBREW_JOB_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("REBREW_JOBS_ADDR")
	if addr != "" && !isLoopbackAddr(addr) {
		log.Fatalf("refusing non-loopback REBREW_JOBS_ADDR %q: rebrew-jobs is a local-only owner", addr)
	}
	if addr == "" {
		addr = "127.0.0.1:8089"
	}
	log.Printf("server_starting addr=%q managed=%v", addr, os.Getenv("REBREW_MANAGED_RECOMPILE_URL") != "")
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
		signal.Stop(sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	log.Fatal(server.Serve(ln))
}
