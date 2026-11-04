// Command rebrew-jobs serves one local workspace's durable job owner.
package main

import (
	"fmt"
	jobs "github.com/relumea/rebrew/services/jobs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
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
	ln, err := net.Listen("tcp", "127.0.0.1:8089")
	if err != nil {
		log.Fatal(err)
	}
	// Explicit timeouts, matching the compile mediator's socket server:
	// without ReadHeaderTimeout a slow-loris client can hold a connection
	// forever, and without WriteTimeout a stalled client can block a job
	// dispatch past the request's own context. WriteTimeout is generous
	// by design: reconcile and SSE follow handlers run past 150s.
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 180 * time.Second}
	log.Fatal(srv.Serve(ln))
}
