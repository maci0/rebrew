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
	log.Fatal(http.Serve(ln, h))
}
