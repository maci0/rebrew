package jobs

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Handler exposes one configured owner's local API; it is not a tenant authorization boundary.
func (o *Owner) Handler(token string) (http.Handler, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("job token must contain at least 32 bytes")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodPost && r.URL.Path == "/jobs" {
			var in struct {
				Key             string `json:"key"`
				Seed            string `json:"seed"`
				WorkspaceSHA256 string `json:"workspace_sha256"`
				Generations     *int   `json:"generations"`
				Population      *int   `json:"population"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			dec.DisallowUnknownFields()
			if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
				http.Error(w, "invalid request", 400)
				return
			}
			credential := r.Header.Get("X-Rebrew-Compile-Credential")
			var saved Receipt
			var created bool
			var err error
			options := defaultMatchOptions
			if in.Generations != nil {
				options.Generations = *in.Generations
			}
			if in.Population != nil {
				options.Population = *in.Population
			}
			if credential != "" {
				saved, created, err = o.AdmitManagedTuned(in.Key, in.Seed, in.WorkspaceSHA256, credential, options)
			} else {
				saved, created, err = o.AdmitTuned(in.Key, in.Seed, in.WorkspaceSHA256, options)
			}
			if err != nil {
				http.Error(w, "admission refused", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if created {
				w.WriteHeader(http.StatusAccepted)
			}
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/jobs/") {
			http.NotFound(w, r)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/")
		if len(parts) > 2 {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "compile-intents" {
			intents, err := o.CompileIntents(id)
			if err != nil {
				http.Error(w, "managed job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(intents)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "compile-reconcile" {
			var in struct {
				Intent string `json:"intent"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			dec.DisallowUnknownFields()
			if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || !validHex(in.Intent, 64) {
				http.Error(w, "invalid request", 400)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
			defer cancel()
			if o.ReconcileCompile(ctx, id, in.Intent, r.Header.Get("X-Rebrew-Compile-Credential")) != nil {
				http.Error(w, "compile remains unresolved", 409)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "cancel" {
			saved, err := o.Cancel(id)
			if err != nil {
				http.Error(w, "job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "reconcile" {
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			saved, err := o.ReconcileDocker(ctx, id)
			if err != nil {
				http.Error(w, "stop remains unresolved", 409)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if r.Method == http.MethodGet && len(parts) == 1 {
			saved, err := o.Get(id)
			if err != nil {
				http.Error(w, "job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "output" {
			if _, err := o.Get(id); err != nil {
				http.Error(w, "job unavailable", 404)
				return
			}
			file, err := os.Open(filepath.Join(o.dir, id+".output"))
			if err != nil {
				http.Error(w, "output unavailable", 404)
				return
			}
			defer file.Close()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.Copy(w, io.LimitReader(file, outputLimit))
			return
		}
		if r.Method != http.MethodGet || len(parts) != 2 || parts[1] != "events" {
			http.NotFound(w, r)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unavailable", 500)
			return
		}
		o.mu.Lock()
		saved, err := o.read(id)
		if err != nil {
			o.mu.Unlock()
			http.Error(w, "job unavailable", 404)
			return
		}
		ch := make(chan struct{}, 1)
		if o.listeners[id] == nil {
			o.listeners[id] = map[chan struct{}]bool{}
		}
		o.listeners[id][ch] = true
		o.mu.Unlock()
		defer func() {
			o.mu.Lock()
			delete(o.listeners[id], ch)
			if len(o.listeners[id]) == 0 {
				delete(o.listeners, id)
			}
			o.mu.Unlock()
		}()
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(v Receipt) bool {
			b, e := json.Marshal(v)
			if e != nil {
				return false
			}
			controller := http.NewResponseController(w)
			if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				return false
			}
			if _, e = fmt.Fprintf(w, "data: %s\n\n", b); e != nil {
				return false
			}
			flusher.Flush()
			return true
		}
		if !send(saved) {
			return
		}
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ch:
				saved, err = o.Get(id)
				if err != nil || !send(saved) {
					return
				}
			}
		}
	}), nil
}
