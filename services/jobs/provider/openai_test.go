package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func baseRequest() Request {
	return Request{Model: "fixture-model", Messages: json.RawMessage(`[{"role":"user","content":"fixture"}]`), MaxTokens: 32}
}
func TestCompleteAndUsage(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer fixture-key" {
			t.Error("request differs")
		}
		fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":2}}`)
	}))
	defer s.Close()
	c, e := New(s.URL+"/v1", "fixture-key", time.Second, 4096, 4096)
	if e != nil {
		t.Fatal(e)
	}
	out, e := c.Complete(context.Background(), true, baseRequest(), nil)
	if e != nil || out.Usage == nil || *out.Usage.PromptTokens != 7 || *out.Usage.CompletionTokens != 2 || calls.Load() != 1 {
		t.Fatal("completion/usage differs", e)
	}
}
func TestStreamUsageAndTruncation(t *testing.T) {
	for _, complete := range []bool{true, false} {
		t.Run(fmt.Sprint(complete), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n")
				if complete {
					fmt.Fprint(w, "data: [DONE]\n\n")
				}
			}))
			defer s.Close()
			c, _ := New(s.URL, "", time.Second, 4096, 4096)
			q := baseRequest()
			q.Stream = true
			events := 0
			out, e := c.Complete(context.Background(), true, q, func(json.RawMessage) error { events++; return nil })
			if complete {
				if e != nil || events != 2 || out.Usage == nil || *out.Usage.CompletionTokens != 1 {
					t.Fatal("stream differs", e)
				}
			} else if !errors.Is(e, ErrUncertain) {
				t.Fatal("truncated stream accepted")
			}
		})
	}
}
func TestAdmissionBoundsAndNoRetry(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
		fmt.Fprint(w, "fixture-secret")
	}))
	defer s.Close()
	c, _ := New(s.URL, "fixture-secret", time.Second, 4096, 4096)
	if _, e := c.Complete(context.Background(), false, baseRequest(), nil); !errors.Is(e, ErrInvalid) || calls.Load() != 0 {
		t.Fatal("unadmitted call dispatched")
	}
	_, e := c.Complete(context.Background(), true, baseRequest(), nil)
	if !errors.Is(e, ErrUncertain) || calls.Load() != 1 || strings.Contains(e.Error(), "fixture-secret") {
		t.Fatal("failed call was retried or leaked")
	}
}
func TestTimeoutAndResponseLimitAreUncertain(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		fmt.Fprint(w, `{"value":"`+strings.Repeat("x", 200)+`"}`)
	}))
	defer s.Close()
	c, _ := New(s.URL, "", 5*time.Millisecond, 4096, 128)
	if _, e := c.Complete(context.Background(), true, baseRequest(), nil); !errors.Is(e, ErrUncertain) {
		t.Fatal("timeout not uncertain")
	}
	c, _ = New(s.URL, "", time.Second, 4096, 128)
	if _, e := c.Complete(context.Background(), true, baseRequest(), nil); !errors.Is(e, ErrUncertain) {
		t.Fatal("oversize accepted")
	}
}
func TestEndpointRestriction(t *testing.T) {
	if _, e := New("http://example.test/v1", "", time.Second, 1, 1); e != nil {
		t.Fatal("configured HTTP endpoint refused")
	}
	if _, e := New("https://user:secret@example.test/v1", "", time.Second, 1, 1); !errors.Is(e, ErrInvalid) {
		t.Fatal("embedded credentials allowed")
	}
}

func TestMissingUsageAndInvalidResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"missing usage", `{"choices":[{"message":{"content":"ok"}}]}`, true},
		{"provider error in success", `{"error":{"message":"fixture-secret"}}`, false},
		{"negative usage", `{"choices":[{}],"usage":{"prompt_tokens":-1}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("unexpected authorization")
				}
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			c, _ := New(s.URL, "", time.Second, 4096, 4096)
			out, err := c.Complete(context.Background(), true, baseRequest(), nil)
			if tc.valid {
				if err != nil || out.Usage != nil {
					t.Fatal("missing usage must stay unknown")
				}
			} else if !errors.Is(err, ErrUncertain) || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("invalid response accepted or leaked")
			}
		})
	}
}
func TestRedirectNeverForwardsCredential(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c, _ := New(source.URL, "fixture-key", time.Second, 4096, 4096)
	if _, err := c.Complete(context.Background(), true, baseRequest(), nil); !errors.Is(err, ErrUncertain) || leaked.Load() {
		t.Fatal("redirect followed or result accepted")
	}
}

func TestStreamErrorAndConsumerCancellationRemainUncertain(t *testing.T) {
	for _, body := range []string{"data: {\"error\":{\"message\":\"fixture-secret\"}}\n\ndata: [DONE]\n\n", "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n"} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c, _ := New(s.URL, "", time.Second, 4096, 4096)
		q := baseRequest()
		q.Stream = true
		_, err := c.Complete(context.Background(), true, q, func(json.RawMessage) error { return errors.New("caller stopped") })
		s.Close()
		if !errors.Is(err, ErrUncertain) || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("stream error or cancellation accepted")
		}
	}
}

func TestConfigurationBounds(t *testing.T) {
	for _, tc := range []struct {
		timeout           time.Duration
		request, response int
	}{{time.Second, 1 << 30, 10}, {time.Second, 10, 1 << 30}, {11 * time.Minute, 10, 10}} {
		if _, err := New("https://example.test/v1", "", tc.timeout, tc.request, tc.response); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe limit accepted")
		}
	}
}

func TestEndpointNormalization(t *testing.T) {
	for _, path := range []string{"/v1", "/v1/chat/completions", "/v1/embeddings/"} {
		c, err := New("http://example.test"+path, "", time.Second, 100, 100)
		if err != nil || c.endpoint != "http://example.test/v1/chat/completions" {
			t.Fatal("endpoint normalization differs")
		}
	}
}
