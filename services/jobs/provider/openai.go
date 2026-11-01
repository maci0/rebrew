// Package provider calls an existing OpenAI-compatible chat API. The caller
// owns admission, credential selection, durable settlement and reconciliation.
package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid provider request")

// ErrUncertain means a request may have reached the provider; billing and
// physical cancellation are unknown and the owner must reconcile, not retry.
var ErrUncertain = errors.New("provider outcome requires reconciliation")

type Request struct {
	Model         string          `json:"model"`
	Messages      json.RawMessage `json:"messages"`
	Temperature   *float64        `json:"temperature,omitempty"`
	MaxTokens     int             `json:"max_tokens"`
	Tools         json.RawMessage `json:"tools,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
	StreamOptions json.RawMessage `json:"stream_options,omitempty"`
}
type Usage struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	TotalTokens      *int64 `json:"total_tokens"`
}
type Result struct {
	Body  json.RawMessage
	Usage *Usage
}
type Client struct {
	endpoint, key           string
	http                    *http.Client
	maxRequest, maxResponse int
	timeout                 time.Duration
}

// New requires an explicitly configured endpoint and caller-scoped credential.
// HTTP and HTTPS match the existing provider contract; redirects are refused.
func New(endpoint, key string, timeout time.Duration, maxRequest, maxResponse int) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || timeout <= 0 || timeout > 10*time.Minute || maxRequest < 1 || maxRequest > 16<<20 || maxResponse < 1 || maxResponse > 16<<20 {
		return nil, ErrInvalid
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, ErrInvalid
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/embeddings")
	if !strings.HasSuffix(u.Path, "/chat/completions") {
		u.Path += "/chat/completions"
	}
	return &Client{endpoint: u.String(), key: key, timeout: timeout, maxRequest: maxRequest, maxResponse: maxResponse, http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Complete makes one request only. An admitted caller must durably record its
// intent before calling and settle provider usage when present; absent usage is
// unknown, never zero. onEvent receives raw JSON chunks for streamed responses.
func (c *Client) Complete(ctx context.Context, admitted bool, request Request, onEvent func(json.RawMessage) error) (Result, error) {
	messages := bytes.TrimSpace(request.Messages)
	if !admitted || request.Model == "" || request.MaxTokens < 1 || request.MaxTokens > 65536 || len(messages) == 0 || !json.Valid(messages) || messages[0] != '[' || request.Stream != (onEvent != nil) {
		return Result{}, ErrInvalid
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > c.maxRequest {
		return Result{}, ErrInvalid
	}
	callctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, ErrUncertain
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, ErrUncertain
	}
	if request.Stream {
		return c.stream(resp.Body, onEvent)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.maxResponse)+1))
	if err != nil || len(raw) > c.maxResponse || !json.Valid(raw) {
		return Result{}, ErrUncertain
	}
	var envelope struct {
		Choices []json.RawMessage `json:"choices"`
		Usage   *Usage            `json:"usage"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Choices) == 0 || !validUsage(envelope.Usage) {
		return Result{}, ErrUncertain
	}
	return Result{Body: raw, Usage: envelope.Usage}, nil
}

func validUsage(u *Usage) bool {
	if u == nil {
		return true
	}
	for _, n := range []*int64{u.PromptTokens, u.CompletionTokens, u.TotalTokens} {
		if n != nil && *n < 0 {
			return false
		}
	}
	return true
}

func (c *Client) stream(body io.Reader, onEvent func(json.RawMessage) error) (Result, error) {
	scanner := bufio.NewScanner(io.LimitReader(body, int64(c.maxResponse)+1))
	scanner.Buffer(make([]byte, 4096), c.maxResponse+1)
	total := 0
	done := false
	sawChoice := false
	var usage *Usage
	var data []string
	flush := func() error {
		if len(data) == 0 {
			return nil
		}
		s := strings.Join(data, "\n")
		data = nil
		if s == "[DONE]" {
			done = true
			return nil
		}
		raw := json.RawMessage(s)
		if !json.Valid(raw) {
			return ErrUncertain
		}
		var item struct {
			Choices []json.RawMessage `json:"choices"`
			Error   json.RawMessage   `json:"error"`
			Usage   *Usage            `json:"usage"`
		}
		if json.Unmarshal(raw, &item) != nil || len(item.Error) > 0 && string(item.Error) != "null" || !validUsage(item.Usage) {
			return ErrUncertain
		}
		if len(item.Choices) > 0 {
			sawChoice = true
		}
		if item.Usage != nil {
			usage = item.Usage
		}
		if onEvent(raw) != nil {
			return ErrUncertain
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > c.maxResponse {
			return Result{}, ErrUncertain
		}
		if line == "" {
			if flush() != nil {
				return Result{}, ErrUncertain
			}
			if done {
				break
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if scanner.Err() != nil || !done || !sawChoice {
		return Result{}, ErrUncertain
	}
	return Result{Usage: usage}, nil
}
