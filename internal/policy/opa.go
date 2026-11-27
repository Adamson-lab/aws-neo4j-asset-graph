package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type IncidentOverride struct {
	Enabled    bool   `json:"enabled"`
	IncidentID string `json:"incident_id"`
}

type Input struct {
	CorrelationID    string           `json:"correlation_id"`
	Role             string           `json:"role"`
	Boundary         string           `json:"boundary"`
	Region           string           `json:"region"`
	UTCHour          int              `json:"utc_hour"`
	IncidentOverride IncidentOverride `json:"incident_override"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type opaResp struct {
	Result *Decision `json:"result"`
}

type Client struct {
	baseURL string
	httpc   *http.Client
}

func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpc:   &http.Client{Timeout: timeout},
	}
}

func (c *Client) Check(ctx context.Context, in Input) (Decision, error) {
	resDec, err := c.evalPath(ctx, "/v1/data/graph/residency", in)
	if err != nil {
		return Decision{}, fmt.Errorf("residency policy check failed: %w", err)
	}
	if !resDec.Allowed {
		return resDec, nil
	}
	winDec, err := c.evalPath(ctx, "/v1/data/graph/window", in)
	if err != nil {
		return Decision{}, fmt.Errorf("sync window policy check failed: %w", err)
	}
	return winDec, nil
}

func (c *Client) evalPath(ctx context.Context, path string, in Input) (Decision, error) {
	raw, err := json.Marshal(map[string]any{"input": in})
	if err != nil {
		return Decision{}, fmt.Errorf("marshal policy input: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return Decision{}, fmt.Errorf("create opa request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if in.CorrelationID != "" {
		req.Header.Set("X-Correlation-ID", in.CorrelationID)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("opa request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("opa status %d", resp.StatusCode)
	}
	var out opaResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Decision{}, fmt.Errorf("decode opa response: %w", err)
	}
	if out.Result == nil {
		return Decision{}, fmt.Errorf("missing opa result")
	}
	return *out.Result, nil
}
