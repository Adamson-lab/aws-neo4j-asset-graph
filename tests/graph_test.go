package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Adamson-lab/aws-neo4j-asset-graph/internal/awsgraph"
	"github.com/Adamson-lab/aws-neo4j-asset-graph/internal/policy"
	"github.com/Adamson-lab/aws-neo4j-asset-graph/internal/webhook"
)

func TestWebhookAuthAndReplayWindow(t *testing.T) {
	secret := "test-secret"
	a := webhook.NewAuth(secret, 5*time.Minute)
	body := []byte(`{"boundary":"us-gov","region":"us-east-1"}`)
	now := time.Now().UTC().Unix()

	sig := webhook.Sign([]byte(secret), now, body)
	if err := a.Verify(sig, strconv.FormatInt(now, 10), body); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
	if err := a.Verify("sha256=invalid", strconv.FormatInt(now, 10), body); !errors.Is(err, webhook.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
	oldTS := now - 400
	oldSig := webhook.Sign([]byte(secret), oldTS, body)
	if err := a.Verify(oldSig, strconv.FormatInt(oldTS, 10), body); !errors.Is(err, webhook.ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew, got %v", err)
	}
}

func TestPolicyResidencyAndOverride(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input policy.Input `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch r.URL.Path {
		case "/v1/data/graph/residency":
			ok := !(req.Input.Boundary == "us-gov" && req.Input.Region == "eu-central-1")
			_ = json.NewEncoder(w).Encode(map[string]any{"result": policy.Decision{Allowed: ok, Reason: "residency"}})
		case "/v1/data/graph/window":
			ok := (req.Input.UTCHour >= 4 && req.Input.UTCHour <= 23) || req.Input.IncidentOverride.Enabled
			_ = json.NewEncoder(w).Encode(map[string]any{"result": policy.Decision{Allowed: ok, Reason: "window"}})
		}
	}))
	defer opa.Close()

	pc := policy.NewClient(opa.URL, 2*time.Second)
	d1, err := pc.Check(context.Background(), policy.Input{Role: "infra-sre", Boundary: "us-gov", Region: "eu-central-1", UTCHour: 12})
	if err != nil || d1.Allowed {
		t.Fatalf("expected denial for us-gov in eu-central-1, got dec=%+v err=%v", d1, err)
	}

	d2, err := pc.Check(context.Background(), policy.Input{
		Role:     "infra-sre",
		Boundary: "us-gov",
		Region:   "us-east-1",
		UTCHour:  1,
		IncidentOverride: policy.IncidentOverride{
			Enabled:    true,
			IncidentID: "INC-771",
		},
	})
	if err != nil || !d2.Allowed {
		t.Fatalf("expected incident override allow off-hours, got dec=%+v err=%v", d2, err)
	}
}

func TestLiveContainersGraphSync(t *testing.T) {
	awsEP := os.Getenv("AWS_ENDPOINT_URL")
	opaEP := os.Getenv("OPA_URL")
	neoEP := os.Getenv("NEO4J_HTTP_URL")
	if awsEP == "" || opaEP == "" || neoEP == "" {
		t.Skip("container endpoints not set; skipping live integration test")
	}

	hc := &http.Client{Timeout: 2 * time.Second}
	if _, err := hc.Get(awsEP + "/_localstack/health"); err != nil {
		t.Skipf("localstack not reachable: %v", err)
	}
	if _, err := hc.Get(opaEP + "/health"); err != nil {
		t.Skipf("opa not reachable: %v", err)
	}
	if _, err := hc.Get(neoEP); err != nil {
		t.Skipf("neo4j not reachable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	col, err := awsgraph.NewCollector(ctx, "us-east-1", awsEP, neoEP, os.Getenv("NEO4J_USER"), os.Getenv("NEO4J_PASSWORD"), nil)
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}
	snap, err := col.BuildAndSync(ctx, "it-corr-1", false)
	if err != nil {
		t.Fatalf("BuildAndSync failed: %v", err)
	}
	if len(snap.Nodes) == 0 {
		t.Fatalf("expected at least default VPC/SG nodes from LocalStack")
	}
}

func BenchmarkAuthAndPolicy(b *testing.B) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": policy.Decision{Allowed: true, Reason: "ok"}})
	}))
	defer opa.Close()

	secret := "bench-secret"
	a := webhook.NewAuth(secret, 5*time.Minute)
	pc := policy.NewClient(opa.URL, 2*time.Second)
	body := []byte(`{"boundary":"standard","region":"us-east-1"}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts := time.Now().UTC().Unix()
		sig := webhook.Sign([]byte(secret), ts, body)
		if err := a.Verify(sig, strconv.FormatInt(ts, 10), body); err != nil {
			b.Fatal(err)
		}
		if _, err := pc.Check(ctx, policy.Input{Role: "sync-job", Boundary: "standard", Region: "us-east-1", UTCHour: 10}); err != nil {
			b.Fatal(err)
		}
	}
}
