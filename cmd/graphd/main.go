package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Adamson-lab/aws-neo4j-asset-graph/internal/awsgraph"
	"github.com/Adamson-lab/aws-neo4j-asset-graph/internal/policy"
	"github.com/Adamson-lab/aws-neo4j-asset-graph/internal/webhook"
)

type syncReq struct {
	CorrelationID    string                  `json:"correlation_id"`
	Role             string                  `json:"role"`
	Boundary         string                  `json:"boundary"`
	Region           string                  `json:"region"`
	IncidentOverride policy.IncidentOverride `json:"incident_override"`
}

type syncResp struct {
	CorrelationID string             `json:"correlation_id"`
	Status        string             `json:"status"`
	Reason        string             `json:"reason"`
	Snapshot      *awsgraph.Snapshot `json:"snapshot,omitempty"`
}

func probe(ctx context.Context, hc *http.Client, url string) bool {
	if url == "" {
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	awsEndpoint := envDefault("AWS_ENDPOINT_URL", "http://localhost:4566")
	awsRegion := envDefault("AWS_REGION", "us-east-1")
	opaURL := envDefault("OPA_URL", "http://localhost:8181")
	neo4jURL := envDefault("NEO4J_HTTP_URL", "http://localhost:7474")
	neo4jUser := envDefault("NEO4J_USER", "neo4j")
	neo4jPass := envDefault("NEO4J_PASSWORD", "localdevpassword")
	secret := envDefault("WEBHOOK_HMAC_SECRET", "local-dev-graph-secret")
	addr := envDefault("LISTEN_ADDR", ":8080")

	ctx := context.Background()
	col, err := awsgraph.NewCollector(ctx, awsRegion, awsEndpoint, neo4jURL, neo4jUser, neo4jPass, logger)
	if err != nil {
		logger.Error("init collector failed", "err", err)
		os.Exit(1)
	}

	auth := webhook.NewAuth(secret, 5*time.Minute)
	pol := policy.NewClient(opaURL, 3*time.Second)
	probeHC := &http.Client{Timeout: 2 * time.Second}
	nowUTC := func() time.Time { return time.Now().UTC() }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		pCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		lsOK := probe(pCtx, probeHC, awsEndpoint+"/_localstack/health")
		opaOK := probe(pCtx, probeHC, opaURL+"/health")
		neoOK := probe(pCtx, probeHC, neo4jURL)
		code := http.StatusOK
		status := "ok"
		if !lsOK || !opaOK || !neoOK {
			code = http.StatusServiceUnavailable
			status = "degraded"
		}
		writeJSON(w, code, map[string]any{
			"status":     status,
			"localstack": lsOK,
			"opa":        opaOK,
			"neo4j":      neoOK,
			"utc_time":   nowUTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("POST /v1/graph/sync", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body failed"})
			return
		}
		if err := auth.Verify(r.Header.Get("X-Signature-256"), r.Header.Get("X-Timestamp"), body); err != nil {
			logger.Warn("webhook auth rejected", "err", err.Error())
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		var req syncReq
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		corrID := req.CorrelationID
		if corrID == "" {
			corrID = r.Header.Get("X-Correlation-ID")
		}
		if corrID == "" {
			corrID = fmt.Sprintf("graph-%d", nowUTC().UnixNano())
		}
		if strings.TrimSpace(req.Boundary) == "" {
			req.Boundary = "standard"
		}
		if strings.TrimSpace(req.Region) == "" {
			req.Region = awsRegion
		}

		dec, err := pol.Check(r.Context(), policy.Input{
			CorrelationID:    corrID,
			Role:             req.Role,
			Boundary:         req.Boundary,
			Region:           req.Region,
			UTCHour:          nowUTC().Hour(),
			IncidentOverride: req.IncidentOverride,
		})
		if err != nil {
			logger.Error("opa check error", "correlation_id", corrID, "err", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "policy check failed"})
			return
		}
		if !dec.Allowed {
			logger.Info("graph sync denied", "correlation_id", corrID, "reason", dec.Reason)
			writeJSON(w, http.StatusForbidden, syncResp{
				CorrelationID: corrID,
				Status:        "denied",
				Reason:        dec.Reason,
			})
			return
		}

		snap, err := col.BuildAndSync(r.Context(), corrID, req.IncidentOverride.Enabled)
		if err != nil {
			logger.Error("graph sync failed", "correlation_id", corrID, "err", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}

		logger.Info("graph sync completed", "correlation_id", corrID, "nodes", len(snap.Nodes), "edges", len(snap.Edges))
		writeJSON(w, http.StatusOK, syncResp{
			CorrelationID: corrID,
			Status:        "synced",
			Reason:        dec.Reason,
			Snapshot:      &snap,
		})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("graphd listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	sCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sCtx)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
