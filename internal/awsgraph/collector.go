package awsgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Rel  string `json:"rel"`
}

type Snapshot struct {
	Nodes          []Node `json:"nodes"`
	Edges          []Edge `json:"edges"`
	Neo4jUpserted  int    `json:"neo4j_upserted"`
	LeaseExtension bool   `json:"lease_extension"`
}

type Collector struct {
	ec2c         *ec2.Client
	iamc         *iam.Client
	neo4jHTTPURL string
	neo4jUser    string
	neo4jPass    string
	httpc        *http.Client
	maxRetries   int
	baseBackoff  time.Duration
	maxBackoff   time.Duration
	logger       *slog.Logger
}

func NewCollector(
	ctx context.Context,
	region, awsEndpoint, neo4jHTTPURL, neo4jUser, neo4jPass string,
	logger *slog.Logger,
) (*Collector, error) {
	if region == "" {
		region = "us-east-1"
	}
	if logger == nil {
		logger = slog.Default()
	}

	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if awsEndpoint != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var ec2Opts []func(*ec2.Options)
	var iamOpts []func(*iam.Options)
	if awsEndpoint != "" {
		ec2Opts = append(ec2Opts, func(o *ec2.Options) { o.BaseEndpoint = aws.String(awsEndpoint) })
		iamOpts = append(iamOpts, func(o *iam.Options) { o.BaseEndpoint = aws.String(awsEndpoint) })
	}

	return &Collector{
		ec2c:         ec2.NewFromConfig(cfg, ec2Opts...),
		iamc:         iam.NewFromConfig(cfg, iamOpts...),
		neo4jHTTPURL: strings.TrimRight(neo4jHTTPURL, "/"),
		neo4jUser:    neo4jUser,
		neo4jPass:    neo4jPass,
		httpc:        &http.Client{Timeout: 3 * time.Second},
		maxRetries:   4,
		baseBackoff:  100 * time.Millisecond,
		// Cap backoff at 2s so upstream throttling during bursts does not exceed HTTP handler timeout.
		maxBackoff: 2 * time.Second,
		logger:     logger,
	}, nil
}

func retryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		c := apiErr.ErrorCode()
		if c == "Throttling" || c == "ThrottlingException" || c == "RequestLimitExceeded" || c == "ServiceUnavailable" {
			return true
		}
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		code := respErr.HTTPStatusCode()
		if code == 429 || code == 502 || code == 503 || code == 504 {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "ThrottlingException") || strings.Contains(msg, "503")
}

func (c *Collector) doRetry(ctx context.Context, corrID, op string, fn func() error) error {
	var err error
	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !retryable(err) || attempt == c.maxRetries {
			return err
		}
		delay := time.Duration(float64(c.baseBackoff) * math.Pow(2, float64(attempt-1)))
		if delay > c.maxBackoff {
			delay = c.maxBackoff
		}
		c.logger.Warn("retrying aws call", "correlation_id", corrID, "op", op, "attempt", attempt, "delay_ms", delay.Milliseconds(), "err", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}

func (c *Collector) BuildAndSync(ctx context.Context, corrID string, incidentOverride bool) (Snapshot, error) {
	var vpcOut *ec2.DescribeVpcsOutput
	if err := c.doRetry(ctx, corrID, "ec2:DescribeVpcs", func() error {
		var e error
		vpcOut, e = c.ec2c.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
		return e
	}); err != nil {
		return Snapshot{}, fmt.Errorf("describe vpcs: %w", err)
	}

	var sgOut *ec2.DescribeSecurityGroupsOutput
	if err := c.doRetry(ctx, corrID, "ec2:DescribeSecurityGroups", func() error {
		var e error
		sgOut, e = c.ec2c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		return e
	}); err != nil {
		return Snapshot{}, fmt.Errorf("describe security groups: %w", err)
	}

	var rolesOut *iam.ListRolesOutput
	if err := c.doRetry(ctx, corrID, "iam:ListRoles", func() error {
		var e error
		rolesOut, e = c.iamc.ListRoles(ctx, &iam.ListRolesInput{})
		return e
	}); err != nil {
		return Snapshot{}, fmt.Errorf("list iam roles: %w", err)
	}

	var nodes []Node
	var edges []Edge

	for _, v := range vpcOut.Vpcs {
		if v.VpcId != nil {
			nodes = append(nodes, Node{ID: *v.VpcId, Kind: "VPC", Label: *v.VpcId})
		}
	}
	for _, sg := range sgOut.SecurityGroups {
		if sg.GroupId != nil {
			lbl := *sg.GroupId
			if sg.GroupName != nil && *sg.GroupName != "" {
				lbl = *sg.GroupName
			}
			nodes = append(nodes, Node{ID: *sg.GroupId, Kind: "SecurityGroup", Label: lbl})
			if sg.VpcId != nil && *sg.VpcId != "" {
				edges = append(edges, Edge{From: *sg.GroupId, To: *sg.VpcId, Rel: "IN_VPC"})
			}
		}
	}
	for _, r := range rolesOut.Roles {
		if r.Arn != nil {
			lbl := *r.Arn
			if r.RoleName != nil && *r.RoleName != "" {
				lbl = *r.RoleName
			}
			nodes = append(nodes, Node{ID: *r.Arn, Kind: "IAMRole", Label: lbl})
			for _, v := range vpcOut.Vpcs {
				if v.VpcId != nil {
					edges = append(edges, Edge{From: *r.Arn, To: *v.VpcId, Rel: "SCOPED_TO_VPC"})
				}
			}
		}
	}

	upserted := 0
	if c.neo4jHTTPURL != "" {
		n, err := c.pushNeo4j(ctx, nodes, edges)
		if err != nil {
			return Snapshot{}, fmt.Errorf("neo4j sync failed: %w", err)
		}
		upserted = n
	}

	return Snapshot{
		Nodes:          nodes,
		Edges:          edges,
		Neo4jUpserted:  upserted,
		LeaseExtension: incidentOverride,
	}, nil
}

func (c *Collector) pushNeo4j(ctx context.Context, nodes []Node, edges []Edge) (int, error) {
	type stmt struct {
		Statement  string         `json:"statement"`
		Parameters map[string]any `json:"parameters"`
	}
	var stmts []stmt
	for _, n := range nodes {
		stmts = append(stmts, stmt{
			Statement:  "MERGE (a:CloudAsset {id: $id}) SET a.kind = $kind, a.label = $label",
			Parameters: map[string]any{"id": n.ID, "kind": n.Kind, "label": n.Label},
		})
	}
	for _, e := range edges {
		stmts = append(stmts, stmt{
			Statement:  "MATCH (src:CloudAsset {id: $from}), (dst:CloudAsset {id: $to}) MERGE (src)-[r:RELATES {type: $rel}]->(dst)",
			Parameters: map[string]any{"from": e.From, "to": e.To, "rel": e.Rel},
		})
	}
	if len(stmts) == 0 {
		return 0, nil
	}

	body, err := json.Marshal(map[string]any{"statements": stmts})
	if err != nil {
		return 0, fmt.Errorf("marshal cypher statements: %w", err)
	}

	endpoint := c.neo4jHTTPURL + "/db/neo4j/tx/commit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build neo4j request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.neo4jUser != "" || c.neo4jPass != "" {
		req.SetBasicAuth(c.neo4jUser, c.neo4jPass)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post neo4j commit: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("neo4j commit status %d", resp.StatusCode)
	}
	return len(stmts), nil
}
