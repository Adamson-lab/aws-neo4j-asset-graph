# Design Notes: AWS Cloud Asset Graph in Neo4j

This service queries AWS EC2 VPCs, EC2 security groups, and IAM roles through `aws-sdk-go-v2`, checks residency and sync-window policies in Open Policy Agent (OPA), and merges nodes and edges into Neo4j over its transactional HTTP endpoint.

## Sequence and Failure Handling

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller
    participant Graphd as Go graphd :8080
    participant OPA as OPA :8181
    participant AWS as LocalStack :4566
    participant Neo4j as Neo4j :7687 / :7474

    Caller->>Graphd: POST /v1/graph/sync (X-Timestamp, X-Signature-256)
    Graphd->>Graphd: Verify HMAC-SHA256 and UTC timestamp skew
    alt Invalid signature or stale timestamp
        Graphd-->>Caller: 401 Unauthorized
    else Signature valid
        Graphd->>OPA: POST /v1/data/graph/residency and /v1/data/graph/window
        alt OPA unreachable or non-200
            Graphd-->>Caller: 502 Bad Gateway
        else Boundary or UTC window denied
            Graphd-->>Caller: 403 Forbidden
        else Policy allowed
            Graphd->>AWS: DescribeVpcs, DescribeSecurityGroups, ListRoles
            Note over Graphd,AWS: Retry up to 4 times with backoff (100ms..2s) on ThrottlingException or 503
            Graphd->>Neo4j: POST /db/neo4j/tx/commit (MERGE CloudAsset + RELATES)
            Neo4j-->>Graphd: Commit OK
            Graphd-->>Caller: 200 OK
        end
    end
```

## Sync Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Incoming
    Incoming --> AuthFailed: Bad HMAC or clock skew > 5m
    Incoming --> CheckingPolicy: Signature valid
    CheckingPolicy --> Denied: Residency or UTC window rejected
    CheckingPolicy --> QueryingAWS: Policy allowed
    QueryingAWS --> Retrying: ThrottlingException or HTTP 503
    Retrying --> QueryingAWS: Retry attempt < 4
    QueryingAWS --> SyncingNeo4j: AWS snapshot collected
    SyncingNeo4j --> Completed: Cypher MERGE committed
    SyncingNeo4j --> Failed: Neo4j HTTP error
    AuthFailed --> [*]
    Denied --> [*]
    Failed --> [*]
    Completed --> [*]
```

## Edge Cases and Limitations

Timestamps and sync windows use UTC (`time.Now().UTC()`) so Daylight Saving Time changes do not shift allowed hours. When `incident_override.enabled` is true with an `incident_id` of at least 5 characters, off-window syncs are permitted and `lease_extension` is recorded as true on the snapshot. AWS API retries cap per-step backoff at 2s so webhook callers do not hit client read timeouts during rate-limit bursts.

Current limitations: `pushNeo4j` posts batched Cypher statements to Neo4j's HTTP transaction endpoint rather than maintaining a persistent Bolt connection pool, and `ListRoles` does not paginate beyond the initial AWS response page.
