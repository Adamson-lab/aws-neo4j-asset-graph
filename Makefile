SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down run test bench lint tidy

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

tidy:
	go mod tidy

lint:
	gofmt -l .
	go vet ./...

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	NEO4J_HTTP_URL=http://localhost:7474 \
	NEO4J_USER=neo4j \
	NEO4J_PASSWORD=localdevpassword \
	WEBHOOK_HMAC_SECRET=local-dev-graph-secret \
	go run ./cmd/graphd

test:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	NEO4J_HTTP_URL=http://localhost:7474 \
	NEO4J_USER=neo4j \
	NEO4J_PASSWORD=localdevpassword \
	WEBHOOK_HMAC_SECRET=local-dev-graph-secret \
	go test -v -race ./...

bench:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	NEO4J_HTTP_URL=http://localhost:7474 \
	NEO4J_USER=neo4j \
	NEO4J_PASSWORD=localdevpassword \
	WEBHOOK_HMAC_SECRET=local-dev-graph-secret \
	go test -bench=. -benchmem ./tests/...
