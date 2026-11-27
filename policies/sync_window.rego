package graph.window

import rego.v1

default allow := false
default reason := "denied: sync outside UTC window without incident override"

# Incident override allows off-window graph refresh when an active incident id is provided
incident_override if {
	input.incident_override.enabled == true
	count(input.incident_override.incident_id) >= 5
	input.role in {"infra-sre", "security-engineer"}
}

allow if {
	incident_override
}

allow if {
	not incident_override
	input.role in {"infra-sre", "security-engineer", "sync-job"}
	input.utc_hour >= 4
	input.utc_hour <= 23
}

reason := "allowed via active incident override" if {
	allow
	incident_override
}

reason := "allowed within UTC sync window" if {
	allow
	not incident_override
}
