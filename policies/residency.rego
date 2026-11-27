package graph.residency

import rego.v1

default allow := false
default reason := "denied: region outside approved boundary"

allowed_regions := {
	"us-gov": {"us-east-1", "us-west-2"},
	"standard": {"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"},
}

allow if {
	input.region in allowed_regions[input.boundary]
}

reason := "allowed: region permitted for boundary" if {
	allow
}
