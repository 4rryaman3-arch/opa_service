package system.authz_test

import data.system.authz

tok := "0123456789abcdef0123456789abcdef-test-token"

env := {"env": {"OPA_AUTH_TOKEN": tok}, "version": "test"}

test_decision_query_allowed if {
	authz.allow with input as {"method": "POST", "path": ["v1", "data", "securden", "rules", "x", "decision"], "identity": tok}
		with opa.runtime as env
}

test_health_allowed if {
	authz.allow with input as {"method": "GET", "path": ["health"], "identity": tok} with opa.runtime as env
}

test_wrong_token_denied if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "securden"], "identity": "nope"}
		with opa.runtime as env
}

test_policy_mutation_denied if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "evil"], "identity": tok} with opa.runtime as env
	not authz.allow with input as {"method": "PUT", "path": ["v1", "data", "securden"], "identity": tok} with opa.runtime as env
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "data", "securden"], "identity": tok} with opa.runtime as env
	not authz.allow with input as {"method": "PATCH", "path": ["v1", "data", "securden"], "identity": tok} with opa.runtime as env
}

test_other_endpoints_denied if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "query"], "identity": tok} with opa.runtime as env
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "system"], "identity": tok} with opa.runtime as env
	not authz.allow with input as {"method": "GET", "path": ["v1", "config"], "identity": tok} with opa.runtime as env
	not authz.allow with input as {"method": "POST", "path": ["v1", "data"], "identity": tok} with opa.runtime as env
}

test_short_token_never_valid if {
	not authz.allow with input as {"method": "GET", "path": ["health"], "identity": "short"}
		with opa.runtime as {"env": {"OPA_AUTH_TOKEN": "short"}}
	not authz.allow with input as {"method": "GET", "path": ["health"], "identity": ""}
		with opa.runtime as {"env": {"OPA_AUTH_TOKEN": ""}}
}
