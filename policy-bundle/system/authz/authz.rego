# OPA server API authorization (opa run --authentication=token --authorization=basic).
#
# Defence in depth: OPA is only reachable on the internal Docker network, and
# additionally every API call must present the shared bearer token, and only
# read-only decision queries under data.securden plus /health are permitted.
# Policy/data mutation APIs (PUT/PATCH/DELETE /v1/policies, /v1/data),
# ad-hoc queries (/v1/query, /v1/compile) and config endpoints are denied.
package system.authz

default allow := false

token := opa.runtime().env.OPA_AUTH_TOKEN

authenticated if {
	count(token) >= 32
	input.identity == token
}

allow if {
	authenticated
	input.method == "GET"
	input.path == ["health"]
}

allow if {
	authenticated
	input.method == "POST"
	count(input.path) >= 3
	input.path[0] == "v1"
	input.path[1] == "data"
	input.path[2] == "securden"
}
