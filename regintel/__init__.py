"""Securden regulatory intelligence: global, source-verified PAM regulatory catalog.

Deliberately separate from ``app`` (the deterministic evaluation service):

  * ``app``      evaluates evidence with OPA. No LLM, no network egress.
  * ``regintel`` discovers official sources, extracts candidate requirements
                 with a *local* LLM, and runs the human review / publication
                 workflow that produces the catalog and the policy bundles.

Nothing produced by the LLM is visible through the catalog API or reaches OPA
until a human reviewer has approved it and it has been published.
"""

SCHEMA_VERSION = "1.0"

PAM_DOMAINS = (
    "privileged_access_management",
    "access_control",
    "authentication",
    "credential_lifecycle",
    "session_monitoring",
    "audit_logging",
    "access_reviews",
    "emergency_access",
    "security_event_monitoring",
    "identity_governance",
    "segregation_of_duties",
)
