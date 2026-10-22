# Discovery leads and credential-pattern input

The original scan/manual-input workflows and attack rules remain available.
Optional OMEGA integration does not require changing standalone pentest use.

* MLflow/Jupyter service evidence retains investigation paths without claiming
  artifact writes, kernel creation or RCE. Stronger rules still require explicit
  capability evidence. A `llm_enum` document can supply `capability_evidence` with
  a named capability, `verified: true`, and a nonempty `evidence` description;
  the parser preserves it. No capability is fabricated or actively exercised.
* Notebook kernel/session JSON inventories corroborate presence; catch-all
  baselines still do not. A CDN annotation does not automatically reduce a
  corroborated application capability to informational severity.
* Hostnames in a structured HTTP Location/redirect remain medium-confidence
  hostname investigation candidates. Arbitrary dotted NSE text remains an
  unscored observation. DNS/certificate provenance is retained.
* A `tcp_services.xml.raw` original accompanies normalized one-shot-enum XML.
  Automatic loot detection skips that original to avoid processing it twice;
  it can still be selected explicitly for a manual evidence review.

## Redacted credential patterns

The normalized `secret_finding` entity contains a location and rule identifier,
not a password/account or usable login action. Optional imports can enter through
the existing `scan --input-json` interface. OMEGA's adapter supplies target scope
and passes only whitelisted metadata from the RetroScanner credential artifact.

An exposure/rotation rule retains these investigation leads. A separate SSH rule
requires `attributes.credential_type = ssh-private-key` and a same-host SSH
service. Generic API tokens are not correlated with arbitrary web/login services.
Neither rule establishes validity, deployment, ownership or successful access.
The entities cannot enter credential-reuse login validation as credentials.
