# Worker Broker — batch advisory endpoint

`POST /v1/analyze/batch` is bound to loopback and requires an independent
`BROKER_BATCH_AUTH_TOKEN` (minimum 32 characters). It must be sent in the
`Authorization: Bearer ...` header. This token is distinct from API-provider keys.

**Production batch dispatch is denied by default**, even with the correct
HTTP token. Authentication does not signify that the user approved sending
content externally. An independently audited user-controlled authorization
implementation is needed before external dispatch can operate. The injectable
`authorizeTarget` callback is intended for controlled integration/testing;
it is not a production user-approval mechanism by itself.

An authorized call to an external API transmits the exact submitted task text
off the local machine. Provider/model/task SHA-256 are presented to the
injected authorizer. Worker outputs are advisory data, not instructions.

Limits per broker instance: 256 KiB request body, up to 8 targets, 50,000
characters per task, 2 active batches, 4 queued batches, and 2 parallel
workers per batch. Limits for underlying operations remain cooperative;
misbehaving adapters may continue work after an aborted request.

Legacy `/health` and `/v1/analyze` behavior is unchanged. This phase does not
introduce CEB, arbitrary filesystem actions, autonomous routing, or live
provider calls in tests.
