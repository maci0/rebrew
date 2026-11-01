# OpenAI-compatible provider client

This package is an outbound client library, not a service or an authorization
boundary. It is not wired into the job runtime. Before a caller enables it, the
existing owner must authenticate and authorize the operation, durably admit the
exact request and configured credential, and bind provider usage and result to
its existing settlement receipt. The `admitted` argument is a caller assertion;
it cannot validate ownership or prevent duplicate work. Never expose it as a
public authorization check.

`Complete` sends one chat-completions request with an explicit timeout and size
limits. It accepts an API root or a complete chat-completions URL, supports
keyless local providers and optional streaming, and never follows redirects or
retries. Errors after dispatch are `ErrUncertain`: the provider may have acted
or billed even when the local request was canceled, timed out, failed, or the
stream was truncated. The owner must reconcile rather than dispatch again or
assume physical cancellation. A missing usage block stays unknown rather than
being reported as zero. Errors intentionally exclude provider bodies, prompts,
credentials and URLs.

The endpoint and credential must come from trusted operator configuration, not
the job request. HTTP endpoints are supported for compatibility with existing
providers; their transport confidentiality depends on the deployment network.

Streaming callbacks receive tentative chunks before the terminal marker and
usage. The caller must not publish them as a settled result until its durable
owner receipt binds the exact request, terminal result and usage decision.

The library does not provide durable request identity, owner authorization,
billing, provider-side cancellation confirmation, or a deployable endpoint.
Those require integration and qualification with the existing owner before use.
