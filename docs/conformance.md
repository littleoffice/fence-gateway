# Conformance to arXiv:2511.19727 (§4.5, §7.4.3)

This document maps `fence-gateway` onto the **Security Gateway** the paper
prescribes — *Prompt Fencing: A Cryptographic Approach to Establishing Security
Boundaries in Large Language Model Prompts* (Peh, 2025). It is a checklist for
anyone evaluating the gateway against the paper, and it is honest about the two
places the implementation deliberately diverges. The gateway's own rules, as
normative requirements, are in [specification.md](specification.md).

The paper defines the gateway abstractly: a **pre-processing verification
layer** (§4.5) that "can be implemented in any architecture (e.g. microservice,
API gateway, library) that sits between an application and an LLM provider"
(§7.2). It names five responsibilities (§7.4.3). It does **not** prescribe a
transport, a proxy topology, or a multi-client model — those are left to the
implementer.

## Security Gateway responsibilities (§7.4.3 + §4.5)

| The paper requires the gateway to… | Status | How |
|---|---|---|
| Validate all fence signatures **before** the content reaches the LLM | ✅ | `verify()` runs on every tool result before it is returned to the client/model (`proxy.go`) |
| Maintain and manage cryptographic keys | ✅ | `fenceverify.EndpointKeys` — acquire from the relay's `/fence/public-key`, cache, retain previous across rotation |
| Reject invalid **or missing** signatures | ◑ | Invalid → replaced with an error result under `-policy reject` (the default). *Missing* → a text block with no fence at all fails by default, except the relay's `No results found.` and its error messages (shortened, labelled unverified). Unsigned text *beside* a verified fence (the relay's 1.0 preamble) is surfaced only with `-require-all-fenced`, which is **off by default** — see [Deliberate divergences](#deliberate-divergences) |
| Log security events for an audit trail | ✅ | Structured audit log: `fence.verified`, `fence.rejected`, `fence.policy.reject`, `fence.key.rotated` — attacker-controlled text goes to the log (read by a human), never back to the model |
| Handle key rotation and certificate management | ✅ / n/a | Rotation: refetch-and-retry on a verification failure, plus `-pin` and `-tofu`. "Certificate management" is n/a — the relay signs with raw Ed25519 keys, not X.509 certificates, so there are no certs to manage (TLS certs for the HTTP transport are a separate concern) |
| *(optional)* Strip signature data before the model sees it | ✅ | `-strip-signature` removes the `signature="…"` attribute from verified fences; the nonce is kept because the awareness preamble names it |
| Act as an enforcement point **independent of the LLM** | ✅ | A separate process; the model performs no cryptographic operation |

Signature mechanics the paper specifies (§4.6) — Ed25519, alphabetically sorted
attributes, ISO-8601 timestamps, UTF-8, defined XML escaping — are implemented
in the `fenceverify` package. The one construction difference between the paper
and the relay this gateway pairs with is documented in the README's
["Reconciling the paper with the relay"](../README.md#reconciling-the-paper-with-the-relay).

## Input prompt vs. return path

The paper frames the check on the **prompt**, "before submission to the LLM"
(§4.5) — the input side. This gateway verifies **tool results on the return
path**. That is not a deviation but the correct application of the same
principle to an agent/MCP stack: the untrusted, fenced bytes *are* the tool
output, so the "last deterministic view before the bytes become context" is the
tool-result return leg. This is exactly the data-source stance of §7.5
("Application Integration and Data Pipeline") — classify sources by trust and
verify fenced data at ingress — with the relay as the fence generator and the
gateway as the verifier in front of it.

## Deliberate divergences

Two, both documented rather than hidden:

1. **`-require-all-fenced` defaults off.** The paper says reject *missing*
   signatures (§7.4.3), and §4.2 assumes every segment is fenced. The relay,
   however, emits an **unsigned awareness preamble** outside the fence (the text
   that tells the model to treat the fenced content as data). Rejecting all
   unsigned text by default would block every legitimate response. So the
   default tolerates unsigned regions beside a verified fence, and
   `-require-all-fenced` surfaces them on demand. A text block with no fence at
   all is not tolerated by default (the relay's no-results reply and its error
   messages aside). The real fix is upstream — wrap the preamble in its own
   `rating="trusted" type="instructions"` fence, which is what the paper
   prescribes for system instructions anyway. See the README's
   ["What this found"](../README.md#what-this-found).

2. **Certificate management is n/a**, as noted above — the relay uses raw
   Ed25519 keys, so key management is implemented and certificate management has
   nothing to manage.

## Where the implementation exceeds the paper

Both driven by how the relay actually behaves, and both documented in the
README's "What this found":

- **Freshness** — the paper's signatures carry no freshness; a valid fence is
  valid forever. `-max-age` bounds a fence against its timestamp so cached or
  replayed tool output cannot re-enter a live session.
- **Relay-substitution defence** — the paper's threat model (§2.2) *assumes* the
  gateway operates correctly and keys are secure. `-pin` (and `-tofu`) add a
  defence against a substituted or impersonated relay, which the pinned
  fingerprint detects. The cost is that a pinned deployment needs operator
  action after each relay restart (per-restart key generation), which is the
  single biggest limiter on what the signatures are currently worth — and a
  relay-lifecycle question, not a gateway one.

## What the paper leaves to the implementer

The paper is silent on transport (stdio vs. HTTP), on whether the gateway is a
microservice, an API gateway, or an embedded library, and on multi-client
session handling. Those are engineering choices below the paper's level of
abstraction, not conformance points. The current build is a microservice (an
MCP proxy); the verification core (`fenceverify`) is equally usable as the
"library" placement the paper also permits.
