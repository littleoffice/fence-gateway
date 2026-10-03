# Fence gateway enforcement profile

What a gateway between an MCP tool server and a language model has to do so that the
only tool output reaching the model is signed, intact, fresh and correctly framed. The
requirements are normative: another gateway, or an MCP client that verifies on its own,
can be built from this document and checked against it.

`fence-gateway` is the reference implementation. Each requirement names the code that
implements it and the test that covers it.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

- [Scope](#scope)
- [Relation to the fence verification contract](#relation-to-the-fence-verification-contract)
- [Terms](#terms)
- [1. Fence selection](#1-fence-selection)
- [2. Required attributes](#2-required-attributes)
- [3. Response layout](#3-response-layout)
- [4. Admission](#4-admission)
- [5. What the model is shown](#5-what-the-model-is-shown)
- [6. Key trust](#6-key-trust)
- [7. Audit](#7-audit)
- [8. Caller identity (informative)](#8-caller-identity-informative)
- [9. Producer profile](#9-producer-profile)
- [Conformance](#conformance)

## Scope

**What this profile secures:** the channel. A gateway that conforms guarantees that the
text a tool result places in the model's context meets one of three conditions:

- it is covered by a valid signature from a trusted key, is fresh, and fits a known layout;
- it is one of a small number of fixed or labelled replies, listed in [§4](#4-admission);
- it was withheld, and the model got a fixed refusal instead.

**What it does not secure:** the model. A signature proves who emitted the bytes, not
that the bytes are safe. A verified fence full of prompt injection is exactly what this
system is meant to deliver, labelled `rating="untrusted"`. Whether the model then follows
the awareness preamble and treats that content as data is outside any gateway's control.
`rating="trusted"` is authenticated prose, not an enforcement mechanism. Content that
*persuades* rather than *impersonates* is not addressed by fencing at all.

**Threat model.** The adversary controls content the tool server fetches (pages,
documents, titles, URLs). Unless the key is pinned ([§6](#6-key-trust)), the adversary
may also sit on the network path between the gateway and the tool server, or stand up a
server of their own in its place. The gateway process itself, and its configuration, are
trusted.

## Relation to the fence verification contract

Checking a single fence is specified by the relay's
[fence verification contract](https://github.com/littleoffice/mcp-searxng-relay/blob/1a2824139536fb45fed8b5fd186bf91679348e92/docs/fence-verification.md),
at the commit pinned in [`interop/testdata/relay/RELAY_COMMIT`](../interop/testdata/relay/RELAY_COMMIT).
That contract covers the wire grammar, the canonical metadata, content recovery for
escaped and CDATA bodies, the signing input, and the per-fence schema checks. A
conforming gateway MUST implement it. This document does not restate it.

This profile adds what the contract leaves to the verifier:
- which attributes are mandatory;
- how the fences in one response must fit together;
- what happens to text that carries no fence;
- what the model sees when verification fails;
- how far a key is trusted.

## Terms

- **Tool result:** one MCP `CallToolResult` returned by the tool server.
- **Response:** one text block of a tool result. Layout is checked per response.
- **Candidate:** an occurrence of the literal `<sec:fence` in a response.
- **Claimed candidate:** a candidate whose opening tag contains `signature="`.
- **Content fence:** a verified fence whose `rating` is not `trusted`.
- **Preamble fence:** the format 1.1 fence carrying the awareness preamble: `rating="trusted"`, `type="instructions"`, and the producer's awareness `source` ([§9](#9-producer-profile)).
- **Failure:** any condition this profile says fails. What happens next is set by the policy ([§5](#5-what-the-model-is-shown)).

## 1. Fence selection

**G1.1** The gateway MUST try every candidate in a response and let the signature decide
which candidates are real. It MUST NOT choose a fence by position, length or any other
pattern. *`Verify`, `candidateOffsets` in `fenceverify/verify.go`, `fenceverify/parse.go`;
`TestPreambleProseIsNotAFence`, `TestBoundaryEscapeAttackEscaped`.*

**G1.2** A claimed candidate that fails to parse or verify MUST be recorded as a
rejection, which is a failure. An unclaimed candidate that fails MUST NOT be recorded as
a rejection; it is unsigned text and is handled by [§4](#4-admission). *`claimsSignature`;
`TestBoundaryEscapeAttackRaw`.*

**G1.3** A candidate inside a fence that has already verified MUST be skipped. *`within`;
`TestCDATAContentMayContainFenceSyntax`.*

**G1.4** The gateway MUST limit how many candidates one response may hold, and MUST
treat a response over the limit as a failure without verifying it. Default limit: 1000.
*`Verifier.MaxCandidates`; `TestVerifierCandidateLimit`.*

**G1.5** When a fence names a `kid`, the gateway MUST check it against that key alone. If
it does not hold that key, the result is "unknown key", which is distinct from "bad
signature". *`verifyParsed`; `TestVerifySelectsKeyByKid`,
`TestForgedFenceNamingHeldKeyIsBadSignature`.*

## 2. Required attributes

These run after the signature has verified, as the contract's step 6 requires.

**G2.1** Every fence MUST carry `nonce`. *`Verifier.RequireNonce`.*

**G2.2** Every fence MUST carry `timestamp`, in RFC 3339. A fence without one would never
go stale, because nothing could bound its age. *`Verifier.RequireTimestamp`;
`TestRequireTimestamp`, `TestGatewayRequiresTimestampAndKid`.*

**G2.3** Under the relay's signature construction, every fence MUST carry `kid`. Without
one, a failed check cannot be told apart from a key the gateway has not fetched yet. The
paper-literal construction is exempt, because its reference implementation emits no
`kid`. *`Verifier.RequireKid`, set in `gateway.verify` (`proxy.go`);
`TestRequireKid`, `TestGatewayRequiresTimestampAndKid`.*

**G2.4** A fence whose timestamp is more than the age limit in the past, or more than the
skew allowance in the future, MUST fail. Defaults: age limit 10 minutes (`-max-age`),
skew allowance 2 minutes. An operator MAY disable the age limit; the skew bound always
applies. *`Verifier.MaxAge`, `MaxClockSkew`; `defaultMaxAge` and `fenceClockSkew` in
`main.go`; `TestFreshnessDefaults`.*

## 3. Response layout

A signature covers only its own fence. These rules cover how the fences of one response
fit together, so a preamble cannot be removed, swapped or spliced in without detection.
*`CheckLayout` in `fenceverify/layout.go`; tests in `fenceverify/layout_test.go`.*

**G3.1** Every fence MUST carry a `version` the gateway implements (`1.0`, `1.1`), or no
`version`. Any other value is a failure. *`TestLayoutUnknownFormat`.*

**G3.2** All fences in one response MUST share one `version`. *`TestLayoutMixedFormats`.*

**G3.3** A trusted fence MUST be a preamble fence in format 1.1. Any other trusted fence
is a failure. *`TestLayoutOtherTrustedFence`.*

**G3.4** Under 1.1, each content fence MUST be paired with its own preamble fence, which:
- comes before it in the response;
- names it, by containing the exact text `nonce="<content nonce>"` in its body;
- carries the same `kid` and the same `timestamp` as the content fence.

A preamble fence pairs with at most one content fence. *`TestLayoutPreambleRemoved`,
`TestLayoutPreambleNamesAnotherNonce`, `TestLayoutPreambleAfterContent`,
`TestLayoutKidMismatch`, `TestLayoutTimestampMismatch`,
`TestLayoutOnePreambleTwoContentFences`, `TestGatewayBlocksStrippedPreamble`.*

**G3.5** Every preamble fence MUST be paired. A preamble describing no content fence is a
failure. *`TestLayoutPreambleWithoutContent`.*

**G3.6 Downgrade.** The gateway MUST compare a response's `version` with:
- the oldest format the operator accepts (`-fence-version`);
- otherwise, the format the producer's key endpoint reports.

A response older than the operator's minimum fails. A response older than the endpoint's
format fails as a downgrade, unless re-reading the endpoint shows the producer was rolled
back. *`checkFormatDowngrade` in `proxy.go`; `TestGatewayDowngradeAndRollback`,
`TestGatewayFenceVersion`.*

## 4. Admission

These rules apply to the whole tool result, around the per-fence checks.
*`gateway.verify` in `proxy.go`.*

**G4.1** Content blocks MUST be text or image. Any other content type, and structured
content beside the blocks, can carry words that no fence covers, and is a failure. Images
carry no fence and are passed through. *`TestVerifyRefusesUnfenceableContent`,
`TestVerifyImageOnlyResultPassesUnderRequireAll`.*

**G4.2** A tool result with more than 16 MiB of text MUST fail without being verified.
*`maxResultText`; `TestVerifyRefusesOversizedResult`.*

**G4.3** A non-empty text block with no candidate in it is a failure, apart from the two
exceptions in G4.4. A substituted producer does not need to forge a signature if
unfenced text gets through; it only has to leave the fence out.
*`TestVerifyUnfencedResultBlockedByDefault`,
`TestVerifyUnfencedBlockBesideValidFenceBlockedByDefault`.*

**G4.4** Two kinds of unfenced text MAY be admitted:
- the producer's fixed reply for an empty result, compared exactly;
- the text of an error result. This MUST be shortened to at most 512 bytes and labelled
  as unverified before the model sees it, unless the policy is `audit`.

*`relayNoResults`, `labelUnverifiedError`; `TestVerifyRelayNoResultsPasses`,
`TestVerifyUnfencedErrorLabelledAndShortened`.*

**G4.5** In strict mode (`-require-all-fenced`), nothing unsigned is admitted. G4.4 does
not apply, and non-whitespace text outside verified fences, such as a 1.0 prose preamble,
is a failure. *`TestVerifyUnfencedResultFailsUnderRequireAll`,
`TestVerifyUnfencedBlockBesideValidFenceFailsUnderRequireAll`,
`TestVerifyUnsignedPreambleFlagged`.*

**G4.6** Without strict mode, unsigned text beside a verified fence is admitted. This is
what makes format 1.0 work, and it is the known gap that format 1.1 together with
`-fence-version 1.1` closes. A deployment that can require 1.1 SHOULD.

## 5. What the model is shown

**G5.1** The policy decides what a failure leads to:

| Policy | The model receives | Stops an attack |
|---|---|---|
| `reject` (default) | a fixed error result, nothing from the tool | yes |
| `annotate` | the tool's content, `isError` set, a warning prepended | no |
| `audit` | the tool's content unchanged | no |

A deployment that relies on the gateway for protection MUST use `reject`.
*`reject`, `annotate`; `TestVerifyBlocksTamperedContent`,
`TestVerifyAnnotatePolicyMarksButForwards`.*

**G5.2** Nothing returned to the model on a failure may contain text from the tool
result, from a rejection reason, or from an upstream transport error. Snippets and
reasons go to the audit log, which a person reads. *`reject`, `errUpstreamCall`;
`TestUpstreamFailureMessageIsFixed`.*

**G5.3** If no trusted key is available, every result MUST fail. *`fence.verify.nokey`;
`TestVerifyNoKeyFailsClosedUnderReject`.*

**G5.4** The gateway MAY remove the `signature` attribute from fences that verified.
Removal touches only the opening tags of those fences, and MUST leave `nonce` in place,
because the preamble names it. *`stripSignatures`;
`TestVerifyStripSignatureRemovesAttributeKeepsNonce`,
`TestStripSignatureLeavesContentAlone`, `TestStripSignatureOnRelayVector`.*

**G5.5** Tool arguments MUST be forwarded byte for byte. Tool definitions MUST be passed
through unchanged. The gateway inspects results, not requests. *`toolHandler`,
`syncTools`.*

## 6. Key trust

A signature is worth only as much as the key it is checked against.
*`checkKeyTrust`, `normalizePin` in `keytrust.go`; `EndpointKeys` in `fenceverify/keys.go`.*

**G6.1** The key fingerprint is the first 8 bytes of SHA-256 over the raw Ed25519 public
key, written as 16 lowercase hex characters. It is the same value fences carry as `kid`.
A malformed pin MUST stop startup. *`Fingerprint`; `TestNormalizePin`.*

**G6.2** At startup:

| Key source | Outcome |
|---|---|
| pinned | start; any key not matching the pin is refused |
| unpinned, HTTPS or loopback | start, logging `fence.key.unpinned` |
| unpinned, plain HTTP to another host | MUST refuse to start |

Trust on first use does not count as a pin. *`TestCheckKeyTrust`.*

**G6.3** When a fence names a key the gateway does not hold, the gateway SHOULD look that
key up at the endpoint before deciding:
- at most 4 fetches;
- each `kid` looked up at most once every 2 seconds.

Fences without a `kid` (paper construction only, per G2.3) trigger a plain, rate-limited
refresh instead. *`fetchMissingKeys`, `RefreshFor`; `TestRefreshForFindsEachReplicaKey`,
`TestRefreshForGivesUpOnAKeyNobodyServes`, `TestMinRefreshIntervalLimitsFetches`,
`TestVerifyRecoversFromKeyRotation`, `TestVerifyRecoversFromKeyRotationWithoutKid`.*

**G6.4** Earlier keys stay valid during a rotation, within these bounds:
- at most 8 keys are held;
- a key is dropped after 24 hours without being served or used to verify;
- the key served last is never dropped.

*`TestMaxKeysKeepsTheMostRecent`, `TestKeyTTL`,
`TestGatewayBehindReplicasWithKeysOfTheirOwn`.*

**G6.5** A new key is an audit event (`fence.key.rotated`). Under a pin, a different key
MUST be refused. *`TestPinnedKeyRefusesRotation`, `TestTOFUStillRefusesASecondKey`.*

## 7. Audit

**G7.1** Every outcome MUST be logged with the tool name and the caller identity:
- each verified fence;
- each rejection, with a short excerpt of its text;
- each layout problem, unfenced block, oversized result, and policy decision.

The excerpts are attacker-controlled text. They MUST go only to the log, never to the model.

The reference implementation's event names:

| Event | Meaning |
|---|---|
| `fence.verified`, `fence.ok` | a fence verified; a result passed |
| `fence.rejected` | a claimed candidate failed (G1.2); **alert on this** |
| `fence.layout` | a layout or downgrade failure (§3) |
| `fence.unfenced_block`, `fence.unsigned_text` | unsigned text (G4.3, G4.5) |
| `fence.unverified_error` | an unfenced error result was admitted (G4.4) |
| `fence.too_large` | the result was over the size limit (G4.2) |
| `fence.policy.reject` | the policy withheld a result |
| `fence.verify.nokey`, `fence.key.unavailable` | no usable key (G5.3) |
| `fence.key.loaded`, `fence.key.rotated`, `fence.key.unpinned` | key trust (§6) |
| `fence.version.mismatch` | the producer reports an older format than `-fence-version` requires |

## 8. Caller identity (informative)

This section is not about what reaches the model, but it decides whose tool-server state
a call touches. When more than one caller shares a gateway, the gateway has three ways to
authenticate to the tool server:

- forward each caller's own credential (`passthrough`);
- exchange it for a token issued to the tool server, under RFC 8693 (`exchange`);
- use one credential of its own for everyone (`static`), only where callers may share the
  tool server's history and rate limits.

The gateway refuses to start with several callers until the operator picks one. A call
whose credential cannot be forwarded or exchanged is refused, not sent under the gateway's
own credential. Details: the README's *Which credential reaches the relay* and
[token-exchange.md](token-exchange.md). Tests: `config_test.go`,
`passthrough_test.go`, `exchange_test.go`.

## 9. Producer profile

Most of this profile works for any fence producer. A few values are specific to
`mcp-searxng-relay`. A gateway in front of another producer replaces them, and keeps
every rule:

| Parameter | Relay value | Used by |
|---|---|---|
| Preamble `source` | `mcp-searxng-relay:awareness` | G3.3, G3.4 |
| How the preamble names the content nonce | the text `nonce="<hex>"` in its body | G3.4 |
| Formats implemented | `1.0` (prose preamble), `1.1` (fenced preamble) | G3.1, G3.6 |
| Fixed unfenced reply for an empty result | `No results found.` | G4.4 |
| Non-text content | images (from `searxng_read_url`) | G4.1 |
| Signing domain tag | `PromptFence/v1.0` | the contract |
| Key endpoint | `GET /fence/public-key` → `{version, algorithm, publicKey, fingerprint}` | G3.6, §6 |

## Conformance

A gateway conforms if it meets every MUST in this document and in the fence verification
contract. Under its default configuration, the reference implementation conforms with
one exception: G4.6, which is a SHOULD. Its default is `-fence-version auto`, which
follows the relay; the relay itself defaults to format 1.0.

The executable checks are:
- the interop vectors, generated by the relay's unmodified `fence.go`
  (`interop/`, `relay_vectors_test.go`);
- the tests named under each requirement.

`go test ./...` runs all of them. If a change to the code alters a requirement, this
document changes in the same commit.
