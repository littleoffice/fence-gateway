# Design notes

Where the paper and the relay disagree, and what building and running the gateway
against the real relay found. The rules these led to are in [Verification](verification.md).

## Contents

- [Reconciling the paper with the relay](#reconciling-the-paper-with-the-relay)
  - [Signature construction](#signature-construction)
  - [Escaping](#escaping)
  - [Encoding](#encoding)
  - [Canonicalisation](#canonicalisation)
  - [The nonce](#the-nonce)
- [What this found](#what-this-found)
  - [Prose mentions of the syntax are not attacks](#prose-mentions-of-the-syntax-are-not-attacks)
  - [The awareness preamble was unsigned](#the-awareness-preamble-was-unsigned)
  - [Signatures carry no freshness](#signatures-carry-no-freshness)
  - [Ephemeral keys bound what verification proves](#ephemeral-keys-bound-what-verification-proves)

## Reconciling the paper with the relay

Five places where the two disagree, and what the verifier does about each.

### Signature construction

§4.3 specifies `Ed25519(SHA-256(C ‖ M))`. The relay signs
`"PromptFence/v1.0" ‖ 0x00 ‖ uint64_be(len(C)) ‖ C ‖ M` with PureEd25519 and explains
why. The relay is right, so `SchemeRelay` is the default; `-paper-scheme` selects the
literal construction for interop with the reference implementation. The two do not
cross-verify, and a test asserts they don't.

### Escaping

The relay signs pre-escape content and emits escaped content, so the verifier must
unescape before checking. It does so in a single left-to-right pass over exactly three
entities. A general XML unescaper is wrong here: content containing the literal text
`&lt;` arrives on the wire as `&amp;lt;`, and anything entity-table-driven turns it into
`<` — different bytes than were signed, silent failure. There is a test.

### Encoding

`searxng_session_sources` carries byte-exact URLs, so the relay sends its body as CDATA
(`encoding="cdata"`) rather than entity-escaped. The verifier branches on that
attribute: it finds the element's end by skipping over CDATA sections (a page title may
contain a literal `</sec:fence>`), joins the sections, and refuses any text outside
them. An `encoding` value it does not know is refused, not guessed at. The attribute is
signed, so flipping it breaks the fence.

### Canonicalisation

Attribute values are reconstructed from the raw wire bytes rather than
parsed-then-re-escaped, so the canonical string is rebuilt from the same bytes the
signer saw. Every attribute is canonicalised, including unrecognised ones — otherwise a
smuggled `policy="allow-all"` would ride along outside the signature while still being
visible to the model. `xmlns:*` and `signature` are excluded, matching the generator.

### The nonce

Not in the paper; a relay extension. §4.3's extensibility clause covers it — new
attributes join the alphabetical canonicalisation and are signed like any other. The
gateway requires it: a fence without a `nonce` fails
([G2.1](specification.md#2-required-attributes)).

## What this found

### Prose mentions of the syntax are not attacks

The relay's awareness preamble discusses `<sec:fence rating="untrusted">` and
`</sec:fence>` in plain text, so the first textual match in every genuine response is
not the real element. Two consequences. First, the real fence has to be located by
trying candidates and letting the signature decide, because any pattern-based selector
is something content can steer. Second — and this only showed up on the first live run
— treating unparseable candidates as rejections makes `-policy reject` block *100% of
legitimate traffic*. Candidates are now split: those carrying a `signature=` attribute
are asserting authenticity and failing (→ `Rejections`, alert on these), those without
are prose (→ `Ignored`).

### The awareness preamble was unsigned

In format 1.0 the preamble sits outside the fence, and it is the text instructing the
model to treat the fenced content as data. Nothing binds it to the fence it describes.
Untrusted content cannot currently reach it — it is escaped and enclosed — so this is
not presently exploitable in the relay. But the mechanism it protects is defeated by
editing it, without touching a signature, and §4.2 assumes every segment is fenced.
`-require-all-fenced` surfaces the gap; the real fix is to wrap the preamble in its own
`rating="trusted" type="instructions"` fence, which is what the paper prescribes for
system instructions anyway.

The relay now does this under `FENCE_PREAMBLE=fenced` (format 1.1). But a signature only
covers its own fence, so the gateway also checks how the fences of a response fit
together, refuses unsigned text beside a 1.1 response, and treats an older format than
the relay reports as a downgrade. The rules: [Response layout](verification.md#response-layout)
and [Format versions](verification.md#format-versions).

### Signatures carry no freshness

A valid fence is valid forever, so anything that caches or replays tool output can feed
stale content into a live session with a perfect signature. The gateway bounds a fence's
age against its timestamp: [Freshness](verification.md#freshness).

### Ephemeral keys bound what verification proves

Fetching the key from the same server that produced the fence is *not* circular under
the paper's threat model (§2.2) — the adversary there controls fetched content, not the
relay process, and a malicious page cannot mint signatures however many fake fences it
embeds. That is the §6.3.2 defence and it holds. Against a substituted or impersonated
relay it proves nothing, which is what `-pin` is for. But pinning fights the relay's
per-restart key generation: the gateway has to tolerate rotation (it refetches once on
failure and retains the previous key per §7.4.1) and a pinned deployment needs operator
action after every relay restart. This is the single biggest limiter on what the
signatures are currently worth, and it is a relay lifecycle question, not a gateway one.

The relay now answers it: `FENCE_SIGNING_KEY_FILE` gives it a persistent key, so a pin
survives its restarts. **Relay persistent key + gateway `-pin` is the setup to run.** How
the gateway enforces it: [Key trust](verification.md#key-trust).
