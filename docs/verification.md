# Verification

What the gateway checks on every tool result, and what a failure leads to. The same
rules, stated as numbered requirements tied to the code and tests that implement
them, are in the [enforcement profile](specification.md).

## Contents

- [Policies](#policies)
- [What counts as a failure](#what-counts-as-a-failure)
- [Text without a fence](#text-without-a-fence)
- [Response layout](#response-layout)
- [Format versions](#format-versions)
- [Freshness](#freshness)
- [Key trust](#key-trust)

## Policies

`-policy` is `reject` (Definition 4.5 rule 4 — drop the result), `annotate` (forward
with a warning and `isError`), or `audit` (log only). Only `reject` actually stops an
attack; the other two describe one.

| Policy | The model receives | Stops an attack |
|---|---|---|
| `reject` (default) | a fixed error result, nothing from the tool | yes |
| `annotate` | the tool's content, `isError` set, a warning prepended | no |
| `audit` | the tool's content unchanged | no |

Under every policy the reason goes to the audit log, which a person reads, never to
the model: rejection reasons and snippets carry text an attacker chose.

## What counts as a failure

| Check | Fails when | Rule |
|---|---|---|
| Signature | a candidate that claims a signature does not verify, or names a key the gateway does not hold even after looking it up | [G1.2](specification.md#1-fence-selection), [G1.5](specification.md#1-fence-selection) |
| Required attributes | a fence has no `nonce` or no `timestamp`, or (relay construction) no `kid` | [§2](specification.md#2-required-attributes) |
| Freshness | a fence is older than `-max-age`, or dated too far ahead | [G2.4](specification.md#2-required-attributes), [Freshness](#freshness) |
| Layout | fences that verify one by one do not fit together | [§3](specification.md#3-response-layout), [Response layout](#response-layout) |
| Format | a response is older than `-fence-version` or than the relay reports | [G3.6](specification.md#3-response-layout), [Format versions](#format-versions) |
| Unfenced text | a text block carries no fence at all | [G4.3](specification.md#4-admission), [Text without a fence](#text-without-a-fence) |
| Content type | a block is neither text nor image, or structured content sits beside the blocks | [G4.1](specification.md#4-admission) |
| Size | more than 16 MiB of text, or more than 1000 fence candidates | [G4.2](specification.md#4-admission), [G1.4](specification.md#1-fence-selection) |
| Key | no trusted key is available | [G5.3](specification.md#5-what-the-model-is-shown) |

Prose that merely mentions the fence syntax, without claiming a signature, is not a
failure in itself; it is unsigned text, and the rules below decide what happens to it.
Why the line falls there: [Design notes](design-notes.md#prose-mentions-of-the-syntax-are-not-attacks).

## Text without a fence

A text block with no fence at all is a failure too, and the policy applies to it. A
substituted relay, or anyone on a plain-HTTP link, does not need to forge a signature to
reach the model; it only has to leave the fence out. Two replies the relay sends unfenced
are let through: the exact text `No results found.`, and error results, which are
shortened and labelled as unverified so a failed fetch still reads as a failed fetch.
`-require-all-fenced` goes further and accepts nothing unsigned, those two included.

## Response layout

A signature only covers its own fence: cut the preamble out, or splice a preamble from
one response onto another's content, and everything left still verifies. So the gateway
also checks how the fences fit together:

- Under 1.1, each content fence must follow a trusted preamble fence
  (`source="mcp-searxng-relay:awareness"`) that names its nonce and shares its key and
  timestamp.
- All fences in a response must share one format.
- A trusted fence can only be that preamble.
- Nothing but whitespace may sit outside the fences of a 1.1 response: the relay sends
  nothing there, so text beside them was added on the way, whatever
  `-require-all-fenced` says.
- A response in an older format than the relay's key endpoint reports is a downgrade,
  unless a re-read of the endpoint shows the relay was rolled back.

Any of these is a failure, and the policy applies. How the preamble came to be fenced:
[Design notes](design-notes.md#the-awareness-preamble-was-unsigned).

## Format versions

`-fence-version` sets the oldest format accepted outright. `auto` (the default) follows
the key endpoint as above, because the relay itself defaults to 1.0. `1.1` refuses 1.0
responses, so every response that reaches the model has a signed preamble and no
unsigned text beside its fences. It is the setting to use once the relay runs with
`FENCE_PREAMBLE=fenced`. `1.0` accepts either relay format but refuses fences with no
version, which only other producers emit; a 1.0 response still carries its preamble as
unsigned prose, which anyone on the gateway→relay path can rewrite. If the relay
reports an older format than required at startup, the gateway logs
`fence.version.mismatch`, since every result would then be blocked.

## Freshness

**Signatures carry no freshness.** A valid fence is valid forever. Anything that caches
or replays tool output can feed stale content into a live session with a perfect
signature. `-max-age` bounds it against the fence timestamp: 10 minutes by default,
since the relay stamps each fence when it answers. A fence dated more than two minutes
ahead of the gateway's clock is refused too, so it cannot outlive the bound. Both depend
on the relay's and the gateway's clocks roughly agreeing; `-max-age 0` turns the age
check off. A fence with no `timestamp` at all is refused, since nothing could bound it.

## Key trust

A key fetched from the relay proves that a fence came from whoever serves that key.
Against a substituted or impersonated relay it proves nothing, which is what `-pin` is
for. Why that is not circular, and how the relay's per-restart keys used to undercut it:
[Design notes](design-notes.md#ephemeral-keys-bound-what-verification-proves).

**Relay persistent key + gateway `-pin` is the setup to run.** `FENCE_SIGNING_KEY_FILE`
gives the relay a persistent key (the `searxng-helm` chart mounts one via
`fenceKey.existingSecret`), so a pin survives its restarts. The gateway enforces the
floor:

| Key source | Startup |
|---|---|
| `-pin` set | starts; the key may come over any transport, since it must match the pin |
| no pin, key over HTTPS or from this machine (`localhost`, `127.0.0.1`, `::1`) | starts, with a `fence.key.unpinned` warning |
| no pin, key over plain HTTP from another machine | **refused**: anyone on the path could serve their own key |

A pin protects the key, not the unsigned text around a response. Under format 1.0 the
preamble is unsigned prose, and anyone on the gateway→relay path can rewrite it or add
to it without touching a signature. With the relay on `FENCE_PREAMBLE=fenced` and the
gateway on `-fence-version 1.1`, nothing unsigned reaches the model beside a signed
response. The relay's unfenced replies ([above](#text-without-a-fence)) are a separate
matter; `-require-all-fenced` refuses those too.

Each fence names the key that signed it (`kid`), and the gateway checks it against that
key alone; a relay-scheme fence that names none is refused. So "signed by a key I do not
hold" and "forged" are told apart in the audit log. A fence naming a key the gateway does
not have (a new rotation, or another relay replica) makes it fetch the endpoint until that
key turns up, up to four times, at most once per key every two seconds. Keys the relay
has stopped using drop out after a day. Several replicas on keys of their own therefore
work, but they cannot be pinned: a pin accepts one key. Give all replicas the same key to
pin them.

`-tofu` does not count as a pin: its first fetch has the same problem, and it is
remembered only until the gateway restarts. A malformed `-pin` (not 16 hex characters)
stops startup instead of silently matching no key; upper case is accepted.
