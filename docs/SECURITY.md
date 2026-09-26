# Security Policy

This document describes how to report security issues in `fence-gateway` and
what to expect once you do. For the project's dependency, build-provenance, and
development-process statement — the "what am I actually trusting if I run this"
question — see [supply-chain.md](supply-chain.md).

This project is maintained by a single individual: the holder of the GitHub
account with admin rights on the repository. References to "the maintainer"
below mean that person. The codebase is primarily AI-generated and
human-reviewed; [supply-chain.md](supply-chain.md#development-process) describes
that process in full, and it is relevant context for how security reports are
handled — every fix, like every other change, is reviewed, built, and tested by
the maintainer before release.

`fence-gateway` is a **proof of concept** (see the README). That status is
itself security-relevant: it has not had the external audit the relay it pairs
with received, and it should be evaluated on that basis.

## Supported versions

The latest released version receives security fixes. There is no backport window
for older releases — if a fix ships, it ships in a new release, and the
expectation is that operators move forward to it.

If you are running an untagged build from `main`, treat it as unsupported for
security purposes — pin to a release.

## Reporting a vulnerability

**Do not open a public issue for security problems.** Public issues are visible
to everyone, including before a fix exists.

Report privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form with as much detail as you can — affected version,
   reproduction steps, and the impact you believe it has.

This routes the report privately to the maintainer and gives both sides a shared
space to coordinate a fix and a disclosure timeline.

### What happens next

This is a single-maintainer project. It is honest to be plain about what that
means rather than promise a service level that cannot be backed:

- There is **no committed response time**. There is no team, no rotation, and no
  on-call.
- GitHub notifies the maintainer when a report is filed, so reports are *seen* —
  they do not vanish into an unwatched inbox.
- The maintainer will review and respond as soon as they are reasonably able,
  and will keep you informed once they have engaged with the report.
- You will be credited in the published advisory unless you ask not to be.

## Disclosure policy

The project follows coordinated disclosure:

1. You report the issue privately.
2. The maintainer confirms it and develops a fix.
3. A disclosure date is agreed with you. The aim is for disclosure to be
   reasonably prompt once a fix exists — the goal is to protect users, not to
   sit on findings — but no specific timeline is committed to in advance.
4. The fix ships in a tagged release, and a GitHub Security Advisory is
   published describing the issue, the affected versions, and the fix, crediting
   the reporter.

If an issue is already being exploited in the wild, the maintainer will move
faster and may disclose alongside the fix rather than waiting.

## Scope

**In scope** — report these here:

- The Go source code in this repository, especially the `fenceverify` package.
  A verification bypass — anything that makes the gateway accept a fence it
  should reject, or reject a legitimate one in a way that could be steered by
  content — is the highest-severity class of bug this project can have, because
  the whole point of the gateway is to be the deterministic checker the model
  cannot be.
- The `Dockerfile` and the container image it produces, including the default
  configuration values.
- Cases where the documentation steers an operator toward an unsafe
  configuration (for example, running `-policy audit` or `-policy annotate` in a
  context where the operator believes they are protected), or where an unsafe
  configuration is too easy to reach by accident. A footgun in the docs or
  defaults is a project bug.

**Out of scope** — please report these to the relevant upstream project instead:

- **`mcp-searxng-relay`** (the fence *generator*). This project is a verifier
  for the fences that relay produces; bugs in the signing side, the relay's key
  lifecycle, or its awareness preamble belong to
  <https://github.com/littleoffice/mcp-searxng-relay>. A heads-up here is still
  appreciated where the two interact, but the fix belongs there.
- **The prompt-fencing scheme itself** (arXiv:2511.19727). Limits of what a
  signature over tool output can and cannot prove — replay/freshness, the
  unsigned preamble, ephemeral-key trust — are discussed honestly in the README
  under "What this found." Those are properties of the design, not
  implementation vulnerabilities, unless the gateway implements a defence
  incorrectly.
- **The Go standard library and toolchain.** Report stdlib issues to the Go
  project; `govulncheck` in CI tracks published advisories against the pinned
  version on this side.

## Existing security posture

The gateway's design already addresses several classes of risk. A reviewer
evaluating it may find these useful starting points (all are discussed in more
depth in the README):

- **Fail-closed verification.** Under the default `-policy reject`, a tool result
  that carries a `signature=` attribute and fails verification is replaced with
  an error result; the attacker-controlled text never reaches the model, and the
  rejection detail is written to the audit log (read by a human) rather than
  echoed back (read by a model).
- **Content cannot steer fence selection.** The real fence is located by trying
  candidates and letting the signature decide, rather than by any pattern-based
  selector that content could influence. Candidates carrying a `signature=`
  attribute that fail are treated as rejections to alert on; unsigned prose
  mentions of the fence syntax are ignored, so legitimate traffic is not blocked
  wholesale.
- **Every attribute is canonicalised, including unrecognised ones**, so a
  smuggled attribute cannot ride along outside the signature while remaining
  visible to the model.
- **A standard-library verification core.** `fenceverify`, which decides whether
  a fence is trusted, uses only the Go standard library (`crypto/ed25519`,
  `crypto/sha256`). The transport (the MCP SDK) and OAuth verification
  (`go-oidc`, `go-jose`) are third-party. See
  [supply-chain.md](supply-chain.md#dependency-inventory).
- **Key pinning (`-pin`), staleness bounds (`-max-age`), nonce
  enforcement, and an all-fenced check (`-require-all-fenced`)** let an operator
  tighten the guarantees to their threat model. Without a pin, the gateway
  refuses to fetch the relay's key over plain HTTP from another machine.

Pointing at these is not a claim that the project is free of vulnerabilities —
it is a proof of concept and should be treated as one. It is context for where
the considered effort has gone.
