# SBPL Probe — `network.allowedIPs` feasibility (PATCH-BRIEF.md spec item 3)

**Date:** 2026-09-04 · **Probed by:** delegated pi session (intercom `01a06af0` closeout)
**Repo state at probe time:** `main` @ `476bf98` ("0.0.70", upstream pinned HEAD), clean tree except untracked `PATCH-BRIEF.md`.

## TL;DR verdict

On macOS 26.6.2, the Seatbelt profile compiler rejects **every** destination host
literal in `(remote …)` network filters — IPv4, IPv4+CIDR, IPv6, IPv6+CIDR,
hostnames, bare or with port, for the `ip`, `tcp`, `udp`, `ip4`, and `ip6`
filter names. The **only** accepted host tokens are `*` and `localhost`, and the
port must be a **single decimal port 1–65535** (no ranges, no `0`; `*:*`
compiles and means "any host, any port"). Therefore the brief's emission form
`(allow network-outbound (remote ip "10.172.102.0/23:9093"))` **cannot compile**
and the brief's first fallback ("single-IP entries only") is **equally
inexpressible**. The smallest workable emission is **port-scoped**:
`(allow network-outbound (remote ip "*:9093"))`.

## Environment

`sw_vers`:

```
ProductName:  macOS
ProductVersion:  26.6.2
BuildVersion:  25G83
```

Probe binary: `/usr/bin/sandbox-exec`. All probes run as
`/usr/bin/sandbox-exec -p '<profile>' /bin/true`.

**Methodology note on exit codes (important for re-running):** the probing
session itself ran _nested_ inside another seatbelt sandbox (pi-claude-sandbox
wraps every bash call). This does not affect verdicts:

- **exit 65 + compiler backtrace** (`<input string>:L:C:` pointing into the
  profile text) = profile **rejected at compile time** by libsandbox's parser.
  This is the grammar verdict and is independent of nesting.
- **exit 71 `sandbox_exec: sandbox_apply: Operation not permitted`** = profile
  **compiled successfully**; the kernel refused a _nested_ `sandbox_apply`.
  Compile-OK is all the grammar probe needs (an un-nested run would exec
  `/bin/true` and exit 0).

## Probe matrix (exact commands + actual stderr)

### Rejected — IP/CIDR host literals, `ip` filter

```
$ /usr/bin/sandbox-exec -p '(version 1)(allow network-outbound (remote ip "127.0.0.1/32:54321"))' /bin/true
sandbox-exec: host must be * or localhost in network address
Backtrace:
<input string>:1:37:
 (remote ip "127.0.0.1/32:54321")
→ REJECT (exit 65)
```

| Profile filter (all prefixed `(version 1)(allow network-outbound …)`) | stderr                                                                   | verdict                                   |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------- |
| `(remote ip "127.0.0.1:54321")`                                       | `host must be * or localhost in network address`                         | REJECT 65                                 |
| `(remote ip "127.0.0.1/32")`                                          | `port missing in network address: 127.0.0.1/32`                          | REJECT 65                                 |
| `(remote ip "::1")`                                                   | `host must be * or localhost in network address`                         | REJECT 65                                 |
| `(remote ip "2001:db8::/32")`                                         | `host must be * or localhost in network address`                         | REJECT 65                                 |
| `(remote ip "0.0.0.0:54321")`                                         | `host must be * or localhost in network address`                         | REJECT 65                                 |
| `(remote ip "10.0.0.0/8:5000-5010")`                                  | `host must be * or localhost in network address`                         | REJECT 65                                 |
| `(remote ip "example.com:80")`                                        | `host must be * or localhost in network address`                         | REJECT 65                                 |
| `(remote ip 127.0.0.1:54321)` (unquoted)                              | `unbound variable: 127.0.0.1:54321 at <input string>, line 1, column 47` | REJECT 65                                 |
| `(remote ip "*")`                                                     | `port missing in network address: *`                                     | REJECT 65 — a port is **always** required |

Note the parse order implied by the errors: the string is split on `:` first
(`"127.0.0.1/32"` with no colon → "port missing"), and only then is the host
part validated against the `*`/`localhost` whitelist.

### Rejected — other filter names (no escape hatch via `tcp`/`udp`/`ip4`/`ip6`)

| Profile filter                     | stderr                                           | verdict   |
| ---------------------------------- | ------------------------------------------------ | --------- |
| `(remote tcp "127.0.0.1:54321")`   | `host must be * or localhost in network address` | REJECT 65 |
| `(remote udp "10.0.0.1:53")`       | `host must be * or localhost in network address` | REJECT 65 |
| `(remote ip4 "127.0.0.1:54321")`   | `host must be * or localhost in network address` | REJECT 65 |
| `(remote ip6 "2001:db8::1:54321")` | `host must be * or localhost in network address` | REJECT 65 |

### Rejected — port forms (scoped to the `*` host, which compiles)

| Profile filter              | stderr                            | verdict                          |
| --------------------------- | --------------------------------- | -------------------------------- |
| `(remote ip "*:5000-5010")` | `invalid port in network address` | REJECT 65 — **no port ranges**   |
| `(remote ip "*:0")`         | `invalid port in network address` | REJECT 65 — port must be 1–65535 |

### Compile-OK (grammar accepted; nested apply then fails with 71)

| Profile filter                  | stderr                                                 | verdict                      |
| ------------------------------- | ------------------------------------------------------ | ---------------------------- |
| `(remote ip "*:54321")`         | `sandbox_exec: sandbox_apply: Operation not permitted` | **COMPILE OK** (71 = nested) |
| `(remote ip "localhost:54321")` | `sandbox_exec: sandbox_apply: Operation not permitted` | **COMPILE OK**               |
| `(remote ip "localhost:*")`     | `sandbox_exec: sandbox_apply: Operation not permitted` | **COMPILE OK**               |
| `(remote tcp "*:9093")`         | `sandbox_exec: sandbox_apply: Operation not permitted` | **COMPILE OK**               |

Additionally **not probed but known-good from Apple's own system profiles**
(see below): `(remote ip "*:*")`, `(remote tcp "*:*")`, `(remote udp "*:*")`
compile — but they allow **all** egress to **any** host/port and are therefore
unusable for `allowedIPs` scoping.

## Cross-checks

1. **Apple's own system profiles** (`grep -rhoE '\(remote (ip|tcp|udp)[a-z0-9]* "[^"]*"' /System/Library/Sandbox/Profiles/`): across every shipped `.sb` profile, host tokens are **only** `*` or `localhost` — e.g. `(remote tcp "*:443")` ×8, `(remote ip "*:443")` ×4, `(remote ip "localhost:631")` ×3, `(remote udp "*:*")` ×3, `(remote ip "localhost:62078")`, … **Zero** IP/CIDR/hostname literals anywhere. Apple never uses per-IP egress filters.
2. **Public SBPL documentation / prior art** (web sources, consistent across independent projects): the `*`/`localhost`-only host restriction is long-standing and documented — security.stackexchange.com/questions/133624 ("Native OS X sandbox profile to control network access (IP host based)"), apple.stackexchange.com/questions/479498, Microsoft `mxc` docs `docs/seatbelt/seatbelt-backend.md` (marks proxy-routing as the per-host workaround, kernel per-IP filtering unsupported), `motosan-sandbox` `src/seatbelt.rs` (deny-all direct egress + loopback proxy pattern), and the SBPL reference at dnesting.com. Conclusion: per-destination-IP kernel enforcement is **not expressible on any macOS build** per current public knowledge; the userspace proxy is the canonical workaround. A "feature-detect for older macOS" upgrade path is therefore speculative but harmless (see implication §).

## Patch implication (for PATCH-BRIEF.md v2)

- **Emission (macOS, restricted-profile branch):** group the configured
  `allowedIPs` entries by port and emit **one rule per unique port**:
  `(allow network-outbound (remote ip "*:<port>"))`. This is the only SBPL
  grammar that (a) compiles everywhere and (b) preserves _any_ destination
  scoping. Semantics are strictly broader than requested (any destination host
  on that port) — MUST be documented in README next to
  `allowUnauthenticatedSocksProxy` and surfaced with an emission-time
  warning/debug log naming the relaxation.
- **Port-less entries** (`"10.1.2.3"`, `"2001:db8::/32"`): remain schema-valid
  (validate as specified in the brief) but are **not emittable** — there is no
  "any port" scoping short of `*:*` (= disable egress restriction). Skip them
  at emission with a config-time/emission-time warning naming the entries.
- **Do NOT emit** the literal `CIDR:port` form on any build: when the compiler
  rejects it, the _entire profile_ fails to compile and every sandboxed command
  fails (functional regression), not just the allowed IP.
- **Optional feature-detect upgrade** (speculative): at wrap time, probe-compile
  one literal rule via `sandbox-exec -p '(version 1)(allow network-outbound
(remote ip "<entry>"))' /bin/true`; exit 65 ⇒ literal unsupported (port-scoped
  fallback), exit 0/71 ⇒ literal accepted (emit exact form). Cost: one
  subprocess per wrap; benefit: currently none known (no build is known to
  accept literals) — keep behind a cached one-shot if implemented at all.
- Config schema, `getAllowedIPs()` getter, `hasNetworkConfig` OR-extension,
  Linux/Windows log-once-and-ignore, README security note: unchanged from
  PATCH-BRIEF.md.

## Repo recon (for the v2 implementer)

- **State:** `main` @ `476bf98` = upstream v0.0.70 pin; work on a fresh
  `feat/allowed-ips` branch. Toolchain: `tsc` + `bun test` + eslint (flat
  config) + prettier (no semicolons, single quotes, ESM with **`.js` import
  suffixes** in src). Gates: `npm run typecheck`, `bun test` (full suite),
  `npm run lint:check`.
- **`src/sandbox/sandbox-config.ts`** — zod **v3**. `NetworkConfigSchema` is a
  plain `z.object` (NOT `.strict()`: unknown keys are silently stripped, so a
  misspelled `allowedIPs` today is inert — add the key explicitly). Style to
  mirror: `domainPatternSchema` uses `.refine()` with a `message:`; cross-field
  checks use `.superRefine()` + `ctx.addIssue({ code: z.ZodIssueCode.custom,
path, message })` (see `extractPatternSchema` and the big
  `SandboxRuntimeConfigSchema` superRefine). Message voice: explanatory
  sentences with examples, security rationale where relevant.
- **`src/sandbox/macos-sandbox-utils.ts`** — `generateSandboxProfile()` takes a
  destructured named-params object; a new param must be added to BOTH the
  inline param type AND the destructuring (same for `MacOSSandboxParams` and
  `wrapCommandWithSandboxMacOS`). Emit inside the `else` (restricted) branch,
  after the SOCKS-proxy block, before the `profile.push('')` that precedes
  `; File read`. Quote strings with `escapePath()` (= `JSON.stringify`).
  Logging via `logForDebugging()` from `../utils/debug.js`.
- **`src/sandbox/sandbox-manager.ts`** (~2000 lines) — module-global `config`.
  Getters cluster near `getAllowUnixSockets()` (~L1075); add `getAllowedIPs()`
  there, plus to the `ISandboxManager` interface (~L1920) and the exported
  object (~L1970). `hasNetworkConfig` is computed **twice** — in
  `wrapWithSandbox` (~L1267) and in the Windows branch of
  `wrapWithSandboxArgv` (~L1408); the brief's OR-extension applies to both.
  macOS wrap call site passes params into `wrapCommandWithSandboxMacOS`
  (~L1305–1325); Linux call site follows — pass nothing there (ignore-once).
- **`updateConfig()`** (~L1546) deep-clones the whole config and getters read
  `config` live — an added `network.allowedIPs` key hot-applies with **zero**
  extra code (do not add per-key plumbing).
- **Tests** (`bun test`, files under `test/`): schema tests import
  `SandboxRuntimeConfigSchema` and use `.safeParse()` directly
  (`test/config-validation.test.ts`, 1800+ lines — add there);
  profile-generation tests import `wrapCommandWithSandboxMacOS` and assert on
  the returned wrapped-command string / generated profile text
  (`test/sandbox/macos-seatbelt.test.ts` is the style reference; macOS-only
  suites use `describe.if(isMacOS)` from `test/helpers/platform.js`).
  `test/sandbox/update-config.test.ts` covers hot-apply.
- **Gotchas:**
  - An agent session running under pi-claude-sandbox cannot `sandbox_apply`
    (nested ⇒ exit 71); tests that exec a real sandboxed process need
    un-nested context or must tolerate/assert 71 vs 0 as "compile-OK" (see
    methodology note above).
  - Existing profile assertions must stay byte-identical when `allowedIPs` is
    absent — emit nothing (not even a comment line) unless configured.
  - Port dedupe for emission should preserve first-seen order for
    deterministic profiles (test-assertable).

_End of probe report._
