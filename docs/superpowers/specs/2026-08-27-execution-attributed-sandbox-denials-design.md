# Attempt-Attributed Sandbox Denial Reporting

## Summary

`sandbox-runtime` will report filesystem and built-in proxy denials for the exact sandboxed process attempt that caused them. Each process attempt receives a runtime-generated handle, a monitor correlation value, and a revocable proxy credential. After the process closes, the caller finishes the attempt and receives its denial summaries.

This is an additive API for `pi-sandbox`. Existing wrapping, configuration, cleanup, SSH, Windows, and session-lifecycle APIs remain compatible. The runtime does not introduce an outer execution abstraction, a new manager state machine, or automatic escalation behavior.

## Project context

`pi-sandbox` runs Pi's Bash tool through this runtime. One Bash tool call may run an initial sandboxed process and, after an existing user-approved write grant, one sandboxed recovery process. Concurrent commands and sequential retries must not consume one another's denial evidence.

The current monitors associate events with a base64 encoding of the first 100 command characters. Identical commands and shared prefixes are therefore ambiguous. The shared HTTP/SOCKS proxy enforces domain policy but does not record which process received a policy denial.

The matching `pi-sandbox` design consumes the attempt-scoped evidence, falls back to a Codex-compatible output heuristic when no structural evidence is available, and adds model-facing guidance for an eligible final failure.

## Goals

- Attribute supported macOS, Linux, and built-in proxy denials to one exact process attempt.
- Isolate concurrent identical commands and sequential recovery attempts.
- Keep one shared proxy and use revocable per-attempt credentials rather than per-attempt listeners.
- Return a small typed denial summary through an attempt-scoped finish API.
- Capture proxy events delivered immediately after process exit with a 100 ms grace period.
- Preserve command-specific `ignoreViolations` behavior without using command text as an identity.
- Let `pi-sandbox` publish its updated macOS/Linux configuration for future attempts without resetting runtime services.
- Preserve all existing compatibility APIs and behavior outside the new attributed path.

## Non-goals

- Grouping attempts in a runtime-owned outer execution.
- Human approval, reviewer-model approval, automatic escalation, or unsandboxed retry.
- Reworking runtime initialization, reset, shutdown, or manager lifecycle state.
- Replacing `updateConfig`, `wrapWithSandbox`, `wrapWithSandboxArgv`, or `cleanupAfterCommand`.
- Introducing exact per-process bwrap cleanup handles or changing current cleanup ownership.
- Adding an authenticated SSH proxy-command helper or changing current Git/SSH routing.
- Attributing traffic that uses legacy session credentials, unauthenticated SOCKS, caller-supplied proxy ports, or existing SSH compatibility paths.
- Adding Windows attempt attribution.
- Guaranteeing observation of Linux reads or every sandbox denial.
- Broad Linux observer hardening beyond bounded framing and schema validation required for the new attempt field.

## Architecture

```text
Pi process attempt
    -> prepareSandboxAttempt({ command, spawn options })
       -> monitor correlation + attempt proxy token
       -> descriptor { attempt, argv, env, sandboxBackend }
    -> caller spawns descriptor once
    -> caller waits for close and performs existing cleanupAfterCommand()
    -> finishSandboxAttempt(handle)
       -> 100 ms grace
       -> revoke correlation and token
       -> drain only this attempt's denial summaries
```

The attempt is the only runtime attribution unit. Pi owns the relationship between a tool call and its attempts. An initial and recovery process use different handles, and Pi decides which attempt is final.

## Additive public API

The following methods are added to the existing `SandboxManager` singleton and `ISandboxManager` interface. Existing public methods retain their signatures.

```ts
declare const sandboxAttemptHandleBrand: unique symbol

export interface SandboxAttemptHandle {
  readonly attemptId: string
  readonly [sandboxAttemptHandleBrand]: true
}

export type SandboxBackend =
  | 'none'
  | 'macos-seatbelt'
  | 'linux-bwrap'
  | 'linux-seccomp'

export interface PrepareSandboxAttemptOptions {
  command: string
  binShell?: string
  abortSignal?: AbortSignal
  cwd?: string
  env?: NodeJS.ProcessEnv
}

export interface SandboxAttemptDescriptor {
  attempt: SandboxAttemptHandle
  argv: string[]
  env: NodeJS.ProcessEnv
  sandboxBackend: SandboxBackend
}

export type SandboxDenialSummary =
  | {
      kind: 'filesystem'
      source: 'macos-seatbelt' | 'linux-seccomp'
    }
  | {
      kind: 'network'
      source: 'macos-seatbelt' | 'http-proxy' | 'socks-proxy'
    }

export interface FinishedSandboxAttempt {
  denials: readonly SandboxDenialSummary[]
}

export function prepareSandboxAttempt(
  options: PrepareSandboxAttemptOptions,
): Promise<SandboxAttemptDescriptor>

export function finishSandboxAttempt(
  attempt: SandboxAttemptHandle,
): Promise<FinishedSandboxAttempt>
```

Attempt IDs are random, URL-safe values generated by the runtime. Command text is retained only for `ignoreViolations`; it is never an attribution key.

A successful preparation atomically publishes the descriptor and its handle. If preparation fails, it rolls back partial correlation, credential, and queue state and returns no descriptor or handle. A returned attempt is finished once; use of an unknown or already finished handle is a programming error. Reset invalidates active attempt state as part of existing teardown, and callers must not use denial evidence from a reset attempt.

No long-lived tombstone cache, exact-object-identity authorization scheme, deep-freezing contract, or outer execution finalization is added. The handle is an in-process typed capability for a trusted package consumer, not a security boundary.

## Descriptor behavior

`prepareSandboxAttempt` is the attributed equivalent of the existing wrapper path. It builds the same macOS or Linux sandbox policy while additionally installing the attempt correlation and proxy environment.

The returned descriptor is spawned as `argv[0]` with `argv.slice(1)`, `shell: false`, and exactly the returned environment. The runtime creates a fresh environment object from the supplied `env`, or from `process.env` when omitted, and applies runtime-controlled proxy variables last. It does not mutate the caller's environment.

The attempt token and proxy URLs containing it are placed only in the descriptor environment. They do not appear in the attributed descriptor argv. Existing handleless wrappers retain their current session-credential behavior and are outside this guarantee.

`sandboxBackend` reports the wrapper actually emitted. Linux reports `linux-seccomp` only when `apply-seccomp` is in the execution chain; otherwise a bwrap wrapper reports `linux-bwrap`. Pi uses this value only for the fallback SIGSYS check.

The new attributed descriptor is supported on macOS and Linux. Other platforms reject it without changing existing handleless behavior.

Existing Git and ordinary SSH construction remains unchanged. If those paths use a legacy session credential or unauthenticated SOCKS, their requests are not attributed to the attempt and rely on Pi's heuristic fallback. This change does not add `routeSshThroughSocks`, a proxy-command helper, or new SSH configuration.

After process close or spawn failure, callers continue to invoke the existing no-argument `cleanupAfterCommand()`. Attempt finalization drains evidence only; it does not own or validate bwrap mount-point cleanup.

## Attempt registry and bounded storage

The runtime keeps one private active-attempt registry with indexes for:

- Attempt ID to attempt state.
- Monitor correlation value to attempt state.
- Proxy token to attempt state.

Attempt state contains the effective command, actual backend, the Linux write-classification data produced during wrapping, and a bounded denial queue. Each attempt retains at most its first 100 supported denials. A noisy attempt cannot evict another attempt's queue.

Public results contain only `kind` and `source`, which is all Pi needs for its cautious guidance decision. Paths, operations, hosts, ports, reason codes, raw monitor text, and timestamps may remain in bounded internal diagnostics but are not part of this public feature contract. Credentials and unrelated command output are never recorded.

## Filesystem attribution

### macOS

Each attributed attempt receives a short random correlation value embedded in its Seatbelt message tag. The log monitor parses supported tagged file and network denials, resolves the correlation through the active registry, applies that attempt's `ignoreViolations` rules, and appends a summary to that attempt's queue. Unknown or closed correlations are discarded.

### Linux

The seccomp observer sends the attempt correlation instead of a base64-encoded command. The monitor resolves the active attempt before applying its command-specific ignore rules and write-denial classification.

The wrapper records the effective write-classification data produced from the same resolved allow/deny decisions used to build that attempt's sandbox command. The monitor uses this attempt snapshot rather than initialization-time or latest-global arrays. Publishing configuration for a later attempt therefore cannot change classification of an already prepared attempt.

Linux observer input remains untrusted. The newline framer imposes a 16 KiB maximum before JSON parsing and accepts only an object with a bounded active correlation, a supported operation, and a bounded absolute path when required. Oversized or malformed frames are discarded without retaining their raw payload. More extensive observer diagnostics and protocol hardening are outside this feature.

## Shared proxy attribution

The built-in HTTP and SOCKS handlers accept both credential classes:

- An active attempt token resolves to that attempt and can create attributed denial summaries.
- The existing session token, legacy unauthenticated SOCKS behavior, and other compatibility traffic remain unattributed.

Authentication resolves the attempt before policy evaluation. When runtime domain policy or the existing request filter denies an authenticated request, the handler records a `network` summary before returning its existing protocol-level denial. Allowed requests and ordinary DNS, connection, TLS, upstream proxy, or remote-server failures do not create denial evidence.

Attempt credentials are generated only for runtime-owned proxy legs. A caller-supplied `httpProxyPort` or `socksProxyPort` receives no attempt token and produces no structured event. In mixed configurations, the runtime-owned leg may remain attributed while the external leg remains unattributed; the runtime never sends its token to the external port.

Finishing an attempt revokes its token for new authentication. Established CONNECT or SOCKS streams are not tracked or forcibly closed. Events received after the attempt closes are discarded.

## Configuration publication

This feature uses the existing synchronous `SandboxManager.updateConfig` API. It does not add `updateSandboxPolicy` or policy version objects.

On macOS and Linux, a later wrapper already compiles filesystem policy from the current configuration. The implementation and documentation will make this supported future-attempt behavior explicit. A prepared attempt keeps its wrapper and Linux classification snapshot, while a later attempt uses the updated configuration. Existing live proxy requests continue to observe the runtime's current network configuration.

Pi calls `updateConfig` only with a complete configuration derived from the same session infrastructure plus updated allowances. Infrastructure changes and Windows filesystem changes retain their existing reset requirements.

## Monitor startup and degradation

The existing `initialize(config, askCallback, enableLogMonitor?)` signature remains. Pi opts into monitoring by passing `true`.

Monitor setup and asynchronous readiness failures are diagnostic failures, not sandbox-enforcement failures. They are logged, and sandboxed execution continues without structural filesystem evidence from that monitor. Pi's output heuristic covers otherwise-unobserved denials. This matches later monitor degradation and avoids making optional telemetry a prerequisite for enforcement.

## Attempt finalization

The caller invokes `finishSandboxAttempt` only after process close and existing command cleanup. Finalization:

1. Keeps accepting events for 100 ms to capture late proxy delivery.
2. Synchronously closes event admission, revokes the attempt token and monitor correlation, and swaps out that attempt's queue.
3. Returns a copied result containing only that attempt's summaries.

An event received after close is discarded and is never reassigned by timing or active-command count. No command-text lookup or global latest-event lookup participates in this path.

## Failure handling

- Attempt allocation or preparation failure publishes no descriptor or handle and rolls back partial state.
- Unknown, malformed, legacy, or revoked proxy credentials create no attributed event.
- Unknown or closed monitor correlations are discarded.
- Monitor startup or later delivery failure logs a bounded diagnostic and does not fabricate evidence.
- Spawn failure follows the caller's existing cleanup path, then finishes the attempt.
- Reset invalidates active attempts and credentials through existing teardown. A reset-raced call receives no usable evidence and must not add guidance.
- No failure in this feature causes automatic local execution or automatic approval.

## Testing

### Registry and finalization

- Give concurrent identical commands distinct attempt IDs, correlations, tokens, and queues.
- Give sequential retries distinct evidence and drain them independently.
- Reject unknown handles without affecting another attempt.
- Roll back all partial state when preparation fails.
- Include an event delivered during the 100 ms grace period and discard one delivered after close.
- Bound each attempt independently to 100 summaries.

### Descriptor and configuration

- Return the actual macOS/Linux backend.
- Put the attempt token in the fresh returned environment and nowhere in attributed argv.
- Leave the supplied environment and `process.env` unchanged.
- Preserve existing handleless wrappers, cleanup, Windows, and SSH behavior.
- Apply `updateConfig` to a later macOS/Linux attempt without changing an already prepared attempt's Linux classification snapshot.
- Send no attempt token to caller-supplied external proxy ports.

### Monitors and proxy

- Attribute supported macOS events by correlation and ignore unrelated tagged operations.
- Attribute Linux events by correlation and the attempt's effective write-classification snapshot.
- Enforce bounded Linux framing and basic schema validation.
- Resolve HTTP and SOCKS attempt credentials and record only policy denials.
- Accept legacy compatibility traffic without attributing it.
- Revoke an attempt token at finish and never reassign a late event.
- Continue initialization when monitoring is unavailable and leave heuristic fallback to Pi.

## Release sequencing

Publish a runtime version containing the additive attempt API, then update `pi-sandbox` and its pnpm lockfile. No existing runtime API is removed, and no compatibility migration is required for other call sites.

## Acceptance criteria

- Concurrent identical commands and sequential retries cannot consume one another's denial evidence.
- Pi can prepare and finish one attempt for every sandboxed process it launches.
- Supported filesystem and built-in proxy denials are returned only by the attempt that caused them.
- Per-attempt credentials use shared ingress, are absent from attributed argv, and are revoked at finish.
- Legacy, SSH, unauthenticated, and external-proxy traffic remains functional and unattributed.
- A later macOS/Linux attempt uses the current configuration without resetting runtime services or changing an already prepared attempt's classification.
- Late events are captured for 100 ms and never reassigned after close.
- Monitor unavailability degrades to Pi's heuristic rather than blocking sandbox enforcement.
- Existing manager lifecycle, wrapping, cleanup, SSH, Windows, and configuration APIs remain intact.
- No reviewer-model, approval, or automatic escalation behavior is introduced.
