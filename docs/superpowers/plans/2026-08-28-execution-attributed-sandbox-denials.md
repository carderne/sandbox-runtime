# Execution-Attributed Sandbox Denials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add macOS, Linux, HTTP-proxy, and SOCKS-proxy denial attribution to the exact sandboxed process attempt that caused each denial, exposed through additive prepare/finish APIs.

**Architecture:** Introduce a private attempt registry indexed by random attempt ID, monitor correlation, and proxy token. Existing platform wrappers gain internal structured-result paths so the manager can build a spawn-once descriptor with an actual backend, fresh environment, correlation, and attempt-only proxy credential while legacy wrapper APIs continue delegating to their current string/argv results. Monitors and shared proxy listeners resolve attempt credentials before recording bounded summaries; `finishSandboxAttempt` owns only a 100 ms admission grace, credential revocation, and queue drain.

**Tech Stack:** TypeScript 5.6, Node.js `node:crypto`/`node:net`/`node:child_process`, Bun test runner, macOS Seatbelt, Linux bubblewrap and seccomp USER_NOTIF, `@pondwader/socks5-server`

**Spec:** `docs/superpowers/specs/2026-08-27-execution-attributed-sandbox-denials-design.md`

## Global Constraints

- This is additive to `SandboxManager` and `ISandboxManager`; existing `initialize`, `updateConfig`, `wrapWithSandbox`, `wrapWithSandboxArgv`, `cleanupAfterCommand`, reset, SSH, Windows, and session APIs keep their signatures and behavior.
- The attributed descriptor path supports macOS and Linux only; other platforms reject it without changing handleless behavior.
- Attempt IDs, monitor correlations, and proxy credentials are random URL-safe runtime values; command text is retained only for `ignoreViolations` and is never an attribution key.
- Each attempt retains its first 100 supported denial summaries independently; public results contain only `kind` and `source`.
- Finalization admits events for exactly 100 ms, then closes admission synchronously, revokes correlation/token lookup, swaps the queue, and returns a copy.
- Linux monitor framing rejects a frame larger than 16 KiB before JSON parsing and retains no raw malformed or oversized payload.
- Attempt proxy credentials are emitted only for runtime-owned HTTP/SOCKS legs, never for caller-supplied external proxy ports and never in attributed argv.
- Legacy session credentials, unauthenticated SOCKS, SSH compatibility paths, and external proxy traffic remain functional and unattributed.
- Callers spawn `argv[0]` with `argv.slice(1)`, `shell: false`, the returned environment, and the same `cwd` supplied during preparation.
- Callers invoke the existing no-argument `cleanupAfterCommand()` after close or spawn failure and before `finishSandboxAttempt()`; finishing never owns bwrap mount cleanup.
- `updateConfig` remains synchronous: later macOS/Linux attempts use current filesystem configuration, prepared attempts retain their wrapper and Linux write-classification snapshot, and live proxy requests continue using current network configuration.
- Monitor setup/readiness/delivery failure is bounded diagnostic telemetry failure and never prevents sandbox enforcement or fabricates denial evidence.
- Reset invalidates active handles and credentials; a reset-raced finish yields no usable evidence.
- Do not retain a long-lived tombstone cache or require exact JavaScript object identity for handles.
- Do not add outer execution grouping, reviewer approval, human approval, automatic escalation, unsandboxed retry, per-attempt listeners, bwrap cleanup handles, SSH proxy-command changes, or Windows attribution.
- This checkout implements and publishes the runtime half only. The matching `pi-sandbox` design must have its own linked executable plan for dependency/lockfile update, initial/recovery/spawn-failure attempt handling, heuristic fallback, and final-failure guidance; consumer rollout starts only after this runtime version is published.

## File Structure

**Create:**

- `src/sandbox/sandbox-attempt-types.ts` — public attempt API types plus narrow internal proxy-auth and Linux-classification interfaces shared across modules.
- `src/sandbox/sandbox-attempt-registry.ts` — private allocation, activation, lookup, ignore filtering, bounded queues, grace-period finalization, revocation, and reset invalidation.
- `src/sandbox/sandbox-attempt-environment.ts` — fresh descriptor-environment construction and per-leg credential overlay.
- `test/sandbox/sandbox-attempt-registry.test.ts` — platform-independent registry concurrency, bounds, revocation, reset, and timing tests.
- `test/sandbox/sandbox-attempt-environment.test.ts` — environment immutability and mixed internal/external proxy credential tests.
- `test/sandbox/proxy-attribution.test.ts` — HTTP, request-filter, and SOCKS policy-denial attribution tests.
- `test/sandbox/macos-attempt-monitor.test.ts` — pure macOS tag/parser and attempt-routing tests.
- `test/sandbox/sandbox-attempt-manager.test.ts` — public prepare/finish descriptor and lifecycle integration tests.

**Modify:**

- `src/sandbox/sandbox-manager.ts` — own the registry, start degraded monitors, wire proxy resolvers, share policy construction, and expose prepare/finish.
- `src/sandbox/sandbox-utils.ts` — support separate HTTP/SOCKS auth tokens without changing the existing single-token call form.
- `src/sandbox/macos-sandbox-utils.ts` — structured wrap result, attempt correlation tags, inherited descriptor proxy environment, and attributed monitor parsing.
- `src/sandbox/linux-sandbox-utils.ts` — structured wrap result/backend metadata, attempt correlation env, inherited descriptor proxy environment, cwd, and write-classification snapshot.
- `src/sandbox/linux-violation-monitor.ts` — dual legacy/attempt routing, bounded framing, schema validation, and active-correlation checks.
- `src/sandbox/http-proxy.ts` — dual session/attempt authentication and policy-denial recording.
- `src/sandbox/socks-proxy.ts` — dual session/attempt authentication and policy-denial recording.
- `src/sandbox/request-filter.ts` — report an actual filter denial to the authenticated request context.
- `src/sandbox/tls-terminate-proxy.ts` — carry the HTTP attempt denial recorder into terminated requests.
- `vendor/seccomp-src/apply-seccomp.c` — emit bounded `attemptCorrelation` headers/events while retaining the legacy encoded-command field for handleless wrappers.
- `test/sandbox/linux-violation-monitor.test.ts` — correlation routing, frame bounds, schema, active lookup, and real-observer protocol coverage.
- `test/sandbox/wrap-with-sandbox.test.ts` — backend metadata, cwd, inherited proxy env, and legacy-wrapper compatibility.
- `test/sandbox/update-config.test.ts` — future-attempt policy snapshot behavior.
- `src/index.ts` — export the additive public types.
- `README.md` — document descriptor spawning, cleanup/finalization ordering, degradation, and `updateConfig` semantics.

---

### Task 1: Attempt Types and Registry Lifecycle

**Files:**

- Create: `src/sandbox/sandbox-attempt-types.ts`
- Create: `src/sandbox/sandbox-attempt-registry.ts`
- Create: `test/sandbox/sandbox-attempt-registry.test.ts`

**Interfaces:**

- Consumes: `IgnoreViolationsConfig` from `src/sandbox/sandbox-config.ts`.
- Produces: the spec's `SandboxAttemptHandle`, `SandboxBackend`, `PrepareSandboxAttemptOptions`, `SandboxAttemptDescriptor`, `SandboxDenialSummary`, and `FinishedSandboxAttempt` types.
- Produces: `LinuxWriteClassification = { allowWritePaths: readonly string[]; denyWritePaths: readonly string[] }`.
- Produces: `AuthenticatedAttemptCredential.recordNetworkDenial(source: 'http-proxy' | 'socks-proxy'): void`.
- Produces: `SandboxAttemptRegistry.allocate`, `activate`, `discard`, `hasActiveCorrelation`, `recordMacOSDenial`, `recordLinuxDenial`, `resolveProxyToken`, `finish`, and `reset`.

- [ ] **Step 1: Define the public and internal types**

Create `src/sandbox/sandbox-attempt-types.ts` with the public contract copied exactly from the spec and these internal seams:

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
  | { kind: 'filesystem'; source: 'macos-seatbelt' | 'linux-seccomp' }
  | {
      kind: 'network'
      source: 'macos-seatbelt' | 'http-proxy' | 'socks-proxy'
    }

export interface FinishedSandboxAttempt {
  denials: readonly SandboxDenialSummary[]
}

export interface LinuxWriteClassification {
  readonly allowWritePaths: readonly string[]
  readonly denyWritePaths: readonly string[]
}

export interface AuthenticatedAttemptCredential {
  recordNetworkDenial(source: 'http-proxy' | 'socks-proxy'): void
}
```

- [ ] **Step 2: Write failing registry tests for exact isolation and bounded storage**

Create tests using a zero-millisecond injected grace for non-timing cases. Include concurrent identical commands, sequential attempts, forged/finished handles, independent first-100 queues, command-specific ignores, and lookup revocation:

```ts
import { describe, expect, it } from 'bun:test'
import { SandboxAttemptRegistry } from '../../src/sandbox/sandbox-attempt-registry.js'
import type { SandboxAttemptHandle } from '../../src/sandbox/sandbox-attempt-types.js'

const activate = (registry: SandboxAttemptRegistry, command = 'same command') => {
  const pending = registry.allocate({ command })
  registry.activate(pending, {
    backend: 'linux-seccomp',
    linuxWriteClassification: {
      allowWritePaths: ['/allowed'],
      denyWritePaths: ['/allowed/denied'],
    },
  })
  return pending
}

describe('SandboxAttemptRegistry', () => {
  it('isolates identical concurrent and sequential attempts', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const a = activate(registry)
    const b = activate(registry)
    registry.recordLinuxDenial(a.correlation, 'openat', '/blocked/a')
    registry.recordLinuxDenial(b.correlation, 'openat', '/blocked/b')
    expect((await registry.finish(a.handle)).denials).toEqual([
      { kind: 'filesystem', source: 'linux-seccomp' },
    ])
    expect((await registry.finish(b.handle)).denials).toEqual([
      { kind: 'filesystem', source: 'linux-seccomp' },
    ])
    const retry = activate(registry)
    expect((await registry.finish(retry.handle)).denials).toEqual([])
  })

  it('keeps the first 100 summaries per attempt', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const a = activate(registry)
    const b = activate(registry)
    for (let i = 0; i < 110; i++) {
      registry.recordLinuxDenial(a.correlation, 'openat', `/blocked/${i}`)
    }
    registry.recordLinuxDenial(b.correlation, 'openat', '/blocked/b')
    expect((await registry.finish(a.handle)).denials).toHaveLength(100)
    expect((await registry.finish(b.handle)).denials).toHaveLength(1)
  })

  it('rejects unknown and already-finished handles without touching peers', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const active = activate(registry)
    const forged = { attemptId: 'unknown' } as SandboxAttemptHandle
    await expect(registry.finish(forged)).rejects.toThrow(/unknown or already finished/i)
    await registry.finish(active.handle)
    await expect(registry.finish(active.handle)).rejects.toThrow(/unknown or already finished/i)
  })
})
```

- [ ] **Step 3: Run the registry tests to verify they fail**

Run: `bun test test/sandbox/sandbox-attempt-registry.test.ts`

Expected: FAIL because `sandbox-attempt-registry.ts` does not exist.

- [ ] **Step 4: Implement allocation, atomic activation, routing, ignores, and first-100 queues**

Implement a registry with three active indexes and no finished-ID set. `allocate()` creates random URL-safe values with `randomBytes(18).toString('base64url')` but publishes none of them. `activate()` copies command, ignore rules, backend, and classification into private state and inserts all three indexes only after validating there are no collisions. `discard()` invalidates an unpublished pending value without adding a tombstone. Resolve a public handle by its `attemptId`, not exact object identity. At the start of `finish`, mark the state as finishing so a concurrent second finish rejects while correlation/token admission remains open; after grace, close admission and remove all indexes. A later call reports `unknown or already finished sandbox attempt` without retaining the ID.

Use explicit state methods matching these signatures:

```ts
export interface PendingSandboxAttempt {
  readonly handle: SandboxAttemptHandle
  readonly correlation: string
  readonly proxyToken: string
}

export class SandboxAttemptRegistry {
  constructor(options: { finishGraceMs?: number } = {})
  allocate(options: {
    command: string
    ignoreViolations?: IgnoreViolationsConfig
  }): PendingSandboxAttempt
  activate(
    pending: PendingSandboxAttempt,
    options: {
      backend: SandboxBackend
      linuxWriteClassification?: LinuxWriteClassification
    },
  ): void
  discard(pending: PendingSandboxAttempt): void
  hasActiveCorrelation(correlation: string): boolean
  recordMacOSDenial(correlation: string, operation: string, details: string): void
  recordLinuxDenial(correlation: string, operation: string, path: string): void
  resolveProxyToken(token: string): AuthenticatedAttemptCredential | undefined
  finish(attempt: SandboxAttemptHandle): Promise<FinishedSandboxAttempt>
  reset(): void
}
```

For macOS, classify `operation.startsWith('file-')` as filesystem and `operation.startsWith('network-')` as network; discard every other operation. For Linux, accept only the supported observer operation set, normalize the absolute path with `posix.normalize`, classify against the stored allow/deny snapshot, and record `linux-seccomp` only when denied. Apply wildcard and command-specific `ignoreViolations` to `details`/`path` before enqueueing. Copy arrays on activation so later configuration mutation cannot affect an active attempt.

- [ ] **Step 5: Add grace, revocation, reset-race, and rollback tests**

Append tests that use the production 100 ms default once, fake discarded preparation, and reset during grace:

```ts
it('admits during the 100 ms grace and revokes after close', async () => {
  const registry = new SandboxAttemptRegistry()
  const a = activate(registry)
  const finishing = registry.finish(a.handle)
  setTimeout(() => {
    registry
      .resolveProxyToken(a.proxyToken)
      ?.recordNetworkDenial('http-proxy')
  }, 20)
  const result = await finishing
  expect(result.denials).toEqual([{ kind: 'network', source: 'http-proxy' }])
  expect(registry.resolveProxyToken(a.proxyToken)).toBeUndefined()
})

it('invalidates reset-raced finishes without returning evidence', async () => {
  const registry = new SandboxAttemptRegistry({ finishGraceMs: 20 })
  const a = activate(registry)
  const finishing = registry.finish(a.handle)
  registry.reset()
  await expect(finishing).rejects.toThrow(/invalidated by reset/i)
})

it('discards captured-token and monitor events after close without reassigning them', async () => {
  const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
  const closed = activate(registry)
  const capturedCredential = registry.resolveProxyToken(closed.proxyToken)!
  await registry.finish(closed.handle)
  const peer = activate(registry)
  capturedCredential.recordNetworkDenial('http-proxy')
  registry.recordLinuxDenial(closed.correlation, 'openat', '/blocked/late')
  expect((await registry.finish(peer.handle)).denials).toEqual([])
})

it('publishes no indexes for discarded preparation', () => {
  const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
  const pending = registry.allocate({ command: 'fails while wrapping' })
  registry.discard(pending)
  expect(registry.hasActiveCorrelation(pending.correlation)).toBe(false)
  expect(registry.resolveProxyToken(pending.proxyToken)).toBeUndefined()
})
```

- [ ] **Step 6: Run the registry tests**

Run: `bun test test/sandbox/sandbox-attempt-registry.test.ts`

Expected: PASS, including one test taking at least 100 ms.

- [ ] **Step 7: Commit the registry unit**

```bash
git add src/sandbox/sandbox-attempt-types.ts src/sandbox/sandbox-attempt-registry.ts test/sandbox/sandbox-attempt-registry.test.ts
git commit -m "feat: add sandbox attempt registry"
```

### Task 2: Fresh Per-Attempt Proxy Environment

**Files:**

- Create: `src/sandbox/sandbox-attempt-environment.ts`
- Create: `test/sandbox/sandbox-attempt-environment.test.ts`
- Modify: `src/sandbox/sandbox-utils.ts:397-574`

**Interfaces:**

- Consumes: a pending attempt's proxy token, the legacy session token used only by existing SSH construction, sandbox-reachable per-leg ports, caller `env`, CA path, and booleans identifying runtime-owned legs.
- Produces: `ProxyAuthTokens = string | { http?: string; socks?: string; ssh?: string }` accepted by `generateProxyEnvVars`; the string form maps to all three fields and retains exact legacy behavior.
- Produces: `buildSandboxAttemptEnvironment(options): NodeJS.ProcessEnv` returning a new object with runtime variables applied last.

- [ ] **Step 1: Write failing environment tests**

```ts
import { describe, expect, it } from 'bun:test'
import { buildSandboxAttemptEnvironment } from '../../src/sandbox/sandbox-attempt-environment.js'

describe('buildSandboxAttemptEnvironment', () => {
  it('does not mutate the supplied environment and overwrites proxy variables last', () => {
    const supplied = { KEEP: 'yes', HTTPS_PROXY: 'http://stale.invalid' }
    const result = buildSandboxAttemptEnvironment({
      env: supplied,
      sandboxHttpProxyPort: 60080,
      sandboxSocksProxyPort: 60080,
      runtimeOwnsHttpProxy: true,
      runtimeOwnsSocksProxy: true,
      attemptProxyToken: 'attempt-token',
      legacySshProxyToken: 'session-token',
    })
    expect(result).not.toBe(supplied)
    expect(supplied.HTTPS_PROXY).toBe('http://stale.invalid')
    expect(result.KEEP).toBe('yes')
    expect(result.HTTPS_PROXY).toContain('srt:attempt-token@localhost:60080')
  })

  it('never sends the attempt token to an external leg', () => {
    const result = buildSandboxAttemptEnvironment({
      env: {},
      sandboxHttpProxyPort: 7777,
      sandboxSocksProxyPort: 60080,
      runtimeOwnsHttpProxy: false,
      runtimeOwnsSocksProxy: true,
      attemptProxyToken: 'attempt-token',
      legacySshProxyToken: 'session-token',
    })
    expect(result.HTTPS_PROXY).toBe('http://localhost:7777')
    expect(result.FTP_PROXY).toContain('srt:attempt-token@localhost:60080')
    expect(result.HTTPS_PROXY).not.toContain('attempt-token')
  })

  it('uses sandbox-reachable Linux bridge ports and keeps SSH unattributed', () => {
    const result = buildSandboxAttemptEnvironment({
      env: {},
      sandboxHttpProxyPort: 3128,
      sandboxSocksProxyPort: 1080,
      runtimeOwnsHttpProxy: true,
      runtimeOwnsSocksProxy: true,
      attemptProxyToken: 'attempt-token',
      legacySshProxyToken: 'session-token',
    })
    expect(result.HTTPS_PROXY).toContain('attempt-token@localhost:3128')
    expect(result.FTP_PROXY).toContain('attempt-token@localhost:1080')
    expect(result.GIT_SSH_COMMAND).not.toContain('attempt-token')
    if (process.platform === 'linux') {
      expect(result.GIT_SSH_COMMAND).toContain('session-token')
    }
  })

  it('does not mutate process.env when no environment is supplied', () => {
    const before = { ...process.env }
    buildSandboxAttemptEnvironment({
      sandboxHttpProxyPort: 60080,
      sandboxSocksProxyPort: 60080,
      runtimeOwnsHttpProxy: true,
      runtimeOwnsSocksProxy: true,
      attemptProxyToken: 'attempt-token',
      legacySshProxyToken: 'session-token',
    })
    expect(process.env).toEqual(before)
  })
})
```

- [ ] **Step 2: Run the environment tests to verify they fail**

Run: `bun test test/sandbox/sandbox-attempt-environment.test.ts`

Expected: FAIL because the environment builder does not exist.

- [ ] **Step 3: Refactor proxy assignment generation for per-leg auth**

Change only the auth-token parameter shape; preserve all current variables and values for string callers:

```ts
export type ProxyAuthTokens =
  | string
  | {
      readonly http?: string
      readonly socks?: string
      readonly ssh?: string
    }

export function generateProxyEnvVars(
  httpProxyPort?: number,
  socksProxyPort?: number,
  caCertPath?: string,
  proxyAuthTokens?: ProxyAuthTokens,
  skipTmpdir?: boolean,
): string[] {
  const httpToken =
    typeof proxyAuthTokens === 'string'
      ? proxyAuthTokens
      : proxyAuthTokens?.http
  const socksToken =
    typeof proxyAuthTokens === 'string'
      ? proxyAuthTokens
      : proxyAuthTokens?.socks
  const sshToken =
    typeof proxyAuthTokens === 'string'
      ? proxyAuthTokens
      : proxyAuthTokens?.ssh
  const httpAuth = httpToken ? `srt:${httpToken}@` : ''
  const socksAuth = socksToken ? `srt:${socksToken}@` : ''
  const sshAuth = sshToken ? `,proxyauth=srt:${sshToken}` : ''
  // Keep the existing variable set; use httpAuth for HTTP/HTTPS, Git HTTP,
  // and gcloud values, socksAuth for SOCKS/FTP/gRPC values, and sshAuth only
  // for the existing Linux GIT_SSH_COMMAND compatibility route.
}
```

When `ALL_PROXY` chooses the HTTP port, use `httpAuth`; only its SOCKS-only fallback uses `socksAuth`. Use `sshAuth`, never `httpAuth`, in Linux `GIT_SSH_COMMAND`. Add assertions showing a string token still appears in every legacy location, while the object form can use an attempt token for HTTP/SOCKS and the session token for SSH.

- [ ] **Step 4: Implement the fresh environment builder**

Parse `KEY=value` assignments on the first `=` and merge them after the supplied environment:

```ts
export function buildSandboxAttemptEnvironment(options: {
  env?: NodeJS.ProcessEnv
  sandboxHttpProxyPort?: number
  sandboxSocksProxyPort?: number
  runtimeOwnsHttpProxy: boolean
  runtimeOwnsSocksProxy: boolean
  attemptProxyToken: string
  legacySshProxyToken?: string
  caCertPath?: string
  skipTmpdir?: boolean
}): NodeJS.ProcessEnv {
  const tokens = {
    http: options.runtimeOwnsHttpProxy
      ? options.attemptProxyToken
      : undefined,
    socks: options.runtimeOwnsSocksProxy
      ? options.attemptProxyToken
      : undefined,
    ssh: options.runtimeOwnsHttpProxy
      ? options.legacySshProxyToken
      : undefined,
  }
  const assignments = generateProxyEnvVars(
    options.sandboxHttpProxyPort,
    options.sandboxSocksProxyPort,
    options.caCertPath,
    tokens,
    options.skipTmpdir,
  )
  const overlay: NodeJS.ProcessEnv = {}
  for (const assignment of assignments) {
    const equals = assignment.indexOf('=')
    if (equals >= 0) overlay[assignment.slice(0, equals)] = assignment.slice(equals + 1)
  }
  return { ...(options.env ?? process.env), ...overlay }
}
```

- [ ] **Step 5: Run focused environment compatibility tests**

Run: `bun test test/sandbox/sandbox-attempt-environment.test.ts test/sandbox/proxy-env-vars.test.ts test/sandbox/sandbox-env-tmpdir.test.ts`

Expected: PASS; supplied objects remain unchanged and legacy single-token output is unchanged.

- [ ] **Step 6: Commit the environment unit**

```bash
git add src/sandbox/sandbox-attempt-environment.ts src/sandbox/sandbox-utils.ts test/sandbox/sandbox-attempt-environment.test.ts test/sandbox/proxy-env-vars.test.ts
git commit -m "feat: build per-attempt proxy environments"
```

### Task 3: Structured Platform Wrapper Results

**Files:**

- Modify: `src/sandbox/macos-sandbox-utils.ts:23-56, 96-99, 829-982`
- Modify: `src/sandbox/linux-sandbox-utils.ts:36-91, 1351-1640`
- Modify: `test/sandbox/wrap-with-sandbox.test.ts`

**Interfaces:**

- Consumes: `SandboxBackend`, `LinuxWriteClassification`, optional `monitorCorrelation`, `cwd`, and `embedProxyEnvironment`.
- Produces: `prepareCommandWithSandboxMacOS(params): MacOSSandboxWrapResult` and the unchanged `wrapCommandWithSandboxMacOS(params): string` delegate.
- Produces: `prepareCommandWithSandboxLinux(params): Promise<LinuxSandboxWrapResult>` and the unchanged `wrapCommandWithSandboxLinux(params): Promise<string>` delegate.

- [ ] **Step 1: Write failing structured-wrapper tests**

Add platform-conditional assertions around direct wrapper calls. Extend the test imports with `mkdtempSync`, `mkdirSync`, and `rmSync` from `node:fs`, `tmpdir` from `node:os`, and `join` from `node:path`:

```ts
it.if(isMacOS)('reports none or macos-seatbelt and uses an attempt tag', () => {
  const plain = prepareCommandWithSandboxMacOS({
    command: 'echo ok',
    needsNetworkRestriction: false,
    readConfig: { denyOnly: [] },
    writeConfig: undefined,
    monitorCorrelation: 'corr_1234567890',
    embedProxyEnvironment: false,
  })
  expect(plain.sandboxBackend).toBe('none')
  const wrapped = prepareCommandWithSandboxMacOS({
    command: 'cat /private/blocked',
    needsNetworkRestriction: false,
    readConfig: { denyOnly: ['/private/blocked'] },
    writeConfig: undefined,
    monitorCorrelation: 'corr_1234567890',
    embedProxyEnvironment: false,
  })
  expect(wrapped.sandboxBackend).toBe('macos-seatbelt')
  expect(wrapped.command).toContain('SRTATTEMPT_corr_1234567890_END_')
})

it.if(isLinux)('reports the emitted Linux backend and classification snapshot', async () => {
  const allowDir = mkdtempSync(join(tmpdir(), 'srt-write-classification-'))
  const denyDir = join(allowDir, 'no')
  mkdirSync(denyDir)
  try {
    const result = await prepareCommandWithSandboxLinux({
      command: 'echo ok',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [allowDir], denyWithinAllow: [denyDir] },
      monitorCorrelation: 'corr_1234567890',
      embedProxyEnvironment: false,
    })
    expect(['linux-bwrap', 'linux-seccomp']).toContain(result.sandboxBackend)
    expect(result.linuxWriteClassification).toEqual({
      allowWritePaths: [allowDir],
      denyWritePaths: [denyDir],
    })
    expect(result.command).toContain('SRT_ATTEMPT_CORRELATION')
  } finally {
    rmSync(allowDir, { recursive: true, force: true })
  }
})
```

- [ ] **Step 2: Run the wrapper tests to verify they fail**

Run: `bun test test/sandbox/wrap-with-sandbox.test.ts`

Expected: FAIL because the structured preparation functions are not exported.

- [ ] **Step 3: Add the macOS structured path without changing the legacy result**

Add `cwd?: string`, `monitorCorrelation?: string`, and `embedProxyEnvironment?: boolean` to `MacOSSandboxParams`. Make mandatory project deny paths resolve from `cwd ?? process.cwd()`. Generate `SRTATTEMPT_<correlation>_END_<sessionSuffix>` when a correlation is present and retain `CMD64_<encoded command>_END_<sessionSuffix>` otherwise. The explicit `_END_` delimiter makes parsing unambiguous even though URL-safe correlations may contain `_`. Skip `generateProxyEnvVars` only when `embedProxyEnvironment === false`.

Use these result types and delegation:

```ts
export interface MacOSSandboxWrapResult {
  command: string
  sandboxBackend: 'none' | 'macos-seatbelt'
}

export function prepareCommandWithSandboxMacOS(
  params: MacOSSandboxParams,
): MacOSSandboxWrapResult

export function wrapCommandWithSandboxMacOS(params: MacOSSandboxParams): string {
  return prepareCommandWithSandboxMacOS(params).command
}
```

- [ ] **Step 4: Add the Linux structured path and actual backend reporting**

Add the same three optional parameters to `LinuxSandboxParams`. Preserve the resolved `applySeccompPrefix` decision and return `linux-seccomp` only when it is present in the emitted chain; return `linux-bwrap` for bwrap without it and `none` for the early unchanged-command path. Set `SRT_ATTEMPT_CORRELATION` instead of `SRT_ENCODED_CMD` only for an attributed wrap. Skip proxy `--setenv` entries only when `embedProxyEnvironment === false`; bwrap inherits the returned descriptor environment.

```ts
export interface LinuxSandboxWrapResult {
  command: string
  sandboxBackend: 'none' | 'linux-bwrap' | 'linux-seccomp'
  linuxWriteClassification?: LinuxWriteClassification
}

export async function prepareCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<LinuxSandboxWrapResult>

export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  return (await prepareCommandWithSandboxLinux(params)).command
}
```

Change Linux filesystem generation to return its emitted arguments and the effective write decisions together:

```ts
interface LinuxFilesystemBuildResult {
  args: string[]
  writeClassification: LinuxWriteClassification
}

async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  maskedFileBinds: readonly MaskedFileBind[] | undefined,
  maskedFileStoreDir: string | undefined,
  ripgrepConfig: { command: string; args?: string[] },
  mandatoryDenySearchDepth: number,
  abortSignal: AbortSignal | undefined,
): Promise<LinuxFilesystemBuildResult>
```

Accumulate `allowWritePaths` only at the same branches that emit effective writable binds after normalization, existence/ancestor checks, glob expansion, and symlink resolution. Accumulate `denyWritePaths` from the exact resolved read-only carve-outs and mandatory deny decisions that override those writable binds. Return copies with the bwrap argv; do not reconstruct classification later from input config. For `writeConfig === undefined`, return `allowWritePaths: ['/']` and `denyWritePaths: []`, because bwrap permits host writes when filesystem policy is disabled.

Add focused Linux tests where a configured allow path is skipped, a deny path resolves through a symlink, and a mandatory project deny overrides an allowed ancestor. Assert the classification matches the actual emitted `--bind`/`--ro-bind` policy in every case.

- [ ] **Step 5: Prove legacy wrappers still embed their session credential**

Add assertions that default calls still include `proxyAuthToken` in the legacy wrapper and attributed-mode direct calls with `embedProxyEnvironment: false` do not:

```ts
expect(legacyWrapped).toContain('session-token')
expect(attributedResult.command).not.toContain('attempt-token')
```

- [ ] **Step 6: Run wrapper and integration tests**

Run: `bun test test/sandbox/wrap-with-sandbox.test.ts test/sandbox/integration.test.ts`

Expected: PASS with no change to existing wrapper callers.

- [ ] **Step 7: Commit the wrapper unit**

```bash
git add src/sandbox/macos-sandbox-utils.ts src/sandbox/linux-sandbox-utils.ts test/sandbox/wrap-with-sandbox.test.ts
git commit -m "refactor: expose sandbox wrapper metadata"
```

### Task 4: Shared Proxy Attempt Authentication and Denial Recording

**Files:**

- Create: `test/sandbox/proxy-attribution.test.ts`
- Modify: `src/sandbox/http-proxy.ts:27-115, 119-170, 300-380`
- Modify: `src/sandbox/socks-proxy.ts:10-90`
- Modify: `src/sandbox/request-filter.ts:72-132`
- Modify: `src/sandbox/tls-terminate-proxy.ts:112-245`

**Interfaces:**

- Consumes: `resolveAttemptProxyToken(token: string): AuthenticatedAttemptCredential | undefined` while retaining `proxyAuthToken` for the legacy session credential.
- Produces: HTTP/SOCKS handlers that authenticate before policy evaluation and invoke `recordNetworkDenial` only for domain-policy or request-filter denial.
- Produces: `decideAndRespond(..., onPolicyDenied?: () => void)`; the callback runs for a returned/thrown filter denial, not malformed parsing, upstream, DNS, TLS, or connection failure.

- [ ] **Step 1: Write failing HTTP attribution tests**

Create a raw CONNECT helper and test session, attempt, revoked, and unknown credentials. Use a recorder that pushes sources:

```ts
const recorded: string[] = []
const attempt = {
  recordNetworkDenial: (source: 'http-proxy' | 'socks-proxy') =>
    recorded.push(source),
}
const proxy = createHttpProxyServer({
  filter: () => false,
  proxyAuthToken: 'session-token',
  resolveAttemptProxyToken: token =>
    token === 'attempt-token' ? attempt : undefined,
})
```

Assert attempt auth receives 403 and records `http-proxy`; session auth receives the same 403 without recording; unknown auth receives 407 without recording. Add a plain-HTTP `filterRequest` denial case and a filter throw case that each record once, plus an upstream 502 case that records nothing.

- [ ] **Step 2: Write failing SOCKS attribution tests**

Drive a minimal SOCKS5 username/password handshake over `node:net`, advertise method `0x02`, send username `srt`, and assert a denied attempt request records `socks-proxy`. Send the session token and an unknown token in separate connections; the session request remains unattributed and the unknown token fails authentication. Keep an unauthenticated compatibility case for `allowUnauthenticatedSocksProxy` with no recorder.

- [ ] **Step 3: Run proxy attribution tests to verify they fail**

Run: `bun test test/sandbox/proxy-attribution.test.ts`

Expected: FAIL because proxy options do not resolve attempt credentials.

- [ ] **Step 4: Return authentication context instead of a boolean in HTTP**

Add this option and local result:

```ts
resolveAttemptProxyToken?: (
  token: string,
) => AuthenticatedAttemptCredential | undefined

type ProxyAuthentication =
  | { authenticated: false }
  | {
      authenticated: true
      attempt?: AuthenticatedAttemptCredential
    }
```

Parse Basic credentials once. Accept the configured session token with no `attempt`, otherwise resolve the supplied token through `resolveAttemptProxyToken`. Carry the result through CONNECT and regular request handling. Immediately before existing 403 responses caused by `options.filter === false`, call `auth.attempt?.recordNetworkDenial('http-proxy')`.

- [ ] **Step 5: Carry request-filter denials through plain and terminated HTTP**

Add an optional final callback to `decideAndRespond`. Invoke it exactly once after the callback returns `{ action: 'deny' }` or throws and before writing the 403. Thread the authenticated attempt recorder from `http-proxy.ts` into both its direct call and `terminateAndForward`/`forwardUpstream` in `tls-terminate-proxy.ts`:

```ts
const onPolicyDenied = auth.attempt
  ? () => auth.attempt!.recordNetworkDenial('http-proxy')
  : undefined
```

Do not invoke it when constructing `Request` fails, when the client disconnects, or when any upstream leg fails.

- [ ] **Step 6: Carry attempt context from SOCKS authentication to its ruleset**

Add `resolveAttemptProxyToken` to `SocksProxyServerOptions`. In authenticated mode, accept either the legacy session token or an active attempt token. Store only an attributed resolution in a `WeakMap<object, AuthenticatedAttemptCredential>` keyed by the library connection object. When the existing domain filter returns false, read the map and record `socks-proxy` before returning false. Unknown/malformed/revoked tokens and upstream failures record nothing.

When unauthenticated SOCKS compatibility is enabled, accept both methods without attributing no-auth traffic. Because `@pondwader/socks5-server` supports only one method policy per instance, create authenticated and no-auth state machines with the same ruleset/connection handler and add a bounded greeting selector in `SocksProxyWrapper.handleConnection`: clients offering username/password (`0x02`) go to the authenticated state machine, while clients offering only no-auth (`0x00`) go to the compatibility state machine. Unshift every peeked byte before dispatch so the selected parser sees the complete greeting. A no-auth connection never receives an attempt recorder.

- [ ] **Step 7: Run focused proxy regression tests**

Run: `bun test test/sandbox/proxy-attribution.test.ts test/sandbox/request-filter.test.ts test/sandbox/connect-non-tls.test.ts test/sandbox/mux-proxy.test.ts test/sandbox/parent-proxy-tunnel.test.ts`

Expected: PASS; all existing protocol status codes and responses remain unchanged.

- [ ] **Step 8: Commit the proxy unit**

```bash
git add src/sandbox/http-proxy.ts src/sandbox/socks-proxy.ts src/sandbox/request-filter.ts src/sandbox/tls-terminate-proxy.ts test/sandbox/proxy-attribution.test.ts
git commit -m "feat: attribute shared proxy policy denials"
```

### Task 5: macOS Correlation Parsing and Routing

**Files:**

- Create: `test/sandbox/macos-attempt-monitor.test.ts`
- Modify: `src/sandbox/macos-sandbox-utils.ts:79-102, 998-1110`

**Interfaces:**

- Consumes: `recordMacOSDenial(correlation, operation, details)` from the registry and the existing legacy `SandboxViolationCallback`.
- Produces: a pure `parseMacOSSandboxDenial(text)` parser and a monitor option `recordAttemptDenial` while retaining legacy command-tag reporting.

- [ ] **Step 1: Write failing parser and routing tests**

Use realistic compact-log fragments and assert the parser distinguishes attempt and legacy tags:

```ts
expect(
  parseMacOSSandboxDenial(
    'SRTATTEMPT_corr_abcdefgh_END__123_SBX\nSandbox: bash(1) deny(1) file-read-data /secret',
  ),
).toEqual({
  attribution: { kind: 'attempt', correlation: 'corr_abcdefgh' },
  operation: 'file-read-data',
  details: 'bash(1) deny(1) file-read-data /secret',
})
```

Add cases for `network-outbound`, an unrelated `mach-lookup`, an unknown correlation, a closed correlation, and command/wildcard ignore rules. Assert only supported file/network records reach the finished attempt.

- [ ] **Step 2: Run the macOS monitor tests to verify they fail**

Run: `bun test test/sandbox/macos-attempt-monitor.test.ts`

Expected: FAIL because the pure parser and attributed callback do not exist.

- [ ] **Step 3: Extract pure parsing and retain the legacy callback**

Define a discriminated parse result:

```ts
export type ParsedMacOSSandboxDenial = {
  attribution:
    | { kind: 'attempt'; correlation: string }
    | { kind: 'legacy'; encodedCommand?: string; command?: string }
  operation: string
  details: string
}
```

Bound correlation extraction to URL-safe `[A-Za-z0-9_-]{8,128}`. Extract the operation token immediately following `deny`/`deny(1)`. Return `undefined` for malformed input and preserve the existing noisy diagnostic exclusions. Never log or retain the raw malformed message.

- [ ] **Step 4: Route attempt tags before legacy storage**

Change the monitor signature to an options object or an additional optional argument that supplies:

```ts
recordAttemptDenial?: (
  correlation: string,
  operation: string,
  details: string,
) => void
```

For attempt tags, invoke only this callback; do not construct a `SandboxViolationEvent` and do not append to `SandboxViolationStore`. For legacy `CMD64` tags, retain command decode, ignore handling, event shape, and callback behavior exactly.

- [ ] **Step 5: Run macOS focused tests**

Run: `bun test test/sandbox/macos-attempt-monitor.test.ts test/sandbox/macos-seatbelt.test.ts test/sandbox/macos-apple-events.test.ts`

Expected: PASS on macOS; pure parser tests pass on every platform.

- [ ] **Step 6: Commit the macOS monitor unit**

```bash
git add src/sandbox/macos-sandbox-utils.ts test/sandbox/macos-attempt-monitor.test.ts
git commit -m "feat: route macOS denials by attempt correlation"
```

### Task 6: Linux Correlation Protocol, Bounded Framing, and Snapshot Classification

**Files:**

- Modify: `src/sandbox/linux-violation-monitor.ts`
- Modify: `vendor/seccomp-src/apply-seccomp.c:94-105, 443-468, 676-680, 750-766, 836-838`
- Modify: `test/sandbox/linux-violation-monitor.test.ts`

**Interfaces:**

- Consumes: `SRT_ATTEMPT_CORRELATION`, `hasActiveCorrelation`, and `recordAttemptDenial(correlation, operation, path)`.
- Produces: dual protocol handling: attributed `attemptCorrelation` routes to registry snapshots; legacy `encodedCommand` keeps the violation-store path.
- Produces: newline framing with `MAX_OBSERVER_FRAME_BYTES = 16 * 1024`, `MAX_CORRELATION_CHARS = 128`, and `MAX_OBSERVER_PATH_CHARS = 4096`.

- [ ] **Step 1: Replace listener tests with explicit attributed and legacy cases**

Extend the listener setup with active-correlation callbacks and send both protocols:

```ts
const active = new Set(['corr_abcdefgh'])
const attributed: Array<{ correlation: string; operation: string; path: string }> = []
mon = startLinuxSandboxViolationMonitor(v => legacy.push(v), legacyOptions, {
  hasActiveCorrelation: correlation => active.has(correlation),
  recordAttemptDenial: (correlation, operation, path) =>
    attributed.push({ correlation, operation, path }),
})
```

Assert a header `{ "attemptCorrelation": "corr_abcdefgh" }` followed by supported absolute-path events reaches `attributed`, while `{ "encodedCommand": "dGVzdA==" }` retains current legacy behavior. Assert inactive correlations, relative paths, unsupported operations, non-object JSON, overlong correlation/path, and a 16 KiB-plus-one frame are dropped.

- [ ] **Step 2: Add split/coalesced/oversized frame tests**

Write bytes in chunks that split a JSON line across packets and coalesce several lines into one packet. Send an oversized frame followed by a valid newline-delimited frame on the same connection and assert the oversized frame is discarded without poisoning the valid one.

- [ ] **Step 3: Run Linux monitor tests to verify they fail**

Run: `bun test test/sandbox/linux-violation-monitor.test.ts`

Expected: FAIL because the listener still uses unbounded `readline` and knows only `encodedCommand`.

- [ ] **Step 4: Implement bounded manual framing and schema validation**

Replace `readline` with a per-connection `Buffer` accumulator and an `discardUntilNewline` flag. Check size before `JSON.parse`; once a frame exceeds 16 KiB, drop bytes through the next newline. Accept only a non-array object whose header has one bounded correlation/encoded command, or whose event has a supported operation and an absolute path no longer than 4096 characters. Do not include raw input in diagnostics.

The first valid header of either kind is authoritative for the connection. An attributed header must satisfy `hasActiveCorrelation` when received and again before each record. Route attributed events to `recordAttemptDenial`; keep the current legacy classification and `SandboxViolationEvent` callback for encoded commands. Define the supported operation set exactly as `openat`, `openat2`, `unlinkat`, `mkdirat`, `mknodat`, `symlinkat`, `linkat`, `renameat`, `renameat2`, `fchmodat`, `fchmodat2`, `fchownat`, `utimensat`, `open`, `creat`, `unlink`, `rmdir`, `rename`, `link`, `symlink`, `mkdir`, `mknod`, `truncate`, `chmod`, `chown`, `lchown`, `utime`, and `utimes` so the TypeScript schema stays aligned with `observe_calls` in C.

- [ ] **Step 5: Change the C observer to emit attempt correlation without removing legacy support**

Read both environment variables before namespace setup:

```c
const char *attempt_correlation = getenv("SRT_ATTEMPT_CORRELATION");
const char *encoded_cmd = getenv("SRT_ENCODED_CMD");
```

If `attempt_correlation` is present, emit a bounded header and add `"attemptCorrelation":"..."` to event lines; otherwise retain `encodedCommand`. Limit correlation formatting to 128 characters, JSON-escape it, and unset both environment variables before `execvp`. Do not change observer failure, nonblocking delivery, syscall continuation, namespace, or exit-status behavior.

- [ ] **Step 6: Build and exercise the real observer on Linux**

Run on Linux: `npm run build:seccomp`

Expected on Linux: `vendor/seccomp/apply-seccomp` builds with `-Wall -Wextra` and no compiler error. On macOS/Windows, record the platform skip and require the same command in Linux CI before merge.

Run: `bun test test/sandbox/linux-violation-monitor.test.ts`

Expected: PASS, including the real-binary tests when the host is Linux and the binary is available.

- [ ] **Step 7: Commit the Linux monitor unit**

```bash
git add src/sandbox/linux-violation-monitor.ts vendor/seccomp-src/apply-seccomp.c test/sandbox/linux-violation-monitor.test.ts
git commit -m "feat: route Linux denials by attempt correlation"
```

### Task 7: Public Prepare/Finish Manager Integration

**Files:**

- Create: `test/sandbox/sandbox-attempt-manager.test.ts`
- Modify: `src/sandbox/sandbox-manager.ts:1-145, 322-455, 1158-1521, 1700-1833, 1905-1990`
- Modify: `test/sandbox/update-config.test.ts`
- Modify: `src/index.ts`

**Interfaces:**

- Consumes: all prior task interfaces.
- Produces: `SandboxManager.prepareSandboxAttempt(options): Promise<SandboxAttemptDescriptor>` and `SandboxManager.finishSandboxAttempt(attempt): Promise<FinishedSandboxAttempt>` on `ISandboxManager`.
- Produces: exact attempt-scoped descriptor spawn contract, monitor/proxy routing, preparation rollback, reset invalidation, and future-attempt config snapshots.

- [ ] **Step 1: Write failing public descriptor tests**

Create platform-conditional tests with reset in `beforeEach`/`afterEach`. Cover unique handles for identical commands, fresh env, supplied-env and default-`process.env` immutability, actual backend, token absent from argv, spawn-once execution, unknown/double finish, unsupported platform, spawn-failure cleanup ordering, and reset invalidation. Use `mkdtempSync` to supply a cwd different from `process.cwd()`, spawn with that same directory, and on macOS assert the generated mandatory-deny profile resolves project paths against it:

```ts
const supplied = { ...process.env, KEEP: 'yes', HTTPS_PROXY: 'stale' }
const descriptor = await SandboxManager.prepareSandboxAttempt({
  command: 'printf attributed',
  cwd: attemptCwd,
  env: supplied,
})
expect(descriptor.attempt.attemptId).toMatch(/^[A-Za-z0-9_-]+$/)
const token = new URL(descriptor.env.HTTPS_PROXY!).password
expect(token).not.toBe('')
expect(descriptor.argv.join('\0')).not.toContain(token)
expect(descriptor.env).not.toBe(supplied)
expect(supplied.HTTPS_PROXY).toBe('stale')
const child = spawn(descriptor.argv[0]!, descriptor.argv.slice(1), {
  shell: false,
  cwd: attemptCwd,
  env: descriptor.env,
})
await once(child, 'close')
SandboxManager.cleanupAfterCommand()
expect((await SandboxManager.finishSandboxAttempt(descriptor.attempt)).denials).toEqual([])
```

Add a caller-lifecycle test that prepares successfully, forces `spawn` to emit `error` for a nonexistent executable, and uses the same `try/finally` pattern documented in Task 8. Spy on `cleanupAfterCommand` and `finishSandboxAttempt` to assert each runs once and in that order after the spawn error.

- [ ] **Step 2: Write failing end-to-end policy-denial and config-snapshot tests**

Prepare two identical commands, authenticate raw proxy requests from each descriptor's proxy URL, deny both, and finish them independently. Add a mixed external-port case proving only the runtime-owned leg contains the attempt token.

On Linux, assert the returned `HTTPS_PROXY`/`HTTP_PROXY` point to `localhost:3128` and SOCKS-specific variables point to `localhost:1080`, then actually spawn the descriptor and observe an authenticated denied HTTP request through the socat bridge. Assert the resulting summary is `http-proxy`. Verify `GIT_SSH_COMMAND` contains the legacy session credential (when the runtime owns HTTP ingress), never the attempt token, and a denied SSH compatibility request does not enter the attempt queue.

Force a real manager preparation failure with an unresolvable shell. Spy on `SandboxAttemptRegistry.prototype.allocate`, `activate`, and `discard`; capture the pending registration and assert `discard` runs, `activate` does not, and the registry unit contract leaves its ID/correlation/token unpublished. This couples manager rollback control flow to the lookup-level rollback test from Task 1 without exposing the singleton registry publicly.

Stub the current platform's monitor factory to throw synchronously and, for Linux, return a monitor whose readiness rejects. Assert `initialize(config, undefined, true)` still resolves, wrapping/preparation still emits an enforcing sandbox, and no structural filesystem summary is fabricated. Restore the spies after each case.

For Linux classification, prepare attempt A with `/tmp/a` writable, call `updateConfig` with `/tmp/b` writable, prepare B, inject the same correlated path into the monitor seam, and assert A uses its A snapshot while B uses B. On macOS, assert the second generated profile reflects the updated current config while A's argv is byte-for-byte unchanged.

- [ ] **Step 3: Run manager tests to verify they fail**

Run: `bun test test/sandbox/sandbox-attempt-manager.test.ts test/sandbox/update-config.test.ts`

Expected: FAIL because the public methods are absent.

- [ ] **Step 4: Share policy construction between legacy and attributed wrappers**

Extract the filesystem, credential, network, cwd, and platform switch portion of `wrapWithSandbox` into a private builder:

```ts
interface BuildSandboxCommandOptions {
  command: string
  binShell?: string
  customConfig?: Partial<SandboxRuntimeConfig>
  abortSignal?: AbortSignal
  cwd?: string
  monitorCorrelation?: string
  embedProxyEnvironment: boolean
}

interface BuiltSandboxCommand {
  command: string
  sandboxBackend: SandboxBackend
  linuxWriteClassification?: LinuxWriteClassification
  filesystemDisabled: boolean
  needsNetworkProxy: boolean
}

async function buildSandboxCommand(
  options: BuildSandboxCommandOptions,
): Promise<BuiltSandboxCommand>
```

Keep `wrapWithSandbox` as a delegate returning `.command` with `embedProxyEnvironment: true`, no correlation, and current behavior. Keep `wrapWithSandboxArgv` unchanged except for delegating through that legacy path.

- [ ] **Step 5: Implement atomic attempt preparation**

Reject non-macOS/Linux before allocation. Allocate a pending attempt with the effective command and current ignore rules, build the structured wrapper with its correlation and `embedProxyEnvironment: false`, build a fresh environment using the pending proxy token, and activate only after argv/environment construction succeeds. Use `binShell ?? '/bin/bash'` for the outer descriptor argv, matching current macOS/Linux `wrapWithSandboxArgv` semantics.

```ts
async function prepareSandboxAttempt(
  options: PrepareSandboxAttemptOptions,
): Promise<SandboxAttemptDescriptor> {
  const platform = getPlatform()
  if (platform !== 'macos' && platform !== 'linux') {
    throw new Error(`Sandbox attempts are not supported on platform: ${platform}`)
  }
  const pending = attemptRegistry.allocate({
    command: options.command,
    ignoreViolations: getIgnoreViolations(),
  })
  try {
    const built = await buildSandboxCommand({
      command: options.command,
      binShell: options.binShell,
      abortSignal: options.abortSignal,
      cwd: options.cwd,
      monitorCorrelation: pending.correlation,
      embedProxyEnvironment: false,
    })
    const env = buildSandboxAttemptEnvironment({
      env: options.env,
      sandboxHttpProxyPort:
        !built.needsNetworkProxy
          ? undefined
          : platform === 'linux'
            ? 3128
            : getProxyPort(),
      sandboxSocksProxyPort:
        !built.needsNetworkProxy
          ? undefined
          : platform === 'linux'
            ? 1080
            : getSocksProxyPort(),
      runtimeOwnsHttpProxy: config?.network.httpProxyPort === undefined,
      runtimeOwnsSocksProxy: config?.network.socksProxyPort === undefined,
      attemptProxyToken: pending.proxyToken,
      legacySshProxyToken: proxyAuthToken,
      caCertPath: mitmCA?.trustBundlePath,
      skipTmpdir: built.filesystemDisabled,
    })
    attemptRegistry.activate(pending, {
      backend: built.sandboxBackend,
      linuxWriteClassification: built.linuxWriteClassification,
    })
    const shell = options.binShell ?? '/bin/bash'
    return {
      attempt: pending.handle,
      argv: [shell, '-c', built.command],
      env,
      sandboxBackend: built.sandboxBackend,
    }
  } catch (error) {
    attemptRegistry.discard(pending)
    throw error
  }
}
```

Ensure the wait-for-network path succeeds before activation and no token/correlation/queue index survives any thrown wrapper/environment step.

- [ ] **Step 6: Wire proxies and monitors to the singleton registry**

Pass `token => attemptRegistry.resolveProxyToken(token)` to both local proxy handlers. Pass macOS `recordAttemptDenial` and Linux `{ hasActiveCorrelation, recordAttemptDenial }` callbacks to monitor startup. Preserve `SandboxViolationStore` callbacks for legacy tags.

Wrap synchronous monitor setup in `try/catch` and log a warning on failure. Attach a rejection handler to asynchronous readiness that logs once and leaves `linuxMonitor` unavailable; do not await it or reject `initialize`. Do not change sandbox dependency failures, proxy startup failures, or enforcement failures into degradations.

- [ ] **Step 7: Implement finish and reset invalidation**

Delegate finish to the registry. At the beginning of existing reset teardown, call `attemptRegistry.reset()` so credentials/correlations stop resolving before listeners shut down. Do not call `cleanupAfterCommand` from finish and do not track established CONNECT/SOCKS streams.

Add both methods to `ISandboxManager` and the `SandboxManager` object, and export all public attempt types from `src/index.ts`.

- [ ] **Step 8: Clarify future-attempt update behavior in code and tests**

Update the `updateConfig` doc comment: macOS/Linux filesystem changes are supported for future wrapper/attempt creation without reset; already prepared wrappers and Linux classification copies do not change. Keep the warning/reset requirement only for Windows filesystem infrastructure changes. Verify live network filters still read current `config` for every proxy request.

- [ ] **Step 9: Run manager, compatibility, and type tests**

Run: `bun test test/sandbox/sandbox-attempt-manager.test.ts test/sandbox/update-config.test.ts test/sandbox/wrap-with-sandbox.test.ts test/configurable-proxy-ports.test.ts test/sandbox/linux-bridge-spawn-error.test.ts test/sandbox/winsrt.test.ts`

Expected: PASS on the current platform; platform-gated suites skip where appropriate.

Run: `npm run typecheck`

Expected: PASS with `ISandboxManager` and the singleton object in sync.

- [ ] **Step 10: Commit the public manager integration**

```bash
git add src/sandbox/sandbox-manager.ts src/index.ts test/sandbox/sandbox-attempt-manager.test.ts test/sandbox/update-config.test.ts
git commit -m "feat: expose attributed sandbox attempt API"
```

### Task 8: Documentation and Full Compatibility Verification

**Files:**

- Modify: `README.md:178-235, 614-638`

**Interfaces:**

- Consumes: the completed public API and exact lifecycle semantics.
- Produces: copy-pastable spawn usage and explicit compatibility/degradation/configuration documentation.

- [ ] **Step 1: Add copy-pastable attempt lifecycle documentation**

Add a section beside the existing wrapper example using this ordering:

```ts
import { once } from 'node:events'
import { spawn } from 'node:child_process'
import {
  SandboxManager,
  type SandboxDenialSummary,
} from '@anthropic-ai/sandbox-runtime'

const descriptor = await SandboxManager.prepareSandboxAttempt({
  command: 'curl https://example.com',
  cwd: process.cwd(),
  env: process.env,
})

let denials: readonly SandboxDenialSummary[] = []
try {
  const child = spawn(descriptor.argv[0], descriptor.argv.slice(1), {
    shell: false,
    cwd: process.cwd(),
    env: descriptor.env,
    stdio: 'inherit',
  })
  await once(child, 'close')
} finally {
  SandboxManager.cleanupAfterCommand()
  ;({ denials } = await SandboxManager.finishSandboxAttempt(
    descriptor.attempt,
  ))
}
```

State that spawn failure follows the same cleanup-then-finish ordering, every process/retry gets a new descriptor, and a handle is finished once.

- [ ] **Step 2: Document evidence scope and degradation**

Document the exact summary union, first-100 bound, 100 ms grace, macOS/Linux-only support, actual backend meaning, runtime-owned proxy credential scope, legacy/SSH/external/unauthenticated exclusions, and monitor-unavailable heuristic fallback expectation. State that the result is diagnostic evidence and never triggers approval, escalation, or local execution.

- [ ] **Step 3: Correct the `updateConfig` filesystem wording**

Replace the current blanket statement that filesystem changes require reset with platform-specific wording: macOS/Linux compile current filesystem policy for each future wrapper/attempt while already prepared attempts remain unchanged; Windows session ACL infrastructure still requires reset/reinitialize when its filesystem access set changes; live network filtering continues using current configuration.

- [ ] **Step 4: Run formatting and static checks**

Run: `npx prettier --check src/sandbox/sandbox-attempt-types.ts src/sandbox/sandbox-attempt-registry.ts src/sandbox/sandbox-attempt-environment.ts src/sandbox/sandbox-manager.ts src/sandbox/sandbox-utils.ts src/sandbox/macos-sandbox-utils.ts src/sandbox/linux-sandbox-utils.ts src/sandbox/linux-violation-monitor.ts src/sandbox/http-proxy.ts src/sandbox/socks-proxy.ts src/sandbox/request-filter.ts src/sandbox/tls-terminate-proxy.ts test/sandbox/sandbox-attempt-registry.test.ts test/sandbox/sandbox-attempt-environment.test.ts test/sandbox/proxy-attribution.test.ts test/sandbox/macos-attempt-monitor.test.ts test/sandbox/sandbox-attempt-manager.test.ts test/sandbox/linux-violation-monitor.test.ts test/sandbox/wrap-with-sandbox.test.ts test/sandbox/update-config.test.ts README.md`

Expected: formatter check exits 0 without modifying the working tree.

Run: `npm run lint:check`

Expected: exits 0.

Run: `npm run typecheck`

Expected: exits 0.

Run: `npm run build`

Expected: exits 0.

- [ ] **Step 5: Run the complete test suite**

Run: `bun test`

Expected: all applicable tests pass and platform-specific tests skip only on unsupported hosts.

- [ ] **Step 6: Review the release boundary**

Confirm the diff contains only the additive runtime API and documentation. Link the matching `pi-sandbox` spec and executable plan in the release notes/PR description, and verify that companion plan covers its dependency and pnpm lockfile update, one descriptor per initial/recovery/spawn-failure process, structural-evidence fallback, final-failure guidance, and consumer tests. Block consumer rollout until this runtime version publishes; do not invent consumer file paths or modify a consumer repository from this runtime checkout.

- [ ] **Step 7: Commit documentation and final verification state**

```bash
git add README.md
git commit -m "docs: explain attributed sandbox attempts"
```
