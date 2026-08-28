import { randomBytes } from 'node:crypto'
import { posix } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import type { IgnoreViolationsConfig } from './sandbox-config.js'
import type {
  AuthenticatedAttemptCredential,
  FinishedSandboxAttempt,
  LinuxWriteClassification,
  SandboxAttemptHandle,
  SandboxBackend,
  SandboxDenialSummary,
} from './sandbox-attempt-types.js'

const MAX_DENIAL_SUMMARIES = 100
const DEFAULT_FINISH_GRACE_MS = 100

const SUPPORTED_LINUX_OPERATIONS = new Set([
  'openat',
  'openat2',
  'unlinkat',
  'mkdirat',
  'mknodat',
  'symlinkat',
  'linkat',
  'renameat',
  'renameat2',
  'fchmodat',
  'fchmodat2',
  'fchownat',
  'utimensat',
  'open',
  'creat',
  'unlink',
  'rmdir',
  'rename',
  'link',
  'symlink',
  'mkdir',
  'mknod',
  'truncate',
  'chmod',
  'chown',
  'lchown',
  'utime',
  'utimes',
])

export interface PendingSandboxAttempt {
  readonly handle: SandboxAttemptHandle
  readonly correlation: string
  readonly proxyToken: string
}

interface PendingState {
  status: 'pending' | 'activated' | 'discarded'
  readonly command: string
  readonly ignoreViolations?: IgnoreViolationsConfig
  readonly generation: number
}

interface ActiveAttemptState {
  readonly attemptId: string
  readonly correlation: string
  readonly proxyToken: string
  readonly command: string
  readonly ignoreViolations?: IgnoreViolationsConfig
  readonly backend: SandboxBackend
  readonly linuxWriteClassification?: LinuxWriteClassification
  readonly generation: number
  admissionOpen: boolean
  finishing: boolean
  denials: SandboxDenialSummary[]
}

function randomRuntimeValue(): string {
  return randomBytes(18).toString('base64url')
}

function copyIgnoreViolations(
  ignoreViolations: IgnoreViolationsConfig | undefined,
): IgnoreViolationsConfig | undefined {
  if (!ignoreViolations) return undefined
  return Object.fromEntries(
    Object.entries(ignoreViolations).map(([pattern, values]) => [
      pattern,
      [...values],
    ]),
  )
}

function copyLinuxWriteClassification(
  classification: LinuxWriteClassification | undefined,
): LinuxWriteClassification | undefined {
  if (!classification) return undefined
  return {
    allowWritePaths: classification.allowWritePaths.map(path =>
      posix.normalize(path),
    ),
    denyWritePaths: classification.denyWritePaths.map(path =>
      posix.normalize(path),
    ),
  }
}

function isUnderPrefix(path: string, prefix: string): boolean {
  return (
    path === prefix ||
    path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`)
  )
}

function shouldIgnore(state: ActiveAttemptState, evidence: string): boolean {
  const ignores = state.ignoreViolations
  if (!ignores) return false
  if (ignores['*']?.some(pattern => evidence.includes(pattern))) return true
  return Object.entries(ignores).some(
    ([commandPattern, patterns]) =>
      commandPattern !== '*' &&
      state.command.includes(commandPattern) &&
      patterns.some(pattern => evidence.includes(pattern)),
  )
}

export class SandboxAttemptRegistry {
  private readonly finishGraceMs: number
  private generation = 0
  private readonly pendingStates = new WeakMap<
    PendingSandboxAttempt,
    PendingState
  >()
  private readonly attemptsById = new Map<string, ActiveAttemptState>()
  private readonly attemptsByCorrelation = new Map<string, ActiveAttemptState>()
  private readonly attemptsByProxyToken = new Map<string, ActiveAttemptState>()

  constructor(options: { finishGraceMs?: number } = {}) {
    this.finishGraceMs = options.finishGraceMs ?? DEFAULT_FINISH_GRACE_MS
    if (!Number.isFinite(this.finishGraceMs) || this.finishGraceMs < 0) {
      throw new Error('finishGraceMs must be a non-negative finite number')
    }
  }

  allocate(options: {
    command: string
    ignoreViolations?: IgnoreViolationsConfig
  }): PendingSandboxAttempt {
    const handle = Object.freeze({
      attemptId: randomRuntimeValue(),
    }) as SandboxAttemptHandle
    const pending = Object.freeze({
      handle,
      correlation: randomRuntimeValue(),
      proxyToken: randomRuntimeValue(),
    })
    this.pendingStates.set(pending, {
      status: 'pending',
      command: options.command,
      ignoreViolations: copyIgnoreViolations(options.ignoreViolations),
      generation: this.generation,
    })
    return pending
  }

  activate(
    pending: PendingSandboxAttempt,
    options: {
      backend: SandboxBackend
      linuxWriteClassification?: LinuxWriteClassification
    },
  ): void {
    const pendingState = this.pendingStates.get(pending)
    if (!pendingState || pendingState.status !== 'pending') {
      throw new Error('sandbox attempt is not pending')
    }
    if (pendingState.generation !== this.generation) {
      pendingState.status = 'discarded'
      throw new Error('sandbox attempt invalidated by reset')
    }
    if (
      this.attemptsById.has(pending.handle.attemptId) ||
      this.attemptsByCorrelation.has(pending.correlation) ||
      this.attemptsByProxyToken.has(pending.proxyToken)
    ) {
      throw new Error('sandbox attempt runtime value collision')
    }

    const active: ActiveAttemptState = {
      attemptId: pending.handle.attemptId,
      correlation: pending.correlation,
      proxyToken: pending.proxyToken,
      command: pendingState.command,
      ignoreViolations: pendingState.ignoreViolations,
      backend: options.backend,
      linuxWriteClassification: copyLinuxWriteClassification(
        options.linuxWriteClassification,
      ),
      generation: this.generation,
      admissionOpen: true,
      finishing: false,
      denials: [],
    }

    this.attemptsById.set(active.attemptId, active)
    this.attemptsByCorrelation.set(active.correlation, active)
    this.attemptsByProxyToken.set(active.proxyToken, active)
    pendingState.status = 'activated'
  }

  discard(pending: PendingSandboxAttempt): void {
    const state = this.pendingStates.get(pending)
    if (state?.status === 'pending') state.status = 'discarded'
  }

  hasActiveCorrelation(correlation: string): boolean {
    return this.isAdmitting(
      this.attemptsByCorrelation.get(correlation),
      'correlation',
      correlation,
    )
  }

  recordMacOSDenial(
    correlation: string,
    operation: string,
    details: string,
  ): void {
    const state = this.attemptsByCorrelation.get(correlation)
    if (
      !this.isAdmitting(state, 'correlation', correlation) ||
      state.backend !== 'macos-seatbelt' ||
      shouldIgnore(state, details)
    ) {
      return
    }

    if (operation.startsWith('file-')) {
      this.enqueue(state, { kind: 'filesystem', source: 'macos-seatbelt' })
    } else if (operation.startsWith('network-')) {
      this.enqueue(state, { kind: 'network', source: 'macos-seatbelt' })
    }
  }

  recordLinuxDenial(
    correlation: string,
    operation: string,
    path: string,
  ): void {
    const state = this.attemptsByCorrelation.get(correlation)
    if (
      !this.isAdmitting(state, 'correlation', correlation) ||
      state.backend !== 'linux-seccomp' ||
      !SUPPORTED_LINUX_OPERATIONS.has(operation) ||
      !posix.isAbsolute(path)
    ) {
      return
    }

    const normalizedPath = posix.normalize(path)
    const classification = state.linuxWriteClassification
    if (!classification || shouldIgnore(state, normalizedPath)) return
    const denied =
      classification.denyWritePaths.some(prefix =>
        isUnderPrefix(normalizedPath, prefix),
      ) ||
      !classification.allowWritePaths.some(prefix =>
        isUnderPrefix(normalizedPath, prefix),
      )
    if (denied) {
      this.enqueue(state, { kind: 'filesystem', source: 'linux-seccomp' })
    }
  }

  resolveProxyToken(token: string): AuthenticatedAttemptCredential | undefined {
    const state = this.attemptsByProxyToken.get(token)
    if (!this.isAdmitting(state, 'proxyToken', token)) return undefined
    return {
      recordNetworkDenial: source => {
        if (this.isAdmitting(state, 'proxyToken', token)) {
          this.enqueue(state, { kind: 'network', source })
        }
      },
    }
  }

  async finish(attempt: SandboxAttemptHandle): Promise<FinishedSandboxAttempt> {
    const state = this.attemptsById.get(attempt.attemptId)
    if (
      !this.isAdmitting(state, 'attemptId', attempt.attemptId) ||
      state.finishing
    ) {
      throw new Error('unknown or already finished sandbox attempt')
    }

    state.finishing = true
    await delay(this.finishGraceMs)

    if (
      state.generation !== this.generation ||
      this.attemptsById.get(state.attemptId) !== state ||
      !state.admissionOpen
    ) {
      throw new Error('sandbox attempt invalidated by reset')
    }

    state.admissionOpen = false
    this.removeIndexes(state)
    const denials = state.denials
    state.denials = []
    return { denials: [...denials] }
  }

  reset(): void {
    this.generation++
    for (const state of this.attemptsById.values()) {
      state.admissionOpen = false
      state.denials = []
    }
    this.attemptsById.clear()
    this.attemptsByCorrelation.clear()
    this.attemptsByProxyToken.clear()
  }

  private enqueue(
    state: ActiveAttemptState,
    denial: SandboxDenialSummary,
  ): void {
    if (state.admissionOpen && state.denials.length < MAX_DENIAL_SUMMARIES) {
      state.denials.push(denial)
    }
  }

  private isAdmitting(
    state: ActiveAttemptState | undefined,
    index: 'attemptId' | 'correlation' | 'proxyToken',
    value: string,
  ): state is ActiveAttemptState {
    if (!state?.admissionOpen || state.generation !== this.generation) {
      return false
    }
    if (index === 'attemptId') return this.attemptsById.get(value) === state
    if (index === 'correlation') {
      return this.attemptsByCorrelation.get(value) === state
    }
    return this.attemptsByProxyToken.get(value) === state
  }

  private removeIndexes(state: ActiveAttemptState): void {
    if (this.attemptsById.get(state.attemptId) === state) {
      this.attemptsById.delete(state.attemptId)
    }
    if (this.attemptsByCorrelation.get(state.correlation) === state) {
      this.attemptsByCorrelation.delete(state.correlation)
    }
    if (this.attemptsByProxyToken.get(state.proxyToken) === state) {
      this.attemptsByProxyToken.delete(state.proxyToken)
    }
  }
}
