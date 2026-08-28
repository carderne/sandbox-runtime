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
