import { randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join, posix } from 'node:path'

import { logForDebugging } from '../utils/debug.js'
import type { SandboxViolationCallback } from './macos-sandbox-utils.js'
import type { IgnoreViolationsConfig } from './sandbox-config.js'
import { decodeSandboxedCommand } from './sandbox-utils.js'

export interface LinuxViolationMonitorOptions {
  /**
   * Paths bwrap mounts read-write. apply-seccomp's USER_NOTIF observer
   * reports every write-intent syscall (allowed or not, since the BPF filter
   * cannot see the mount table); a path is treated as a violation only when
   * it is *not* under any of these prefixes, or when it falls under
   * {@link denyWritePaths}.
   */
  allowWritePaths: string[]
  /** Paths bwrap re-mounts read-only inside an allowWrite region. */
  denyWritePaths: string[]
  ignoreViolations?: IgnoreViolationsConfig
}

export interface LinuxAttemptViolationRouting {
  hasActiveCorrelation(correlation: string): boolean
  recordAttemptDenial(
    correlation: string,
    operation: string,
    path: string,
  ): void
}

export interface LinuxViolationMonitor {
  /** Filesystem unix-socket path the listener is bound to. Bind-mount this
   *  into each bwrap sandbox and pass it to apply-seccomp via
   *  SRT_OBSERVE_SOCK. `undefined` if listen() failed (the caller should
   *  proceed without observation). */
  observeSocketPath: string | undefined
  /** Resolves once the listener is bound, or on listen failure. */
  ready: Promise<void>
  stop: () => void
}

export const MAX_OBSERVER_FRAME_BYTES = 16 * 1024
const MAX_CORRELATION_CHARS = 128
const MAX_OBSERVER_PATH_CHARS = 4096
const ATTEMPT_CORRELATION_REGEX = /^[A-Za-z0-9_-]{8,128}$/
const SUPPORTED_OPERATIONS = new Set([
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

type ConnectionAttribution =
  | { kind: 'attempt'; correlation: string; activeAtHeader: boolean }
  | { kind: 'legacy'; encodedCommand: string }

/**
 * Linux equivalent of {@link startMacOSSandboxLogMonitor}. Creates a single
 * filesystem unix-socket listener; each `apply-seccomp` instance's outer stub
 * connects to it and writes one JSON line per observed write-intent syscall.
 * The supervise loop lives inside `apply-seccomp` itself (the parent that
 * already waitpid()s the workload), so there is no separate supervisor binary.
 *
 * Unlike Seatbelt's `log stream`, the kernel reports *attempts* here, not
 * denials, so this function intersects each path against the configured
 * allow/deny set before forwarding it as a violation.
 *
 * The reported path is read out of the (untrusted) sandboxed process's memory
 * with process_vm_readv and is therefore ATTACKER-CONTROLLED and racy. bwrap's
 * mount table is the only enforcement boundary; the violation events emitted
 * here are diagnostic hints and must never gate a policy decision.
 *
 * The transport is a *filesystem* unix socket because bwrap runs with
 * `--unshare-net` (abstract sockets are net-namespace-scoped) and bwrap closes
 * inherited fds. Filesystem sockets survive across net + user + mount
 * namespaces as long as the path is bind-mounted into the sandbox.
 */
export function startLinuxSandboxViolationMonitor(
  callback: SandboxViolationCallback,
  opts: LinuxViolationMonitorOptions,
  attemptRouting?: LinuxAttemptViolationRouting,
): LinuxViolationMonitor {
  const { allowWritePaths, denyWritePaths, ignoreViolations } = opts

  // sun_path is 108 bytes; mkdtemp under tmpdir() keeps us well under.
  const sockDir = mkdtempSync(join(tmpdir(), 'srt-obs-'))
  const sockPath = join(sockDir, `s${randomBytes(4).toString('hex')}.sock`)

  const wildcardPaths = ignoreViolations?.['*'] ?? []
  const commandPatterns = ignoreViolations
    ? Object.entries(ignoreViolations).filter(([k]) => k !== '*')
    : []

  const underPrefix = (p: string, prefix: string): boolean =>
    p === prefix || p.startsWith(prefix.endsWith('/') ? prefix : prefix + '/')

  /** A write attempt is a violation iff bwrap would refuse it: outside every
   *  allowWrite prefix, or back inside a denyWrite carve-out. apply-seccomp
   *  resolves relative paths against the tracee's cwd/dirfd before emitting,
   *  so events arrive absolute; the joined form may still contain ./ and
   *  ../ segments, which must be collapsed before prefix comparison. */
  const isDenied = (p: string): boolean => {
    const norm = posix.normalize(p)
    if (denyWritePaths.some(d => underPrefix(norm, d))) return true
    return !allowWritePaths.some(a => underPrefix(norm, a))
  }

  const shouldIgnore = (path: string, command: string | undefined): boolean => {
    if (wildcardPaths.some(w => path.includes(w))) return true
    if (command) {
      for (const [pattern, paths] of commandPatterns) {
        if (command.includes(pattern) && paths.some(w => path.includes(w))) {
          return true
        }
      }
    }
    return false
  }

  const handleEvent = (
    ev: Record<string, unknown>,
    attribution: ConnectionAttribution,
  ): void => {
    if (typeof ev.observe_init_error === 'string') {
      logForDebugging('[Sandbox Linux Monitor] observe filter not installed')
      return
    }
    if (
      typeof ev.syscall !== 'string' ||
      !SUPPORTED_OPERATIONS.has(ev.syscall) ||
      typeof ev.path !== 'string' ||
      ev.path.length > MAX_OBSERVER_PATH_CHARS ||
      !posix.isAbsolute(ev.path)
    ) {
      return
    }

    if (attribution.kind === 'attempt') {
      if (
        attribution.activeAtHeader &&
        attemptRouting?.hasActiveCorrelation(attribution.correlation)
      ) {
        attemptRouting.recordAttemptDenial(
          attribution.correlation,
          ev.syscall,
          ev.path,
        )
      }
      return
    }

    if (!isDenied(ev.path)) return
    let command: string | undefined
    try {
      command = decodeSandboxedCommand(attribution.encodedCommand)
    } catch {
      /* retain legacy violation reporting without decoded command text */
    }
    if (shouldIgnore(ev.path, command)) return
    callback({
      line: `deny ${ev.syscall} ${ev.path}`,
      command,
      encodedCommand: attribution.encodedCommand,
      timestamp: new Date(),
    })
  }

  let resolveReady: () => void
  const ready = new Promise<void>(res => {
    resolveReady = res
  })

  let observeSocketPath: string | undefined = sockPath

  const server: Server = createServer(conn => {
    let attribution: ConnectionAttribution | undefined
    let buffered: Buffer = Buffer.alloc(0)
    let discardUntilNewline = false

    const handleFrame = (frame: Buffer): void => {
      if (frame.length === 0 || frame.length > MAX_OBSERVER_FRAME_BYTES) return
      let value: unknown
      try {
        value = JSON.parse(frame.toString('utf8')) as unknown
      } catch {
        return
      }
      if (!isRecord(value)) return

      if (!attribution) {
        const correlation = value.attemptCorrelation
        const encodedCommand = value.encodedCommand
        if (
          typeof correlation === 'string' &&
          encodedCommand === undefined &&
          correlation.length <= MAX_CORRELATION_CHARS &&
          ATTEMPT_CORRELATION_REGEX.test(correlation)
        ) {
          attribution = {
            kind: 'attempt',
            correlation,
            activeAtHeader:
              attemptRouting?.hasActiveCorrelation(correlation) ?? false,
          }
        } else if (
          typeof encodedCommand === 'string' &&
          encodedCommand.length > 0 &&
          correlation === undefined &&
          Buffer.byteLength(encodedCommand, 'utf8') <= MAX_OBSERVER_FRAME_BYTES
        ) {
          attribution = { kind: 'legacy', encodedCommand }
        }
        return
      }

      handleEvent(value, attribution)
    }

    conn.on('data', (chunk: Buffer) => {
      buffered = buffered.length ? Buffer.concat([buffered, chunk]) : chunk
      for (;;) {
        const newline = buffered.indexOf(0x0a)
        if (discardUntilNewline) {
          if (newline < 0) {
            buffered = Buffer.alloc(0)
            return
          }
          buffered = buffered.subarray(newline + 1)
          discardUntilNewline = false
          continue
        }
        if (newline >= 0) {
          const frame = buffered.subarray(0, newline)
          buffered = buffered.subarray(newline + 1)
          handleFrame(frame)
          continue
        }
        if (buffered.length > MAX_OBSERVER_FRAME_BYTES) {
          buffered = Buffer.alloc(0)
          discardUntilNewline = true
        }
        return
      }
    })
    conn.on('error', () => {})
  })

  server.on('error', err => {
    logForDebugging(
      `[Sandbox Linux Monitor] listen failed: ${err.message} - violation monitoring disabled`,
      { level: 'warn' },
    )
    observeSocketPath = undefined
    resolveReady()
  })
  server.listen(sockPath, () => resolveReady())

  const sockets = new Set<Socket>()
  server.on('connection', s => {
    sockets.add(s)
    s.on('close', () => sockets.delete(s))
  })

  const stop = (): void => {
    logForDebugging('[Sandbox Linux Monitor] stopping')
    for (const s of sockets) s.destroy()
    server.close()
    try {
      rmSync(sockDir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }

  return {
    get observeSocketPath() {
      return observeSocketPath
    },
    ready,
    stop,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
