import { describe, expect, it } from 'bun:test'
import { SandboxAttemptRegistry } from '../../src/sandbox/sandbox-attempt-registry.js'
import type {
  SandboxAttemptHandle,
  SandboxBackend,
} from '../../src/sandbox/sandbox-attempt-types.js'

function activate(
  registry: SandboxAttemptRegistry,
  command = 'same command',
  backend: SandboxBackend = 'linux-seccomp',
) {
  const pending = registry.allocate({ command })
  registry.activate(pending, {
    backend,
    linuxWriteClassification:
      backend === 'linux-seccomp'
        ? {
            allowWritePaths: ['/allowed'],
            denyWritePaths: ['/allowed/denied'],
          }
        : undefined,
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
    const peer = activate(registry)
    const forged = { attemptId: 'unknown' } as SandboxAttemptHandle

    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types the matcher as void; awaiting is required at runtime
    await expect(registry.finish(forged)).rejects.toThrow(
      /unknown or already finished/i,
    )
    await registry.finish(active.handle)
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types the matcher as void; awaiting is required at runtime
    await expect(registry.finish(active.handle)).rejects.toThrow(
      /unknown or already finished/i,
    )
    expect((await registry.finish(peer.handle)).denials).toEqual([])
  })

  it('resolves cloned handles by attempt ID while rejecting concurrent finishes', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 10 })
    const active = activate(registry)
    const finishing = registry.finish({
      attemptId: active.handle.attemptId,
    } as SandboxAttemptHandle)

    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types the matcher as void; awaiting is required at runtime
    await expect(registry.finish(active.handle)).rejects.toThrow(
      /unknown or already finished/i,
    )
    expect((await finishing).denials).toEqual([])
  })

  it('classifies only supported denied Linux operations and normalizes paths', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const active = activate(registry)

    registry.recordLinuxDenial(
      active.correlation,
      'openat',
      '/allowed/child/../file',
    )
    registry.recordLinuxDenial(
      active.correlation,
      'renameat2',
      '/allowed/denied/../denied/file',
    )
    registry.recordLinuxDenial(active.correlation, 'read', '/blocked/read')
    registry.recordLinuxDenial(active.correlation, 'openat', 'relative/path')

    expect((await registry.finish(active.handle)).denials).toEqual([
      { kind: 'filesystem', source: 'linux-seccomp' },
    ])
  })

  it('copies Linux classification and ignore rules at activation', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const allowWritePaths = ['/allowed']
    const denyWritePaths = ['/allowed/denied']
    const ignoredPaths = ['/ignored']
    const pending = registry.allocate({
      command: 'npm install',
      ignoreViolations: { npm: ignoredPaths, '*': ['/global-ignore'] },
    })
    registry.activate(pending, {
      backend: 'linux-seccomp',
      linuxWriteClassification: { allowWritePaths, denyWritePaths },
    })

    allowWritePaths.push('/blocked')
    denyWritePaths.length = 0
    ignoredPaths.length = 0
    registry.recordLinuxDenial(pending.correlation, 'openat', '/ignored/file')
    registry.recordLinuxDenial(
      pending.correlation,
      'openat',
      '/global-ignore/file',
    )
    registry.recordLinuxDenial(pending.correlation, 'openat', '/blocked/file')
    registry.recordLinuxDenial(
      pending.correlation,
      'openat',
      '/allowed/denied/file',
    )

    expect((await registry.finish(pending.handle)).denials).toEqual([
      { kind: 'filesystem', source: 'linux-seccomp' },
      { kind: 'filesystem', source: 'linux-seccomp' },
    ])
  })

  it('classifies supported macOS file and network denials and applies ignores', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const pending = registry.allocate({
      command: 'curl example.com',
      ignoreViolations: {
        '*': ['/ignored'],
        curl: ['telemetry.example'],
      },
    })
    registry.activate(pending, { backend: 'macos-seatbelt' })

    registry.recordMacOSDenial(
      pending.correlation,
      'file-read-data',
      'bash deny file-read-data /ignored/key',
    )
    registry.recordMacOSDenial(
      pending.correlation,
      'network-outbound',
      'curl deny network-outbound telemetry.example:443',
    )
    registry.recordMacOSDenial(
      pending.correlation,
      'file-write-create',
      'bash deny file-write-create /blocked',
    )
    registry.recordMacOSDenial(
      pending.correlation,
      'network-outbound',
      'curl deny network-outbound blocked.example:443',
    )
    registry.recordMacOSDenial(
      pending.correlation,
      'mach-lookup',
      'bash deny mach-lookup com.example',
    )

    expect((await registry.finish(pending.handle)).denials).toEqual([
      { kind: 'filesystem', source: 'macos-seatbelt' },
      { kind: 'network', source: 'macos-seatbelt' },
    ])
  })

  it('admits during the 100 ms grace and revokes after close', async () => {
    const registry = new SandboxAttemptRegistry()
    const active = activate(registry)
    const finishing = registry.finish(active.handle)
    setTimeout(() => {
      registry
        .resolveProxyToken(active.proxyToken)
        ?.recordNetworkDenial('http-proxy')
    }, 20)

    const started = performance.now()
    const result = await finishing
    expect(performance.now() - started).toBeGreaterThanOrEqual(70)
    expect(result.denials).toEqual([{ kind: 'network', source: 'http-proxy' }])
    expect(registry.resolveProxyToken(active.proxyToken)).toBeUndefined()
    expect(registry.hasActiveCorrelation(active.correlation)).toBe(false)
  })

  it('invalidates reset-raced finishes without returning evidence', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 20 })
    const active = activate(registry)
    const finishing = registry.finish(active.handle)
    registry.reset()

    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types the matcher as void; awaiting is required at runtime
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
})
