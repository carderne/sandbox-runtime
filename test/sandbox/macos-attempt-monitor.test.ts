import { describe, expect, it } from 'bun:test'
import {
  parseMacOSSandboxDenial,
  routeMacOSSandboxDenial,
  type SandboxViolationEvent,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxAttemptRegistry } from '../../src/sandbox/sandbox-attempt-registry.js'

describe('macOS attempt monitor parsing', () => {
  it('parses attempt file and network denial tags', () => {
    expect(
      parseMacOSSandboxDenial(
        'SRTATTEMPT_corr_abcdefgh_END__123_SBX\n' +
          'Sandbox: bash(1) deny(1) file-read-data /secret',
      ),
    ).toEqual({
      attribution: { kind: 'attempt', correlation: 'corr_abcdefgh' },
      operation: 'file-read-data',
      details: 'bash(1) deny(1) file-read-data /secret',
    })
    expect(
      parseMacOSSandboxDenial(
        'SRTATTEMPT_corr_abcdefgh_END__123_SBX\n' +
          'Sandbox: curl(2) deny network-outbound example.com:443',
      )?.operation,
    ).toBe('network-outbound')
  })

  it('parses legacy tags and decodes their commands', () => {
    const encoded = Buffer.from('printf legacy').toString('base64')
    expect(
      parseMacOSSandboxDenial(
        `CMD64_${encoded}_END__123_SBX\n` +
          'Sandbox: bash(1) deny(1) file-write-data /blocked',
      ),
    ).toEqual({
      attribution: {
        kind: 'legacy',
        encodedCommand: encoded,
        command: 'printf legacy',
      },
      operation: 'file-write-data',
      details: 'bash(1) deny(1) file-write-data /blocked',
    })
  })

  it('drops malformed tags, malformed denials, and noisy diagnostics', () => {
    expect(
      parseMacOSSandboxDenial(
        'SRTATTEMPT_short_END__123_SBX\n' +
          'Sandbox: bash(1) deny(1) file-read-data /secret',
      ),
    ).toBeUndefined()
    expect(
      parseMacOSSandboxDenial(
        `SRTATTEMPT_${'a'.repeat(129)}_END__123_SBX\n` +
          'Sandbox: bash(1) deny(1) file-read-data /secret',
      ),
    ).toBeUndefined()
    expect(
      parseMacOSSandboxDenial(
        'SRTATTEMPT_corr_abcdefgh_END__123_SBX\nSandbox: malformed',
      ),
    ).toBeUndefined()
    expect(
      parseMacOSSandboxDenial(
        'SRTATTEMPT_corr_abcdefgh_END__123_SBX\n' +
          'Sandbox: mDNSResponder deny(1) network-outbound example.com:53',
      ),
    ).toBeUndefined()
    expect(
      parseMacOSSandboxDenial(
        'SRTATTEMPT_corr_abcdefgh_END__123_SBX\n' +
          'Sandbox: bash(1) deny(1) mach-lookup com.apple.analyticsd',
      ),
    ).toBeUndefined()
  })
})

describe('macOS attempt monitor routing', () => {
  it('routes attempt tags only to the active registry correlation', async () => {
    const registry = new SandboxAttemptRegistry({ finishGraceMs: 0 })
    const pending = registry.allocate({
      command: 'same command',
      ignoreViolations: {
        '*': ['/wildcard-ignore'],
        same: ['/command-ignore'],
      },
    })
    registry.activate(pending, { backend: 'macos-seatbelt' })
    const legacy: SandboxViolationEvent[] = []
    const route = (correlation: string, operation: string, details: string) =>
      registry.recordMacOSDenial(correlation, operation, details)

    for (const details of [
      'bash(1) deny(1) file-read-data /blocked',
      'bash(1) deny(1) network-outbound example.com:443',
      'bash(1) deny(1) mach-lookup com.example.service',
      'bash(1) deny(1) file-read-data /wildcard-ignore',
      'bash(1) deny(1) file-read-data /command-ignore',
    ]) {
      routeMacOSSandboxDenial(
        `SRTATTEMPT_${pending.correlation}_END__123_SBX\nSandbox: ${details}`,
        violation => legacy.push(violation),
        undefined,
        route,
      )
    }
    routeMacOSSandboxDenial(
      'SRTATTEMPT_unknown_corr_END__123_SBX\n' +
        'Sandbox: bash(1) deny(1) file-read-data /unknown',
      violation => legacy.push(violation),
      undefined,
      route,
    )

    expect(legacy).toEqual([])
    expect((await registry.finish(pending.handle)).denials).toEqual([
      { kind: 'filesystem', source: 'macos-seatbelt' },
      { kind: 'network', source: 'macos-seatbelt' },
    ])

    routeMacOSSandboxDenial(
      `SRTATTEMPT_${pending.correlation}_END__123_SBX\n` +
        'Sandbox: bash(1) deny(1) file-read-data /closed',
      violation => legacy.push(violation),
      undefined,
      route,
    )
    expect(legacy).toEqual([])
  })

  it('retains legacy callback and ignore behavior', () => {
    const events: SandboxViolationEvent[] = []
    const encoded = Buffer.from('printf legacy').toString('base64')
    const text = (path: string) =>
      `CMD64_${encoded}_END__123_SBX\n` +
      `Sandbox: bash(1) deny(1) file-write-data ${path}`

    routeMacOSSandboxDenial(text('/blocked'), event => events.push(event), {
      '*': ['/wildcard-ignore'],
      legacy: ['/command-ignore'],
    })
    routeMacOSSandboxDenial(
      text('/wildcard-ignore'),
      event => events.push(event),
      { '*': ['/wildcard-ignore'] },
    )
    routeMacOSSandboxDenial(
      text('/command-ignore'),
      event => events.push(event),
      { legacy: ['/command-ignore'] },
    )

    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      line: 'bash(1) deny(1) file-write-data /blocked',
      command: 'printf legacy',
      encodedCommand: encoded,
    })
  })
})
