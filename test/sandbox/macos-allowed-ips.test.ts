import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * Tests for network.allowedIPs — seatbelt-level direct-dial egress.
 *
 * On current macOS the seatbelt compiler rejects IP/CIDR destination
 * literals in (remote ip ...) filters (probe matrix:
 * docs/sbpl-probe-allowedIPs.md), so each configured entry degrades to a
 * PORT-SCOPED allow: one (allow network-outbound (remote ip "*:<port>"))
 * rule per unique port, matching any destination host on that port.
 *
 * These tests use the actual sandbox profile generation code to ensure
 * real-world coverage.
 */

describe.if(isMacOS)('macOS allowedIPs profile generation', () => {
  const ruleFor = (port: number) =>
    `(allow network-outbound (remote ip "*:${port}"))`

  it('emits one rule per unique port, preserving first-seen order', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: true,
      allowedIPs: [
        '10.172.102.0/23:9093',
        '10.0.0.0/8:443',
        '192.168.1.10:9093', // duplicate port — must not emit a second rule
        '10.1.2.3:8080',
      ],
      readConfig: undefined,
      writeConfig: undefined,
    })

    expect(wrapped).toContain(ruleFor(9093))
    expect(wrapped).toContain(ruleFor(443))
    expect(wrapped).toContain(ruleFor(8080))

    const i9093 = wrapped.indexOf(ruleFor(9093))
    const i443 = wrapped.indexOf(ruleFor(443))
    const i8080 = wrapped.indexOf(ruleFor(8080))
    expect(i9093).toBeLessThan(i443)
    expect(i443).toBeLessThan(i8080)

    // Exactly one rule per unique port.
    expect(wrapped.split(ruleFor(9093)).length - 1).toBe(1)
    expect(wrapped.split(ruleFor(443)).length - 1).toBe(1)
    expect(wrapped.split(ruleFor(8080)).length - 1).toBe(1)
  })

  it('emits no rules for port-less entries', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: true,
      allowedIPs: ['10.1.2.3', '2001:db8::/32'],
      readConfig: undefined,
      writeConfig: undefined,
    })

    expect(wrapped).not.toContain('(allow network-outbound (remote ip "*:')
    expect(wrapped).not.toContain('Direct-dial IP egress')
  })

  it('produces a byte-identical profile when allowedIPs is absent or empty', () => {
    const base = {
      command: 'echo hi',
      needsNetworkRestriction: true,
      readConfig: undefined,
      writeConfig: undefined,
    }

    const without = wrapCommandWithSandboxMacOS(base)
    const empty = wrapCommandWithSandboxMacOS({ ...base, allowedIPs: [] })

    // Absent and empty must be indistinguishable (don't disturb existing
    // profiles), and neither may carry the allowedIPs marker comment.
    expect(empty).toBe(without)
    expect(without).not.toContain('Direct-dial IP egress')
    expect(without).not.toContain(ruleFor(9093))
  })

  it('emits rules alongside (not instead of) the proxy localhost rules', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: true,
      httpProxyPort: 3128,
      allowedIPs: ['10.0.0.0/23:9093'],
      readConfig: undefined,
      writeConfig: undefined,
    })

    expect(wrapped).toContain(ruleFor(9093))
    expect(wrapped).toContain(
      '(allow network-outbound (remote ip "localhost:3128"))',
    )
  })
})

describe.if(isMacOS)('macOS allowedIPs via SandboxManager', () => {
  beforeEach(async () => {
    await SandboxManager.reset()
  })
  afterEach(async () => {
    await SandboxManager.reset()
  })

  const configWith = (
    allowedIPs?: string[],
    allowedDomains: string[] = [],
  ): SandboxRuntimeConfig => ({
    network: {
      allowedDomains,
      deniedDomains: [],
      ...(allowedIPs !== undefined ? { allowedIPs } : {}),
    },
    filesystem: {
      denyRead: ['~/.ssh'],
      allowWrite: ['.', '/tmp'],
      denyWrite: ['.env'],
    },
  })

  it('restricts the network when only allowedIPs is configured (empty allowedDomains)', async () => {
    await SandboxManager.initialize(configWith(['10.0.0.0/23:9093']))

    const command = 'echo hi'
    const wrapped = await SandboxManager.wrapWithSandbox(command)

    // Wrapped (not passed through) and port rule present.
    expect(wrapped).not.toBe(command)
    expect(wrapped).toContain('(allow network-outbound (remote ip "*:9093"))')
    // Restricted profile: no blanket network allow.
    expect(wrapped).not.toContain('(allow network*)')
  })

  it('hot-applies allowedIPs through updateConfig()', async () => {
    await SandboxManager.initialize(configWith(undefined, ['example.com']))

    const before = await SandboxManager.wrapWithSandbox('echo hi')
    expect(before).not.toContain(
      '(allow network-outbound (remote ip "*:9093"))',
    )

    SandboxManager.updateConfig(
      configWith(['10.0.0.0/23:9093'], ['example.com']),
    )

    const after = await SandboxManager.wrapWithSandbox('echo hi')
    expect(after).toContain('(allow network-outbound (remote ip "*:9093"))')
  })
})
