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

  it('never sends the attempt token to an external HTTP leg', () => {
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
    expect(result.GIT_SSH_COMMAND).not.toContain('attempt-token')
  })

  it('never sends the attempt token to an external SOCKS leg', () => {
    const result = buildSandboxAttemptEnvironment({
      env: {},
      sandboxHttpProxyPort: 60080,
      sandboxSocksProxyPort: 7777,
      runtimeOwnsHttpProxy: true,
      runtimeOwnsSocksProxy: false,
      attemptProxyToken: 'attempt-token',
      legacySshProxyToken: 'session-token',
    })

    expect(result.HTTPS_PROXY).toContain('srt:attempt-token@localhost:60080')
    expect(result.FTP_PROXY).toBe('socks5h://localhost:7777')
    expect(result.FTP_PROXY).not.toContain('attempt-token')
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
    const result = buildSandboxAttemptEnvironment({
      sandboxHttpProxyPort: 60080,
      sandboxSocksProxyPort: 60080,
      runtimeOwnsHttpProxy: true,
      runtimeOwnsSocksProxy: true,
      attemptProxyToken: 'attempt-token',
      legacySshProxyToken: 'session-token',
    })

    expect(process.env).toEqual(before)
    expect(result).not.toBe(process.env)
  })

  it('parses generated assignments on only the first equals sign', () => {
    const result = buildSandboxAttemptEnvironment({
      env: {},
      sandboxHttpProxyPort: 60080,
      sandboxSocksProxyPort: 60080,
      runtimeOwnsHttpProxy: true,
      runtimeOwnsSocksProxy: true,
      attemptProxyToken: 'token=with=equals',
      legacySshProxyToken: 'session-token',
    })

    expect(result.HTTPS_PROXY).toBe(
      'http://srt:token=with=equals@localhost:60080',
    )
  })
})
