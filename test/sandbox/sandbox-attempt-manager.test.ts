import { once } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { SandboxAttemptRegistry } from '../../src/sandbox/sandbox-attempt-registry.js'
import type {
  SandboxAttemptHandle,
  SandboxAttemptDescriptor,
} from '../../src/sandbox/sandbox-attempt-types.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

const supported = isMacOS || isLinux
const d = supported ? describe : describe.skip

function config(
  overrides: Partial<SandboxRuntimeConfig['network']> = {},
  allowWrite: string[] = [],
): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: [],
      deniedDomains: [],
      ...overrides,
    },
    filesystem: { denyRead: [], allowWrite, denyWrite: [] },
  }
}

function attemptToken(descriptor: SandboxAttemptDescriptor): string {
  return new URL(descriptor.env.HTTPS_PROXY!).password
}

function hostReachableAttemptProxy(
  descriptor: SandboxAttemptDescriptor,
): string {
  if (!isLinux) return descriptor.env.HTTPS_PROXY!
  const url = new URL(descriptor.env.HTTPS_PROXY!)
  url.port = String(SandboxManager.getProxyPort())
  return url.toString()
}

function proxyConnect(
  proxyUrl: string,
  host = 'denied.example',
): Promise<number> {
  const url = new URL(proxyUrl)
  const auth = Buffer.from(`${url.username}:${url.password}`).toString('base64')
  return new Promise((resolve, reject) => {
    let response = ''
    const socket = connect(Number(url.port), '127.0.0.1', () => {
      socket.write(
        `CONNECT ${host}:443 HTTP/1.1\r\n` +
          `Host: ${host}:443\r\n` +
          `Proxy-Authorization: Basic ${auth}\r\n\r\n`,
      )
    })
    socket.on('data', chunk => {
      response += chunk.toString()
      const status = /HTTP\/1\.1 (\d+)/.exec(response)?.[1]
      if (status) {
        socket.destroy()
        resolve(Number(status))
      }
    })
    socket.on('error', reject)
    socket.setTimeout(2_000, () => {
      socket.destroy()
      reject(new Error('proxy response timed out'))
    })
  })
}

async function rejected(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    return error as Error
  }
  throw new Error('expected promise to reject')
}

d('SandboxManager attributed attempts', () => {
  let attemptCwd: string

  beforeEach(async () => {
    await SandboxManager.reset()
    attemptCwd = mkdtempSync(join(tmpdir(), 'srt-attempt-manager-'))
  })

  afterEach(async () => {
    await SandboxManager.reset()
    rmSync(attemptCwd, { recursive: true, force: true })
  })

  it('returns isolated immutable-input descriptors and executes one spawn', async () => {
    await SandboxManager.initialize(config({}, [attemptCwd]))
    const supplied = { ...process.env, KEEP: 'yes', HTTPS_PROXY: 'stale' }
    const processEnvBefore = { ...process.env }
    const a = await SandboxManager.prepareSandboxAttempt({
      command: 'printf attributed',
      cwd: attemptCwd,
      env: supplied,
    })
    const b = await SandboxManager.prepareSandboxAttempt({
      command: 'printf attributed',
      cwd: attemptCwd,
    })

    expect(a.attempt.attemptId).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(a.attempt.attemptId).not.toBe(b.attempt.attemptId)
    expect(a.env).not.toBe(supplied)
    expect(a.env.KEEP).toBe('yes')
    expect(supplied.HTTPS_PROXY).toBe('stale')
    expect(process.env).toEqual(processEnvBefore)
    expect(attemptToken(a)).not.toBe('')
    expect(a.argv.join('\0')).not.toContain(attemptToken(a))
    if (isMacOS) expect(a.sandboxBackend).toBe('macos-seatbelt')
    if (isLinux) expect(a.sandboxBackend).toMatch(/^linux-(?:bwrap|seccomp)$/)
    if (isLinux) {
      expect(a.env.HTTPS_PROXY).toContain('localhost:3128')
      expect(a.env.FTP_PROXY).toContain('localhost:1080')
      expect(a.env.GIT_SSH_COMMAND).toContain(
        SandboxManager.getProxyAuthToken()!,
      )
      expect(a.env.GIT_SSH_COMMAND).not.toContain(attemptToken(a))
    }
    if (isMacOS) {
      expect(a.argv.join('\0')).toContain(join(attemptCwd, '.mcp.json'))
    }

    const child = spawn(a.argv[0]!, a.argv.slice(1), {
      shell: false,
      cwd: attemptCwd,
      env: a.env,
    })
    let stdout = ''
    child.stdout?.on('data', chunk => (stdout += chunk.toString()))
    const [status] = await once(child, 'close')
    expect(status).toBe(0)
    expect(stdout).toBe('attributed')

    SandboxManager.cleanupAfterCommand()
    expect(
      (await SandboxManager.finishSandboxAttempt(a.attempt)).denials,
    ).toEqual([])
    SandboxManager.cleanupAfterCommand()
    expect(
      (await SandboxManager.finishSandboxAttempt(b.attempt)).denials,
    ).toEqual([])
  })

  it('attributes denied proxy requests independently by descriptor token', async () => {
    await SandboxManager.initialize(config())
    const a = await SandboxManager.prepareSandboxAttempt({ command: 'same' })
    const b = await SandboxManager.prepareSandboxAttempt({ command: 'same' })

    expect(await proxyConnect(hostReachableAttemptProxy(a))).toBe(403)
    expect(await proxyConnect(hostReachableAttemptProxy(b))).toBe(403)
    SandboxManager.cleanupAfterCommand()
    expect(
      (await SandboxManager.finishSandboxAttempt(a.attempt)).denials,
    ).toEqual([{ kind: 'network', source: 'http-proxy' }])
    SandboxManager.cleanupAfterCommand()
    expect(
      (await SandboxManager.finishSandboxAttempt(b.attempt)).denials,
    ).toEqual([{ kind: 'network', source: 'http-proxy' }])
  })

  it('rejects unknown, double-finished, and reset-invalidated handles', async () => {
    await SandboxManager.initialize(config())
    const descriptor = await SandboxManager.prepareSandboxAttempt({
      command: 'true',
    })
    expect(
      (
        await rejected(
          SandboxManager.finishSandboxAttempt({
            attemptId: 'unknown',
          } as SandboxAttemptHandle),
        )
      ).message,
    ).toMatch(/unknown or already finished/i)
    SandboxManager.cleanupAfterCommand()
    await SandboxManager.finishSandboxAttempt(descriptor.attempt)
    expect(
      (await rejected(SandboxManager.finishSandboxAttempt(descriptor.attempt)))
        .message,
    ).toMatch(/unknown or already finished/i)

    const resetRaced = await SandboxManager.prepareSandboxAttempt({
      command: 'true',
    })
    await SandboxManager.reset()
    expect(
      (await rejected(SandboxManager.finishSandboxAttempt(resetRaced.attempt)))
        .message,
    ).toMatch(/unknown|reset/i)
  })

  it('keeps attempt credentials off caller-owned proxy legs', async () => {
    await SandboxManager.initialize(config({ httpProxyPort: 43123 }))
    const descriptor = await SandboxManager.prepareSandboxAttempt({
      command: 'true',
    })
    const http = new URL(descriptor.env.HTTPS_PROXY!)
    const socks = new URL(descriptor.env.FTP_PROXY!)
    expect(http.port).toBe(isLinux ? '3128' : '43123')
    expect(http.password).toBe('')
    if (isLinux) expect(socks.port).toBe('1080')
    expect(socks.password).not.toBe('')
    expect(descriptor.argv.join('\0')).not.toContain(socks.password)
    SandboxManager.cleanupAfterCommand()
    await SandboxManager.finishSandboxAttempt(descriptor.attempt)
  })

  it('keeps attributed runtime environment keys after credential restrictions', async () => {
    const previousNoProxy = process.env.NO_PROXY
    process.env.NO_PROXY = 'parent-value-to-mask'
    try {
      await SandboxManager.initialize({
        ...config(),
        credentials: {
          allowPlaintextInject: true,
          envVars: [
            { name: 'HTTPS_PROXY', mode: 'deny' },
            { name: 'NO_PROXY', mode: 'mask' },
            { name: 'UNRELATED_SECRET', mode: 'deny' },
          ],
        },
      })
      const descriptor = await SandboxManager.prepareSandboxAttempt({
        command: 'true',
      })
      const argv = descriptor.argv.join('\0')

      expect(descriptor.env.HTTPS_PROXY).toContain('localhost:')
      expect(descriptor.env.NO_PROXY).toContain('localhost')
      expect(argv).not.toMatch(/(?:-u|--unsetenv)[ '"]+HTTPS_PROXY/)
      expect(argv).not.toContain('NO_PROXY=fake_value_')
      expect(argv).toContain('UNRELATED_SECRET')

      SandboxManager.cleanupAfterCommand()
      await SandboxManager.finishSandboxAttempt(descriptor.attempt)
    } finally {
      if (previousNoProxy === undefined) delete process.env.NO_PROXY
      else process.env.NO_PROXY = previousNoProxy
    }
  })

  it('masks credentials from the supplied attempt environment', async () => {
    const previousToken = process.env.API_TOKEN
    delete process.env.API_TOKEN
    try {
      await SandboxManager.initialize({
        ...config({}, [attemptCwd]),
        credentials: {
          allowPlaintextInject: true,
          envVars: [{ name: 'API_TOKEN', mode: 'mask' }],
        },
      })
      const supplied = { API_TOKEN: 'review-secret' }
      const descriptor = await SandboxManager.prepareSandboxAttempt({
        command: `printf '%s' "$API_TOKEN"`,
        cwd: attemptCwd,
        env: supplied,
      })

      const child = spawn(descriptor.argv[0]!, descriptor.argv.slice(1), {
        shell: false,
        cwd: attemptCwd,
        env: descriptor.env,
      })
      let stdout = ''
      child.stdout?.on('data', chunk => (stdout += chunk.toString()))
      const [status] = await once(child, 'close')

      expect(status).toBe(0)
      expect(stdout).toMatch(/^fake_value_[0-9a-f-]{36}$/)
      expect(stdout).not.toContain('review-secret')
      expect(supplied).toEqual({ API_TOKEN: 'review-secret' })

      SandboxManager.cleanupAfterCommand()
      await SandboxManager.finishSandboxAttempt(descriptor.attempt)
    } finally {
      if (previousToken === undefined) delete process.env.API_TOKEN
      else process.env.API_TOKEN = previousToken
    }
  })

  it('discards an unpublished attempt when wrapper preparation fails', async () => {
    await SandboxManager.initialize(config())
    const allocate = spyOn(SandboxAttemptRegistry.prototype, 'allocate')
    const activate = spyOn(SandboxAttemptRegistry.prototype, 'activate')
    const discard = spyOn(SandboxAttemptRegistry.prototype, 'discard')
    try {
      expect(
        (
          await rejected(
            SandboxManager.prepareSandboxAttempt({
              command: 'true',
              binShell: 'definitely-not-an-srt-shell',
            }),
          )
        ).message,
      ).toMatch(/shell.*not found/i)
      expect(allocate).toHaveBeenCalledTimes(1)
      expect(activate).not.toHaveBeenCalled()
      expect(discard).toHaveBeenCalledTimes(1)
    } finally {
      allocate.mockRestore()
      activate.mockRestore()
      discard.mockRestore()
    }
  })

  it('cleans up before finalizing after a spawn error', async () => {
    await SandboxManager.initialize(config())
    const descriptor = await SandboxManager.prepareSandboxAttempt({
      command: 'true',
    })
    descriptor.argv[0] = join(attemptCwd, 'missing-executable')
    const calls: string[] = []
    const originalCleanup = SandboxManager.cleanupAfterCommand
    const originalFinish = SandboxManager.finishSandboxAttempt
    const cleanup = spyOn(
      SandboxManager,
      'cleanupAfterCommand',
    ).mockImplementation(() => {
      calls.push('cleanup')
      originalCleanup()
    })
    const finish = spyOn(
      SandboxManager,
      'finishSandboxAttempt',
    ).mockImplementation(attempt => {
      calls.push('finish')
      return originalFinish(attempt)
    })
    try {
      try {
        const child = spawn(descriptor.argv[0]!, descriptor.argv.slice(1), {
          shell: false,
          cwd: attemptCwd,
          env: descriptor.env,
        })
        await once(child, 'error')
      } finally {
        SandboxManager.cleanupAfterCommand()
        await SandboxManager.finishSandboxAttempt(descriptor.attempt)
      }
      expect(calls).toEqual(['cleanup', 'finish'])
      expect(cleanup).toHaveBeenCalledTimes(1)
      expect(finish).toHaveBeenCalledTimes(1)
    } finally {
      cleanup.mockRestore()
      finish.mockRestore()
    }
  })

  it('keeps prepared wrappers fixed while updateConfig changes future attempts', async () => {
    const aPath = join(attemptCwd, 'a')
    const bPath = join(attemptCwd, 'b')
    mkdirSync(aPath)
    mkdirSync(bPath)
    await SandboxManager.initialize(config({}, [aPath]))
    const a = await SandboxManager.prepareSandboxAttempt({ command: 'true' })
    const aArgv = [...a.argv]
    SandboxManager.updateConfig(config({}, [bPath]))
    const b = await SandboxManager.prepareSandboxAttempt({ command: 'true' })

    expect(a.argv).toEqual(aArgv)
    expect(a.argv.join('\0')).toContain(aPath)
    expect(b.argv.join('\0')).toContain(bPath)
    if (isMacOS) expect(b.argv.join('\0')).not.toContain(aPath)
    SandboxManager.cleanupAfterCommand()
    await SandboxManager.finishSandboxAttempt(a.attempt)
    SandboxManager.cleanupAfterCommand()
    await SandboxManager.finishSandboxAttempt(b.attempt)
  })
})

it.skipIf(supported)(
  'rejects attempt preparation on unsupported platforms',
  async () => {
    expect(
      (
        await rejected(
          SandboxManager.prepareSandboxAttempt({ command: 'true' }),
        )
      ).message,
    ).toMatch(/not supported on platform/i)
  },
)
