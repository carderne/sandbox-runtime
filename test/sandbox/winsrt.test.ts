import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer, type Server } from 'node:net'
import type { AddressInfo } from 'node:net'
import { isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import {
  getSrtWinPath,
  getWindowsWfpStatus,
  getWindowsSandboxUserStatus,
  installWindowsSandbox,
  uninstallWindowsSandbox,
  verifyWindowsWfpEgress,
  wrapCommandWithSandboxWindows,
  parseWindowsBinShell,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
} from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * Windows network-sandbox integration tests.
 *
 * The sandboxed child runs as the dedicated `srt-sandbox` user via
 * the two-hop launch (`CreateProcessWithLogonW`). beforeAll
 * provisions that account + the user-SID-keyed WFP filters under a
 * dedicated test sublayer; afterAll uninstalls.
 *
 * Real end-to-end (the actual fence) is also covered by
 * `vendor/srt-win-src/ci/smoke-exec.ps1` which runs before this file
 * in CI; this suite proves the TS layer wires correctly on top.
 */

// Dedicated test sublayer (distinct from smoke.ps1's b2e8a6c4-… and
// smoke-exec.ps1's 5b0e64f4-… so the three suites are independent).
const TEST_SUBLAYER = '7c1f0e90-3a2b-4f5d-9e8c-1d2e3f4a5b6c'

// Match smoke-exec.ps1's range; the WFP install below uses it.
const PORT_RANGE: readonly [number, number] = DEFAULT_WINDOWS_PROXY_PORT_RANGE

// Bash userland gates (Group E). git-for-windows ships the first;
// msys2 wget only exists on runners with msys2 installed.
const GIT_BASH = 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'
const MSYS2_WGET = 'C:\\msys64\\usr\\bin\\wget.exe'

/** True if `name` resolves on PATH (via `where.exe`). */
function hasTool(name: string): boolean {
  if (!isWindows) return false
  const r = spawnSync('where', [name], { encoding: 'utf8', timeout: 5_000 })
  return r.status === 0
}

function createTestConfig(
  allowedDomains: string[] = ['example.com'],
): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains,
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    },
    windows: {
      wfpSublayerGuid: TEST_SUBLAYER,
      proxyPortRange: [PORT_RANGE[0], PORT_RANGE[1]],
    },
  }
}

/** Run a command inside the Windows sandbox and capture output. */
async function runSandboxed(
  command: string,
  timeoutMs = 60_000,
  extraEnv?: Record<string, string>,
): Promise<{
  stdout: string
  stderr: string
  status: number | null
}> {
  const { argv, env } = await SandboxManager.wrapWithSandboxArgv(command)
  // The child reaches the proxy via the runner's --env overlay; the
  // returned `env` is the BROKER's spawn env (proxy vars also there
  // for diagnostics, but the runner's overlay is what the child sees).
  return spawnAsync(argv[0], argv.slice(1), {
    timeout: timeoutMs,
    env: extraEnv ? { ...env, ...extraEnv } : env,
  })
}

type RunResult = { stdout: string; stderr: string; status: number | null }

/**
 * Run a sandboxed command up to `attempts` times until `ok` holds.
 * For ALLOW rows only (they hit live hosts; a registry/network blip
 * should not read as a security regression). NEVER use on BLOCK
 * rows — those must stay single-shot so a fluke "allowed" can't be
 * retried away.
 */
async function runSandboxedUntil(
  command: string,
  ok: (r: RunResult) => boolean,
  attempts = 2,
  timeoutMs = 60_000,
): Promise<RunResult> {
  let last: RunResult = { stdout: '', stderr: '', status: null }
  for (let i = 0; i < attempts; i++) {
    last = await runSandboxed(command, timeoutMs)
    if (ok(last)) return last
  }
  return last
}

/**
 * Assert the sandboxed run exited with one of `allowed`; on failure
 * throw with captured stdout+stderr so a CI failure self-explains
 * (curl/tool errors go to stderr — keep `-sS` on curl rows).
 */
function expectStatus(label: string, r: RunResult, allowed: number[]): void {
  if (allowed.includes(r.status ?? -999)) return
  throw new Error(
    `${label}: exit ${r.status} not in [${allowed.join(',')}] · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

/**
 * Assert a sandboxed BLOCK row did NOT succeed (exit 0 = the egress
 * reached the host = fence broken). The exact failure code varies by
 * platform/build (DNS-resolve, resolver-thread, connect, TLS, …), so
 * assert only not-success and capture stderr for diagnosis —
 * enumerating codes is cross-platform whack-a-mole. Do NOT re-tighten.
 */
function expectEgressBlocked(label: string, r: RunResult): void {
  if (r.status !== 0) return
  throw new Error(
    `${label}: direct/blocked egress unexpectedly SUCCEEDED (exit 0) · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

interface BoundListener {
  port: number
  close: () => Promise<void>
}

function listenOn(port: number): Promise<BoundListener> {
  return new Promise((resolve, reject) => {
    // Minimal HTTP/1.1 responder so a sandboxed `curl` that REACHES
    // it exits 0. A raw-TCP "ok\n" reply makes curl exit non-zero on
    // HTTP-parse failure even though the TCP connect — the
    // loopback-PERMIT we're proving — succeeded.
    const srv: Server = createServer(sock => {
      sock.on('data', () => {
        sock.end(
          'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n',
        )
      })
      sock.on('error', () => {})
    })
    srv.once('error', reject)
    srv.listen(port, '127.0.0.1', () => {
      const actual = (srv.address() as AddressInfo).port
      resolve({
        port: actual,
        close: () =>
          new Promise<void>(r => {
            srv.close(() => r())
          }),
      })
    })
  })
}

/**
 * Bind the first free port from `candidates`, retrying on
 * EADDRINUSE. Used by the IN-range loopback row (C6) where the
 * candidate list is the proxy range minus the live proxy ports.
 */
async function bindFirstFree(candidates: number[]): Promise<BoundListener> {
  let lastErr: unknown
  for (const p of candidates) {
    try {
      return await listenOn(p)
    } catch (e) {
      lastErr = e
      if ((e as NodeJS.ErrnoException)?.code !== 'EADDRINUSE') throw e
    }
  }
  throw new Error(
    `no free port among ${candidates.join(',')}: ${(lastErr as Error)?.message}`,
  )
}

/**
 * Bind an ephemeral loopback port (the OS picks) and return it
 * provided it falls OUTSIDE the WFP-allowed proxy port range. If
 * the assigned port lands in the range (the Windows ephemeral pool
 * 49152–65535 overlaps it), close and retry — capped at 5; the
 * chance of all 5 landing in a 10-port window of ~16k is
 * effectively zero.
 */
async function bindOutOfRange(): Promise<BoundListener> {
  for (let i = 0; i < 5; i++) {
    const l = await listenOn(0)
    if (l.port < PORT_RANGE[0] || l.port > PORT_RANGE[1]) {
      return l
    }
    await l.close()
  }
  throw new Error(
    `bindOutOfRange: 5 ephemeral binds all landed in ` +
      `[${PORT_RANGE[0]}, ${PORT_RANGE[1]}]`,
  )
}

// Pure-JS object test — runs on all platforms. SRT_WIN_PATH is
// pointed at any existing file so getSrtWinPath() doesn't throw on
// non-Windows hosts.
describe('wrapCommandWithSandboxWindows (pure, all platforms)', () => {
  it('argv shape: --env overlay before --', () => {
    const prev = process.env.SRT_WIN_PATH
    process.env.SRT_WIN_PATH = process.execPath
    try {
      const on = wrapCommandWithSandboxWindows({
        command: 'exit 0',
        httpProxyPort: 60080,
      })
      // Two-hop overlay rides on --env: PATH + the single-sourced
      // proxy set. Values follow each --env as KEY=VALUE.
      const envArgs = on.argv.filter((_, i) => on.argv[i - 1] === '--env')
      expect(envArgs.some(e => e.startsWith('PATH='))).toBe(true)
      expect(envArgs).toContain('HTTP_PROXY=http://localhost:60080')
      // CA-bundle vars are NOT forwarded — the bundle lives in
      // broker %TEMP%, unreadable by srt-sandbox.
      expect(envArgs.some(e => e.startsWith('NODE_EXTRA_CA_CERTS='))).toBe(
        false,
      )
      // Every --env must precede `--` (clap stops parsing after it).
      expect(on.argv.lastIndexOf('--env')).toBeLessThan(on.argv.indexOf('--'))
      // --as-sandbox-user is still passed while srt-win has
      // LaunchMode::SameUser as the default; the Rust same-user-
      // removal PR drops both the flag and this assertion.
      expect(on.argv).toContain('--as-sandbox-user')
      // Obsolete discriminator-group flags must NOT appear.
      for (const dead of [
        '--group-sid',
        '--name',
        '--holder-pid',
        '--skip-group-check',
      ]) {
        expect(on.argv).not.toContain(dead)
      }
    } finally {
      if (prev === undefined) delete process.env.SRT_WIN_PATH
      else process.env.SRT_WIN_PATH = prev
    }
  })
})

describe('parseWindowsBinShell (pure, all platforms)', () => {
  it('maps tokens/paths and rejects the rest', () => {
    expect(parseWindowsBinShell(undefined)).toEqual({ kind: 'cmd' })
    expect(parseWindowsBinShell('cmd')).toEqual({ kind: 'cmd' })
    expect(parseWindowsBinShell('pwsh')).toEqual({ kind: 'pwsh' })
    expect(parseWindowsBinShell('PowerShell')).toEqual({ kind: 'powershell' })
    for (const p of [
      'C:\\Program Files\\Git\\bin\\bash.exe',
      'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
      'C:\\Program Files\\Git\\bin\\sh.exe',
    ]) {
      expect(parseWindowsBinShell(p)).toEqual({ kind: 'bash', path: p })
    }
    // Bare/relative bash token: caller must pass the resolved absolute
    // install path (PATH-resolved 'bash' could be WSL, not Git Bash).
    expect(() => parseWindowsBinShell('bash')).toThrow(/absolute/)
    // Unknown values fail loud rather than silently routing to cmd.exe.
    expect(() => parseWindowsBinShell('zsh')).toThrow(/unrecognised binShell/)
    expect(() =>
      parseWindowsBinShell('C:\\Program Files\\Git\\git-bash.exe'),
    ).toThrow(/unrecognised binShell/)
    // An absolute path to pwsh/cmd is NOT a token — reject rather than
    // silently dropping the caller's path and degrading to PATH lookup.
    expect(() =>
      parseWindowsBinShell('C:\\Program Files\\PowerShell\\7\\pwsh.exe'),
    ).toThrow(/unrecognised binShell/)
  })
})

describe.if(isWindows)('Windows sandbox: srt-win helpers', () => {
  it('getSrtWinPath resolves to an existing binary', () => {
    const p = getSrtWinPath()
    expect(existsSync(p)).toBe(true)
    expect(p).toMatch(/srt-win\.exe$/i)
  })

  it('wrapCommandWithSandboxWindows: binShell={kind:bash} → [path, -c, cmd] (not cmd.exe)', () => {
    const cmd = `echo 'a b' && printf '%s' x | cat`
    const bashPath = 'C:\\Program Files\\Git\\bin\\bash.exe'
    const { argv } = wrapCommandWithSandboxWindows({
      command: cmd,
      binShell: { kind: 'bash', path: bashPath },
    })
    expect(argv.slice(-3)).toEqual([bashPath, '-c', cmd])
    expect(argv).not.toContain('/c')
    expect(argv.join(' ')).not.toMatch(/cmd\.exe/i)
  })

  it('getWindowsWfpStatus reports absent for a never-installed sublayer', () => {
    const ws = getWindowsWfpStatus({
      sublayerGuid: '11111111-2222-3333-4444-555555555555',
    })
    expect(ws.state).toBe('absent')
    expect(ws.filters).toBe(0)
  })

  // The non-elevated readiness check that initialize() runs.
  // Hermetic sublayer + full-uninstall in finally so the
  // round-trips test below starts from an unprovisioned state.
  it('verifyWindowsWfpEgress: blocked after install; throws after uninstall --keep-user', async () => {
    const sl = '6a1e0f80-2b3c-4d5e-9f8a-1b2c3d4e5f60'
    installWindowsSandbox({
      sublayerGuid: sl,
      proxyPortRange: PORT_RANGE,
    })
    try {
      // Fence active: WFP block-user filter fires at
      // ALE_AUTH_CONNECT before any packet leaves → WSAEACCES. The
      // probe binds a local out-of-range loopback listener; no
      // external host involved.
      const v = await verifyWindowsWfpEgress({ proxyPortRange: PORT_RANGE })
      expect(v.target).toMatch(/^127\.0\.0\.1:\d+$/)
      // Filters removed, sandbox user kept → fence inactive →
      // throws. This is the throw initialize() relays when a stale
      // install (user provisioned, filters since removed) would
      // otherwise run every exec with full egress. The regex
      // matches both the exit-3 (`is not active`) and exit-2
      // (`could not be verified`) messages — either is correct
      // fail-closed behaviour.
      uninstallWindowsSandbox({ sublayerGuid: sl, keepUser: true })
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        verifyWindowsWfpEgress({ proxyPortRange: PORT_RANGE }),
      ).rejects.toThrow(/WFP egress fence/i)
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl })
    }
  }, 60_000)

  it('installWindowsSandbox round-trips user + wfp under a fresh sublayer', () => {
    // The runner is admin (precondition asserted by smoke-exec.ps1),
    // so srt-win install runs without a UAC prompt and `cancelled`
    // is never set.
    const sl = '8d2f1e91-4b3c-5a6e-af9d-2e3f4a5b6c7d'
    try {
      const r = installWindowsSandbox({
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
      })
      expect(r.cancelled).toBeUndefined()
      expect(r.wfp.state).toBe('installed')
      expect(r.wfp.filters).toBeGreaterThanOrEqual(4)
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[1]])
      // Sandbox user provisioned alongside the WFP.
      expect(r.user.provisioned).toBe(true)
      expect(r.user.sid).toMatch(/^S-1-5-21-/)
      expect(r.user.groupExists).toBe(true)
      expect(r.user.inBuiltinUsers).toBe(true)
      expect(r.user.inSandboxGroup).toBe(true)
      expect(r.user.credPresent).toBe(true)
      expect(r.user.markerVersion).toBe(1)
      expect(r.wfp.userSid).toBe(r.user.sid)
      // Idempotent re-run with the SAME config also succeeds.
      const r2 = installWindowsSandbox({
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
      })
      expect(r2.cancelled).toBeUndefined()
      expect(r2.wfp.state).toBe('installed')
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl })
    }
    expect(getWindowsWfpStatus({ sublayerGuid: sl }).state).toBe('absent')
    const u = getWindowsSandboxUserStatus()
    expect(u.provisioned).toBe(false)
    expect(u.credPresent).toBe(false)
    expect(u.markerVersion).toBeUndefined()
  })

  it('installWindowsSandbox refuses different-config without force (exit 13)', () => {
    const sl = '9e3a2fa2-5c4d-6b7f-ba0e-3f4a5b6c7d8e'
    try {
      installWindowsSandbox({ sublayerGuid: sl, proxyPortRange: PORT_RANGE })
      // Re-install with a DIFFERENT port range under the same
      // sublayer without force → exit 13 → throw.
      expect(() =>
        installWindowsSandbox({
          sublayerGuid: sl,
          proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
        }),
      ).toThrow(/already exist.*different/i)
      // With force → succeeds and replaces.
      const r = installWindowsSandbox({
        sublayerGuid: sl,
        proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
        force: true,
      })
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[0] + 1])
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl })
    }
  })

  it('initialize() throws when sandbox user is not provisioned', async () => {
    // After the previous uninstall, the user is absent.
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.initialize(createTestConfig())).rejects.toThrow(
      /sandbox user is not provisioned.*windows-install/is,
    )
    await SandboxManager.reset()
  })

  it('initialize() with filesystem.denyRead applies the DENY ACE', async () => {
    // Re-provision so the not-provisioned gate doesn't fire first.
    installWindowsSandbox({
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
    })
    const scratch = mkdtempSync(join(tmpdir(), 'srt-fsdeny-'))
    const f = join(scratch, 'secret.txt')
    writeFileSync(f, 'x')
    try {
      const cfg = createTestConfig()
      cfg.filesystem.denyRead = [f]
      await SandboxManager.initialize(cfg)
      // The DENY-ACE mechanism is now wired (no longer throws); the
      // actual deny enforcement is covered by H6. Here we just
      // assert the lifecycle (initialize → reset) round-trips.
      await SandboxManager.reset()
    } finally {
      rmSync(scratch, { recursive: true, force: true })
      // Leave the install in place for the network describe below.
    }
    // 60s: install + initialize() runs verifyWindowsWfpEgress(); first
    // call after a fresh user-provision creates the seclogon profile
    // (~8s on the CI runner), same budget as the verify test above.
  }, 60_000)
})

describe.if(isWindows)('Windows sandbox: SandboxManager network', () => {
  let sbSid: string

  beforeAll(async () => {
    // Checkpoints to stderr (flushed synchronously) so that if the
    // runtime faults mid-setup the LAST line in the CI log
    // localizes the faulting step.
    console.error('[winsrt beforeAll] start')
    // Full install under the test sublayer — provisions
    // srt-sandbox + cred + user-SID WFP filters. Idempotent (the
    // helpers describe above may have left it installed).
    console.error('[winsrt beforeAll] install: begin')
    const r = installWindowsSandbox({
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
    })
    if (!r.user.provisioned || !r.user.sid || !r.user.credPresent) {
      throw new Error(
        `srt-sandbox not provisioned after install: ${JSON.stringify(r.user)}`,
      )
    }
    sbSid = r.user.sid
    console.error('[winsrt beforeAll] install: done')
    expect(r.wfp.state).toBe('installed')
    expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[1]])

    console.error('[winsrt beforeAll] SandboxManager.initialize: begin')
    await SandboxManager.initialize(createTestConfig())
    console.error('[winsrt beforeAll] done')
  })

  afterAll(async () => {
    await SandboxManager.reset()
    uninstallWindowsSandbox({ sublayerGuid: TEST_SUBLAYER })
  })

  it('wrapWithSandbox() throws on Windows (use wrapWithSandboxArgv)', async () => {
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.wrapWithSandbox('echo hi')).rejects.toThrow(
      /wrapWithSandboxArgv/,
    )
  })

  it('wrapWithSandboxArgv returns argv carrying the --env overlay', async () => {
    const { argv } = await SandboxManager.wrapWithSandboxArgv('echo hi')
    expect(argv[0]).toMatch(/srt-win\.exe$/i)
    expect(argv).toContain('exec')
    // Proxy ports ride as --env KEY=VALUE pairs to the runner.
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    const httpProxy = envArgs.find(e => e.startsWith('HTTP_PROXY='))
    const allProxy = envArgs.find(e => e.startsWith('ALL_PROXY='))
    expect(httpProxy).toMatch(/^HTTP_PROXY=http:\/\/.+:\d+$/)
    expect(allProxy).toMatch(/^ALL_PROXY=http:\/\/.+:\d+$/)
    const httpPort = Number(httpProxy!.split(':').pop())
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    // The FULL set rides along, not just the standard trio.
    expect(envArgs.some(e => e.startsWith('DOCKER_HTTP_PROXY='))).toBe(true)
    // Last element is the user's command, passed verbatim to cmd /c.
    expect(argv.slice(-4)).toEqual(['/d', '/s', '/c', 'echo hi'])
  })

  it('proxy ports match what SandboxManager reports', () => {
    const httpPort = SandboxManager.getProxyPort()
    const socksPort = SandboxManager.getSocksProxyPort()
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    expect(socksPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(socksPort).toBeLessThanOrEqual(PORT_RANGE[1])
  })

  // ════════════════════════════════════════════════════════════════
  // Group H — two-hop launch fundamentals
  // ════════════════════════════════════════════════════════════════

  it('H1: child runs as srt-sandbox (different user SID)', async () => {
    const r = await runSandboxed('whoami /user /FO CSV /NH')
    expectStatus('H1', r, [0])
    expect(r.stdout).toContain(sbSid)
  }, 60_000)

  it('H2: stdout marker pipes through runner to broker', async () => {
    const r = await runSandboxed('echo H2-STDOUT-MARK')
    expectStatus('H2', r, [0])
    expect(r.stdout).toContain('H2-STDOUT-MARK')
  }, 60_000)

  it('H3: USERPROFILE isolated to srt-sandbox', async () => {
    const r = await runSandboxed('echo %USERPROFILE%')
    expectStatus('H3', r, [0])
    expect(r.stdout.toLowerCase()).toContain('srt-sandbox')
  }, 60_000)

  // ════════════════════════════════════════════════════════════════
  // Group B — egress via real tools (allowed → reaches host via proxy)
  // ════════════════════════════════════════════════════════════════
  // Each row that needs hosts beyond example.com calls updateConfig()
  // first: the JS proxy's filter reads config.network.allowedDomains
  // live, so the allowlist changes without rebinding the proxies.

  it('B1: curl to an allowedDomains host → 200 via proxy', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxedUntil(
      'curl -s -m 15 -o NUL -w "%{http_code}" https://example.com',
      x => x.stdout.trim() === '200',
    )
    expectStatus('B1', r, [0])
    expect(r.stdout.trim()).toBe('200')
  }, 90_000)

  it('B2: powershell Invoke-WebRequest to a NON-allowed host → blocked', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-WebRequest https://google.com -UseBasicParsing -TimeoutSec 8).StatusCode } catch { 'ERR' }"`,
    )
    expect(r.stdout.trim()).not.toBe('200')
  }, 60_000)

  it('B3: cmd /c curl to a SECOND allowed host (github.com) → 200', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com', 'github.com']))
    const r = await runSandboxedUntil(
      'curl -s -m 15 -o NUL -w "%{http_code}" https://github.com',
      x => x.stdout.trim() === '200',
    )
    expectStatus('B3', r, [0])
    expect(r.stdout.trim()).toBe('200')
  }, 90_000)

  it.skipIf(!hasTool('node'))(
    'B5: node https.get direct egress is BLOCKED (proxy env not honoured)',
    async () => {
      // KEY: Node's built-in https does NOT read HTTPS_PROXY, so it
      // attempts a DIRECT connect. The user-SID WFP filter must
      // refuse it. This is the load-bearing proof that WFP — not the
      // proxy env vars — is the real network boundary.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=Date.now();require('https').get('https://example.com',r=>{console.log('OK:'+r.statusCode);process.exit(0)}).on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},6000)"`,
      )
      expect(r.stdout.startsWith('OK:')).toBe(false)
    },
    60_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Group C — direct-egress / bypass resistance
  // ════════════════════════════════════════════════════════════════

  it('C1: powershell Test-NetConnection 1.1.1.1:80 → blocked at WFP', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$ErrorActionPreference='SilentlyContinue'; (Test-NetConnection 1.1.1.1 -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded"`,
    )
    expect(r.stdout.trim().toLowerCase()).not.toBe('true')
  }, 60_000)

  it('C4: curl --noproxy "*" strips env → WFP still BLOCKS', async () => {
    // KEY: clearing the proxy env makes curl attempt direct egress;
    // WFP must still refuse it. Pairs with B5 as the "env-var bypass
    // doesn't defeat WFP" proof.
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      'curl --noproxy "*" -sS -m 5 https://example.com',
    )
    expectEgressBlocked('C4', r)
  }, 60_000)

  it.skipIf(!hasTool('node'))(
    'C5: node raw socket to 1.1.1.1:80 → not CONNECTED',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=require('net').connect(80,'1.1.1.1');s.setTimeout(4000);s.on('connect',()=>{console.log('CONNECTED');process.exit(0)});s.on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});s.on('timeout',()=>{console.log('TIMEOUT');process.exit(2)})"`,
      )
      expect(r.stdout.includes('CONNECTED')).toBe(false)
    },
    60_000,
  )

  // ── loopback port-range fence ────────────────────────────────────

  it('C6: child reaches an IN-range loopback port (loopback PERMIT)', async () => {
    const httpP = SandboxManager.getProxyPort()
    const socksP = SandboxManager.getSocksProxyPort()
    const candidates: number[] = []
    for (let p = PORT_RANGE[1]; p >= PORT_RANGE[0]; p--) {
      if (p !== httpP && p !== socksP) candidates.push(p)
    }
    const l = await bindFirstFree(candidates)
    try {
      const r = await runSandboxed(
        `curl -sS -m 5 -o NUL -w "%{http_code}" --noproxy "*" http://127.0.0.1:${l.port}`,
      )
      expectStatus('C6', r, [0])
    } finally {
      await l.close()
    }
  }, 60_000)

  it('C7: child BLOCKED from an OUT-of-range loopback port', async () => {
    const l = await bindOutOfRange()
    try {
      expect(l.port < PORT_RANGE[0] || l.port > PORT_RANGE[1]).toBe(true)
      const r = await runSandboxed(
        `curl -sS -m 5 -o NUL -w "%{http_code}" --noproxy "*" http://127.0.0.1:${l.port}`,
      )
      expectEgressBlocked('C7', r)
    } finally {
      await l.close()
    }
  }, 60_000)

  // ════════════════════════════════════════════════════════════════
  // Group D — the proxy port is not an open relay
  // ════════════════════════════════════════════════════════════════

  it.skipIf(!hasTool('curl'))(
    'D2: host curl --socks5 to proxy is not an open relay (disallowed host refused)',
    async () => {
      const socksPort = SandboxManager.getSocksProxyPort()
      const token = SandboxManager.getProxyAuthToken()
      expect(socksPort).toBeGreaterThan(0)
      expect(token).toBeTruthy()

      // Drive curl through the SOCKS proxy to a LOCAL responder via
      // ASYNC spawn. spawnSync blocks bun's event loop, but the SOCKS
      // proxy runs IN this process — self-deadlock → timeout.
      const l = await listenOn(0)
      SandboxManager.updateConfig(createTestConfig(['127.0.0.1']))
      const socks = (host: string, withAuth = true): string[] => [
        '--socks5-hostname',
        withAuth
          ? `srt:${token}@127.0.0.1:${socksPort}`
          : `127.0.0.1:${socksPort}`,
        '-sS',
        '-m',
        '5',
        '-o',
        'NUL',
        '-w',
        '%{http_code}',
        host,
      ]
      try {
        // Host process WITHOUT the secret → refused at the SOCKS
        // handshake.
        const noAuth = await spawnAsync(
          'curl',
          socks(`http://127.0.0.1:${l.port}`, false),
          { timeout: 10_000 },
        )
        expect(noAuth.status).not.toBe(0)

        // Allowed dest reached THROUGH the proxy.
        const ok = await spawnAsync(
          'curl',
          socks(`http://127.0.0.1:${l.port}`),
          { timeout: 10_000 },
        )
        if (ok.stdout.trim() !== '200') {
          throw new Error(
            `D2 allowed: expected 200 · status=${ok.status} · ` +
              `stdout=${JSON.stringify(ok.stdout)} · ` +
              `stderr=${JSON.stringify(ok.stderr)}`,
          )
        }

        // Disallowed dest → refused by the filter PRE-DIAL.
        const blocked = await spawnAsync('curl', socks('https://google.com'), {
          timeout: 10_000,
        })
        expectEgressBlocked('D2 disallowed', blocked)
      } finally {
        await l.close()
      }
    },
  )

  // ════════════════════════════════════════════════════════════════
  // Group E — bash userland (gated; skip if absent)
  // ════════════════════════════════════════════════════════════════

  it.skipIf(!existsSync(GIT_BASH))(
    'E1: git-bash curl to an allowed host → 200',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxedUntil(
        `"${GIT_BASH}" -c "curl -s -m 15 -o /dev/null -w '%{http_code}' https://example.com"`,
        x => x.stdout.trim() === '200',
      )
      expect(r.stdout.trim()).toBe('200')
    },
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E4: binShell=bash.exe — direct egress BLOCKED',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const cmd = `curl --noproxy '*' -sS -m 5 https://example.com`
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        cmd,
        GIT_BASH,
      )
      expect(argv.slice(-3)).toEqual([GIT_BASH, '-c', cmd])
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 60_000,
        env,
      })
      expectEgressBlocked('E4', r)
    },
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E5: binShell=bash.exe — &&, single-quote, pipe survive argv round-trip',
    async () => {
      const cmd = `printf '%s ' one && printf '%s' two | tr a-z A-Z`
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        cmd,
        GIT_BASH,
      )
      expect(argv.slice(-3)).toEqual([GIT_BASH, '-c', cmd])
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 60_000,
        env,
      })
      expectStatus('E5', r, [0])
      expect(r.stdout.trim()).toBe('one TWO')
    },
    90_000,
  )

  it.skipIf(!existsSync(MSYS2_WGET))(
    'E3: msys2 wget to an allowed host → 200',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `"${MSYS2_WGET}" -O NUL --server-response --timeout=15 https://example.com`,
      )
      if (!/HTTP\/[\d.]+ 200/.test(r.stderr + r.stdout)) {
        throw new Error(
          `E3 wget via proxy: no HTTP 200 seen · status=${r.status} · ` +
            `stderr=${JSON.stringify(r.stderr.slice(-2000))}`,
        )
      }
    },
    90_000,
  )

  it.skipIf(!hasTool('nslookup'))(
    'C2: nslookup with explicit server → direct UDP 53 blocked',
    async () => {
      // nslookup does its OWN direct UDP-53 query (bypasses the DNS
      // Client service), so the child's token hits the WFP
      // block-user filter.
      // NOTE: this is the DIRECT-DNS path; resolution via getaddrinfo
      // (Dnscache) is a separate, documented residual — see R1 below.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed('nslookup example.com 1.1.1.1')
      // Don't lean on exit code (varies across Windows builds) or on
      // the generic "Address:" line (nslookup prints the SERVER's own
      // address before any answer). Assert the resolved-NAME answer
      // section is absent AND a failure signature is present.
      expect(r.stdout).not.toMatch(/Name:\s*example\.com/i)
      expect(r.stdout + r.stderr).toMatch(
        /timed out|can't find|no response|request to .* failed|server failed/i,
      )
    },
    20_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Residual pins (documented Windows limitations — NOT bugs)
  // ════════════════════════════════════════════════════════════════
  // These fail loudly if a future change accidentally CLOSES a
  // documented residual.

  it.skipIf(!hasTool('node'))(
    'R1: DNS resolution via getaddrinfo/Dnscache is NOT fenced',
    async () => {
      // getaddrinfo → DNS Client service (NetworkService token) does
      // the wire query, so ALE_USER_ID never sees the child. The
      // child can therefore resolve ARBITRARY names (a DNS-exfil
      // channel) even for hosts it cannot connect to. Resolve a
      // non-allowlisted name to make the point.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "require('dns').lookup('google.com',(e,a)=>{console.log(e?'ERR:'+e.code:'OK:'+a);process.exit(e?1:0)})"`,
      )
      expect(r.stdout.startsWith('OK:')).toBe(true)
    },
    20_000,
  )

  it('R2: ICMP (ping) is NOT fenced', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed('ping -n 1 -w 3000 8.8.8.8')
    // ICMP doesn't traverse ALE_AUTH_CONNECT, so the design can't
    // fence it. A regression that DID start blocking ICMP would make
    // ping report "General failure" — assert we never see that.
    expect(r.stdout).not.toMatch(/General failure/i)
  }, 60_000)
})

describe.if(isWindows)(
  'Windows sandbox: two-hop sandbox-user launch (H-rows)',
  () => {
    let exe: string
    let sbSid: string

    beforeAll(() => {
      exe = getSrtWinPath()
      // Full install under the test sublayer — provisions
      // srt-sandbox + cred + user-SID WFP filters. Idempotent.
      const inst = spawnSync(
        exe,
        [
          'install',
          '--sublayer-guid',
          TEST_SUBLAYER,
          '--proxy-port-range',
          `${PORT_RANGE[0]}-${PORT_RANGE[1]}`,
        ],
        { encoding: 'utf8' },
      )
      if (inst.status !== 0) {
        throw new Error(`srt-win install failed: ${inst.stderr || inst.stdout}`)
      }
      const us = getWindowsSandboxUserStatus()
      if (!us.provisioned || !us.sid || !us.credPresent) {
        throw new Error(
          `srt-sandbox not provisioned after install: ${JSON.stringify(us)}`,
        )
      }
      sbSid = us.sid
    }, 60_000)

    // 60s: `srt-win uninstall` removes the sandbox user account +
    // WFP filters and can exceed bun's 5s default hook timeout
    // when a runner child from a prior test is still draining.
    afterAll(() => {
      spawnSync(exe, ['uninstall', '--sublayer-guid', TEST_SUBLAYER], {
        encoding: 'utf8',
        timeout: 55_000,
      })
    }, 60_000)

    async function rexec(tail: string) {
      const { argv, env } = wrapCommandWithSandboxWindows({
        command: tail,
      })
      return spawnAsync(argv[0], argv.slice(1), {
        env,
        timeout: 60_000,
      })
    }

    it('H1: child runs as srt-sandbox (different user SID)', async () => {
      const r = await rexec('whoami /user /FO CSV /NH')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain(sbSid)
    }, 60_000)

    it('H2: stdout marker pipes through runner to broker', async () => {
      const r = await rexec('echo H2-STDOUT-MARK')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('H2-STDOUT-MARK')
    }, 60_000)

    it('H3: USERPROFILE isolated to srt-sandbox', async () => {
      const r = await rexec('echo %USERPROFILE%')
      expect(r.status).toBe(0)
      expect(r.stdout.toLowerCase()).toContain('srt-sandbox')
    }, 60_000)

    it('H4: direct outbound blocked by F-USER-BLOCK', async () => {
      const r = await rexec(
        'set "HTTP_PROXY=" & set "HTTPS_PROXY=" & set "ALL_PROXY=" & ' +
          'curl -sS -m 5 https://example.com',
      )
      // Exit-code only — see B/C convention: any non-zero is fenced.
      expect(r.status).not.toBe(0)
    }, 60_000)

    // ── H5-H8: FS parity via SandboxManager (grant + deny ACEs) ──
    // The G-rows in smoke-exec.ps1 exercise the srt-win primitives
    // directly; these check the SandboxManager.initialize() →
    // grant + stamp → reset() → revoke + restore plumbing.
    let hScratch: string
    let hSecret: string
    let hSibling: string

    type FsOverrides = Partial<SandboxRuntimeConfig['filesystem']>
    function createFsTestConfig(fs: FsOverrides): SandboxRuntimeConfig {
      const base = createTestConfig()
      return { ...base, filesystem: { ...base.filesystem, ...fs } }
    }

    async function rexecSandboxed(cmd: string, fs: FsOverrides) {
      await SandboxManager.initialize(createFsTestConfig(fs))
      try {
        const wrapped = await SandboxManager.wrapWithSandboxArgv(cmd)
        return await spawnAsync(wrapped.argv[0], wrapped.argv.slice(1), {
          env: wrapped.env,
          timeout: 60_000,
        })
      } finally {
        await SandboxManager.reset()
      }
    }

    it('H5: allowWrite grants the working tree — child reads sibling', async () => {
      hScratch = mkdtempSync(join(tmpdir(), 'srt-h-'))
      hSecret = join(hScratch, 'secret.txt')
      hSibling = join(hScratch, 'sibling.txt')
      writeFileSync(hSecret, 'SECRET')
      writeFileSync(hSibling, 'SIBLING')
      const r = await rexecSandboxed(`type "${hSibling}"`, {
        allowWrite: [hScratch],
      })
      if (r.status !== 0 || !r.stdout.includes('SIBLING')) {
        throw new Error(
          `H5: child read sibling under allowWrite tree failed — ` +
            `exit=${r.status} stderr=${JSON.stringify(r.stderr)} ` +
            `stdout=${JSON.stringify(r.stdout)}`,
        )
      }
    }, 90_000)

    it('H6: allowWrite + denyRead — secret denied, sibling readable', async () => {
      const r = await rexecSandboxed(
        `type "${hSecret}" & echo --SEP-- & type "${hSibling}"`,
        { allowWrite: [hScratch], denyRead: [hSecret] },
      )
      if (r.stdout.includes('SECRET')) {
        throw new Error(
          `H6: child read the denyRead target — ` +
            `stdout=${JSON.stringify(r.stdout)}`,
        )
      }
      if (!r.stdout.includes('SIBLING')) {
        throw new Error(
          `H6: sibling unreadable post-stamp — ` +
            `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
        )
      }
    }, 90_000)

    it('H-denyWrite: child cannot write the denyWrite target', async () => {
      // Was F2 under the same-user PROTECTED-stamp; re-expressed
      // for the additive-DENY-ACE path. Asserts the WRITE-deny
      // half only — the "child can still read" half is covered by
      // smoke-aces A2 (lands with the SYNCHRONIZE-strip fix in
      // the Rust same-user-removal PR; main's `DenyMask::WriteDeny`
      // includes SYNCHRONIZE so a synchronous read open is also
      // denied until then).
      const hCfg = join(hScratch, 'cfg.txt')
      writeFileSync(hCfg, 'CONFIG-V1')
      const w = await rexecSandboxed(`echo POISONED>"${hCfg}"`, {
        allowWrite: [hScratch],
        denyWrite: [hCfg],
      })
      const after = readFileSync(hCfg, 'utf8')
      if (after !== 'CONFIG-V1') {
        throw new Error(
          `H-denyWrite: target was modified — ` +
            `content=${JSON.stringify(after)} exit=${w.status} ` +
            `stderr=${JSON.stringify(w.stderr)}`,
        )
      }
    }, 90_000)

    it('H7: no allowWrite — child has no rights on real-user file', async () => {
      const r = await rexecSandboxed(`type "${hSibling}"`, {})
      if (r.status === 0 || r.stdout.includes('SIBLING')) {
        throw new Error(
          `H7: child read a real-user file with no grant — ` +
            `exit=${r.status} stdout=${JSON.stringify(r.stdout)}`,
        )
      }
    }, 90_000)

    it('H-glob: per-exec denyRead glob — expanded TS-side, both denied, restored', async () => {
      // Red→green for the per-exec/session-level glob asymmetry:
      // before this PR a per-exec `glob-*.secret` reached
      // `srt-win exec --deny-read` raw and `canonicalize_path`
      // hard-failed; now `wrapWithSandboxArgv` routes it through
      // `expandWindowsFsDenyPaths` (same chokepoint as session-
      // level) so the child sees two concrete `--deny-read` paths.
      const dir = mkdtempSync(join(tmpdir(), 'srt-hglob-'))
      const a = join(dir, 'glob-a.secret')
      const b = join(dir, 'glob-b.secret')
      writeFileSync(a, 'GLOB-A')
      writeFileSync(b, 'GLOB-B')
      await SandboxManager.initialize(createFsTestConfig({ allowWrite: [dir] }))
      try {
        const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
          `type "${a}" & echo --SEP-- & type "${b}"`,
          undefined,
          {
            filesystem: {
              denyRead: [join(dir, 'glob-*.secret')],
              allowWrite: [],
              denyWrite: [],
            },
          },
        )
        // Glob expanded TS-side: exactly two --deny-read flags;
        // no glob char survives onto the argv (Rust would
        // hard-fail otherwise).
        const denyIdx = argv.flatMap((x, i) => (x === '--deny-read' ? [i] : []))
        if (denyIdx.length !== 2) {
          throw new Error(
            `H-glob: expected 2 --deny-read flags after glob expand; ` +
              `got ${denyIdx.length}: ${JSON.stringify(argv)}`,
          )
        }
        for (const i of denyIdx) {
          if (argv[i + 1].includes('*') || argv[i + 1].includes('?')) {
            throw new Error(
              `H-glob: glob char survived into --deny-read value ` +
                `'${argv[i + 1]}' — per-exec expand not applied`,
            )
          }
        }
        const r = await spawnAsync(argv[0], argv.slice(1), {
          env,
          timeout: 60_000,
        })
        if (r.stdout.includes('GLOB-A') || r.stdout.includes('GLOB-B')) {
          throw new Error(
            `H-glob: child read a glob-expanded deny target — ` +
              `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
          )
        }
        // Per-exec restore: a fresh child (no customConfig) under
        // the same session can read both — proves the per-exec
        // stamp was lifted on child exit, not leaked onto disk.
        const wf = await SandboxManager.wrapWithSandboxArgv(
          `type "${a}" & type "${b}"`,
        )
        const rR = await spawnAsync(wf.argv[0], wf.argv.slice(1), {
          env: wf.env,
          timeout: 60_000,
        })
        if (!rR.stdout.includes('GLOB-A') || !rR.stdout.includes('GLOB-B')) {
          throw new Error(
            `H-glob: per-exec stamp NOT restored — fresh child still ` +
              `denied. stdout=${JSON.stringify(rR.stdout)} ` +
              `stderr=${JSON.stringify(rR.stderr)}`,
          )
        }
      } finally {
        await SandboxManager.reset()
        rmSync(dir, { recursive: true, force: true })
      }
    }, 120_000)

    it('H8: reset() revokes the grant — sandbox-user ACE gone', async () => {
      // After H5/H6/H7's reset() calls, the root's DACL must NOT
      // carry an explicit ACE for the sandbox user.
      const out = spawnSync('icacls', [hScratch], {
        encoding: 'utf8',
        timeout: 5_000,
      })
      if (out.stdout.includes(sbSid) || out.stdout.includes('srt-sandbox')) {
        throw new Error(
          `H8: srt-sandbox ACE still on '${hScratch}' after reset(): ` +
            out.stdout,
        )
      }
      rmSync(hScratch, { recursive: true, force: true })
    }, 30_000)
  },
)
