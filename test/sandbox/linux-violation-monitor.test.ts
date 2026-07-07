import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { isLinux } from '../helpers/platform.js'
import {
  startLinuxSandboxViolationMonitor,
  type LinuxViolationMonitor,
} from '../../src/sandbox/linux-violation-monitor.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'

const d = isLinux ? describe : describe.skip

d('linux-violation-monitor (listener)', () => {
  let mon: LinuxViolationMonitor
  const violations: { line: string; encodedCommand?: string }[] = []
  const allow = '/tmp/srt-test-allow'
  const deny = '/tmp/srt-test-allow/deny'

  beforeAll(async () => {
    mon = startLinuxSandboxViolationMonitor(
      v => violations.push({ line: v.line, encodedCommand: v.encodedCommand }),
      { allowWritePaths: [allow, '/dev'], denyWritePaths: [deny] },
    )
    await mon.ready
  })
  afterAll(() => mon.stop())

  /** Simulate apply-seccomp's outer stub: connect and write JSON lines. */
  const send = (lines: string[]): Promise<void> =>
    new Promise((res, rej) => {
      const c = connect(mon.observeSocketPath!, () => {
        c.write(lines.join('\n') + '\n')
        c.end()
      })
      c.on('close', () => res())
      c.on('error', rej)
    })

  it('binds a filesystem unix socket', () => {
    expect(mon.observeSocketPath).toBeDefined()
    expect(existsSync(mon.observeSocketPath!)).toBe(true)
  })

  it('filters allowed writes, surfaces denied writes', async () => {
    violations.length = 0
    await send([
      JSON.stringify({ encodedCommand: 'dGVzdA==' }), // base64("test")
      JSON.stringify({ nr: 257, syscall: 'openat', path: `${allow}/ok` }),
      JSON.stringify({ nr: 257, syscall: 'openat', path: '/dev/null' }),
      JSON.stringify({ nr: 257, syscall: 'openat', path: `${deny}/bad` }),
      JSON.stringify({ nr: 263, syscall: 'unlinkat', path: '/etc/passwd' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual([
      `deny openat ${deny}/bad`,
      'deny unlinkat /etc/passwd',
    ])
    expect(violations[0].encodedCommand).toBe('dGVzdA==')
  })

  it('reports relative (dirfd-unresolvable) paths', async () => {
    violations.length = 0
    await send([JSON.stringify({ nr: 83, syscall: 'mkdir', path: 'rel/dir' })])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual(['deny mkdir rel/dir'])
  })

  it('handles concurrent connections (one per command)', async () => {
    violations.length = 0
    await Promise.all([
      send([JSON.stringify({ syscall: 'openat', path: '/a' })]),
      send([JSON.stringify({ syscall: 'openat', path: '/b' })]),
      send([JSON.stringify({ syscall: 'openat', path: '/c' })]),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line).sort()).toEqual([
      'deny openat /a',
      'deny openat /b',
      'deny openat /c',
    ])
  })

  it('ignores malformed lines and observe_init_error', async () => {
    violations.length = 0
    await send([
      'not json',
      JSON.stringify({ observe_init_error: 'seccomp: EINVAL' }),
      JSON.stringify({ nr: 257 }), // no path
      JSON.stringify({ syscall: 'openat', path: '/x' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual(['deny openat /x'])
  })
})

// End-to-end against the real binary. Skipped if the vendored binary is
// missing for this arch (e.g. CI hasn't rebuilt it yet).
const applyPath = isLinux ? getApplySeccompBinaryPath() : null
const de = applyPath && existsSync(applyPath) ? describe : describe.skip

de('linux-violation-monitor + apply-seccomp (e2e)', () => {
  const work = mkdtempSync(join(tmpdir(), 'srt-vmon-'))
  const allow = join(work, 'rw')
  const deny = join(work, 'ro')
  let mon: LinuxViolationMonitor
  const violations: string[] = []

  beforeAll(async () => {
    spawnSync('mkdir', ['-p', allow, deny])
    mon = startLinuxSandboxViolationMonitor(v => violations.push(v.line), {
      allowWritePaths: [allow, '/dev'],
      denyWritePaths: [deny],
    })
    await mon.ready
  })
  afterAll(() => {
    mon.stop()
    rmSync(work, { recursive: true, force: true })
  })

  it('captures write-intent paths from a real workload', async () => {
    const r = spawnSync(
      applyPath!,
      ['/bin/sh', '-c', `echo a > ${allow}/ok; echo b > ${deny}/bad`],
      {
        env: {
          ...process.env,
          SRT_OBSERVE_SOCK: mon.observeSocketPath!,
        },
      },
    )
    expect(r.status).toBe(0)
    await new Promise(r => setTimeout(r, 100))
    expect(violations).toContain(`deny openat ${deny}/bad`)
    expect(violations.some(v => v.includes(`${allow}/ok`))).toBe(false)
  })

  it('does not hang when the listener is unreachable', () => {
    const t0 = Date.now()
    const r = spawnSync(
      applyPath!,
      ['/bin/sh', '-c', `echo a > ${allow}/ok2; exit 5`],
      {
        env: { ...process.env, SRT_OBSERVE_SOCK: '/nonexistent/sock' },
        timeout: 5000,
      },
    )
    expect(r.status).toBe(5)
    expect(Date.now() - t0).toBeLessThan(3000)
  })

  it('reports signal death as 128+signal', () => {
    // The namespace init cannot distinguish a worker's exit(128+N) from
    // a real signal death, so the status is relayed verbatim as an exit
    // code; the layer above (bwrap) applies its own normalization.
    const r = spawnSync(applyPath!, ['/bin/sh', '-c', 'kill -TERM $$'])
    expect(r.status).toBe(128 + 15)
  })
})
