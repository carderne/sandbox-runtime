import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { isLinux } from '../helpers/platform.js'
import {
  MAX_OBSERVER_FRAME_BYTES,
  startLinuxSandboxViolationMonitor,
  type LinuxViolationMonitor,
} from '../../src/sandbox/linux-violation-monitor.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'

describe('linux-violation-monitor (listener)', () => {
  let mon: LinuxViolationMonitor
  const violations: { line: string; encodedCommand?: string }[] = []
  const attributed: Array<{
    correlation: string
    operation: string
    path: string
  }> = []
  const active = new Set(['corr_abcdefgh'])
  const allow = '/tmp/srt-test-allow'
  const deny = '/tmp/srt-test-allow/deny'

  beforeAll(async () => {
    mon = startLinuxSandboxViolationMonitor(
      v => violations.push({ line: v.line, encodedCommand: v.encodedCommand }),
      { allowWritePaths: [allow, '/dev'], denyWritePaths: [deny] },
      {
        hasActiveCorrelation: correlation => active.has(correlation),
        recordAttemptDenial: (correlation, operation, path) => {
          attributed.push({ correlation, operation, path })
          if (path === '/deactivate-after-first') active.delete(correlation)
        },
      },
    )
    await mon.ready
  })
  afterAll(() => mon.stop())

  /** Simulate apply-seccomp's outer stub with arbitrary transport chunks. */
  const sendChunks = (chunks: Array<string | Buffer>): Promise<void> =>
    new Promise((res, rej) => {
      const c = connect(mon.observeSocketPath!, () => {
        for (const chunk of chunks) c.write(chunk)
        c.end()
      })
      c.on('close', () => setTimeout(res, 10))
      c.on('error', rej)
    })

  const send = (lines: unknown[]): Promise<void> =>
    sendChunks(lines.map(line => JSON.stringify(line) + '\n'))

  it('binds a filesystem unix socket', () => {
    expect(mon.observeSocketPath).toBeDefined()
    expect(existsSync(mon.observeSocketPath!)).toBe(true)
  })

  it('routes attributed events and retains legacy classification', async () => {
    violations.length = 0
    attributed.length = 0
    await send([
      { attemptCorrelation: 'corr_abcdefgh' },
      { nr: 257, syscall: 'openat', path: `${allow}/attempt` },
      { nr: 263, syscall: 'unlinkat', path: '/etc/attempt' },
    ])
    await send([
      { encodedCommand: 'dGVzdA==' },
      { nr: 257, syscall: 'openat', path: `${allow}/ok` },
      { nr: 257, syscall: 'openat', path: '/dev/null' },
      { nr: 257, syscall: 'openat', path: `${deny}/bad` },
      { nr: 263, syscall: 'unlinkat', path: '/etc/passwd' },
    ])
    expect(attributed).toEqual([
      {
        correlation: 'corr_abcdefgh',
        operation: 'openat',
        path: `${allow}/attempt`,
      },
      {
        correlation: 'corr_abcdefgh',
        operation: 'unlinkat',
        path: '/etc/attempt',
      },
    ])
    expect(violations.map(v => v.line)).toEqual([
      `deny openat ${deny}/bad`,
      'deny unlinkat /etc/passwd',
    ])
    expect(violations[0].encodedCommand).toBe('dGVzdA==')
  })

  it('drops inactive, malformed, overlong, and unsupported attributed data', async () => {
    attributed.length = 0
    await send([
      { attemptCorrelation: 'inactive_corr' },
      { syscall: 'openat', path: '/inactive' },
    ])
    await send([
      { attemptCorrelation: 'corr_abcdefgh' },
      { syscall: 'openat', path: 'relative' },
      { syscall: 'read', path: '/unsupported' },
      { syscall: 'openat', path: `/${'p'.repeat(4096)}` },
      'not-an-object',
      [{ syscall: 'openat', path: '/array' }],
    ])
    await send([
      { attemptCorrelation: 'x'.repeat(129) },
      { syscall: 'openat', path: '/overlong-correlation' },
    ])
    expect(attributed).toEqual([])
  })

  it('checks correlation activity again before every attributed event', async () => {
    attributed.length = 0
    await send([
      { attemptCorrelation: 'corr_abcdefgh' },
      { syscall: 'openat', path: '/deactivate-after-first' },
      { syscall: 'openat', path: '/closed' },
    ])
    active.add('corr_abcdefgh')
    expect(attributed.map(event => event.path)).toEqual([
      '/deactivate-after-first',
    ])
  })

  it('handles split/coalesced frames and recovers after an oversized frame', async () => {
    attributed.length = 0
    const header = '{"attemptCorrelation":"corr_abcdefgh"}\n'
    await sendChunks([
      header.slice(0, 9),
      header.slice(9),
      '{"syscall":"openat","path":"/split"}\n' +
        '{"syscall":"unlinkat","path":"/coalesced"}\n',
    ])
    await sendChunks([
      Buffer.alloc(MAX_OBSERVER_FRAME_BYTES + 1, 0x61),
      '\n' + header + '{"syscall":"mkdirat","path":"/after-oversized"}\n',
    ])
    expect(attributed.map(event => event.path)).toEqual([
      '/split',
      '/coalesced',
      '/after-oversized',
    ])
  })

  it('drops relative legacy paths and normalizes policy comparisons', async () => {
    violations.length = 0
    await send([
      { encodedCommand: 'dGVzdA==' },
      { nr: 83, syscall: 'mkdir', path: 'rel/dir' },
      { syscall: 'openat', path: `${allow}/sub/../ok` },
      { syscall: 'openat', path: `${allow}/../escape` },
    ])
    expect(violations.map(v => v.line)).toEqual([
      `deny openat ${allow}/../escape`,
    ])
  })

  it('handles concurrent connections (one per command)', async () => {
    violations.length = 0
    await Promise.all([
      send([{ encodedCommand: 'YQ==' }, { syscall: 'openat', path: '/a' }]),
      send([{ encodedCommand: 'Yg==' }, { syscall: 'openat', path: '/b' }]),
      send([{ encodedCommand: 'Yw==' }, { syscall: 'openat', path: '/c' }]),
    ])
    expect(violations.map(v => v.line).sort()).toEqual([
      'deny openat /a',
      'deny openat /b',
      'deny openat /c',
    ])
  })

  it('ignores malformed frames and observe_init_error', async () => {
    violations.length = 0
    await sendChunks([
      'not json',
      '\n',
      JSON.stringify({ encodedCommand: 'dGVzdA==' }) + '\n',
      JSON.stringify({ observe_init_error: 'seccomp: EINVAL' }) + '\n',
      JSON.stringify({ nr: 257 }) + '\n',
      JSON.stringify({ syscall: 'openat', path: '/x' }) + '\n',
    ])
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
  const attributed: Array<{ operation: string; path: string }> = []

  beforeAll(async () => {
    spawnSync('mkdir', ['-p', allow, deny])
    mon = startLinuxSandboxViolationMonitor(
      v => violations.push(v.line),
      {
        allowWritePaths: [allow, '/dev'],
        denyWritePaths: [deny],
      },
      {
        hasActiveCorrelation: correlation => correlation === 'corr_abcdefgh',
        recordAttemptDenial: (_correlation, operation, path) =>
          attributed.push({ operation, path }),
      },
    )
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
          SRT_ENCODED_CMD: 'dGVzdA==',
        },
      },
    )
    expect(r.status).toBe(0)
    await new Promise(r => setTimeout(r, 100))
    expect(violations).toContain(`deny openat ${deny}/bad`)
    expect(violations.some(v => v.includes(`${allow}/ok`))).toBe(false)
  })

  it('resolves relative paths against the workload cwd', async () => {
    violations.length = 0
    const r = spawnSync(
      applyPath!,
      [
        '/bin/sh',
        '-c',
        // Allowed relative write, then a relative write that escapes into
        // the deny dir — both spelled relative, resolved by the supervisor.
        `cd ${allow} && echo a > rel-ok.txt && echo b > ../ro/rel-bad.txt`,
      ],
      {
        env: {
          ...process.env,
          SRT_OBSERVE_SOCK: mon.observeSocketPath!,
          SRT_ENCODED_CMD: 'dGVzdA==',
        },
      },
    )
    expect(r.status).toBe(0)
    await new Promise(r => setTimeout(r, 100))
    // The allowed relative write resolved inside allow → no violation.
    expect(violations.some(v => v.includes('rel-ok.txt'))).toBe(false)
    // The escaping relative write resolved into deny → violation, with
    // an absolute (cwd-joined) path.
    const bad = violations.find(v => v.includes('rel-bad.txt'))
    expect(bad).toBeDefined()
    expect(bad).toContain(`deny openat ${allow}/../ro/rel-bad.txt`)
  })

  it('emits attempt correlation through the real observer protocol', async () => {
    attributed.length = 0
    const r = spawnSync(
      applyPath!,
      ['/bin/sh', '-c', `echo x > ${deny}/attr`],
      {
        env: {
          ...process.env,
          SRT_OBSERVE_SOCK: mon.observeSocketPath!,
          SRT_ATTEMPT_CORRELATION: 'corr_abcdefgh',
          SRT_ENCODED_CMD: 'must-not-win',
        },
      },
    )
    expect(r.status).toBe(0)
    await new Promise(r => setTimeout(r, 100))
    expect(attributed).toContainEqual({
      operation: 'openat',
      path: `${deny}/attr`,
    })
  })

  it('does not hang when the listener stops reading (full pipe drops)', () => {
    // The event pipe is a bounded queue; a stalled consumer must cost
    // log lines, never workload time. 3000 writes far exceeds the pipe
    // capacity — pre-fix this froze at the first full-pipe write.
    const stall = startLinuxSandboxViolationMonitor(() => {}, {
      allowWritePaths: ['/'],
      denyWritePaths: [],
    })
    return stall.ready.then(() => {
      const dir = mkdtempSync(join(tmpdir(), 'srt-vmon-stall-'))
      try {
        const t0 = Date.now()
        const r = spawnSync(
          applyPath!,
          [
            '/bin/sh',
            '-c',
            `cd ${dir} && i=0; while [ $i -lt 3000 ]; do echo x > f$i; i=$((i+1)); done && echo DONE`,
          ],
          {
            env: { ...process.env, SRT_OBSERVE_SOCK: stall.observeSocketPath! },
            timeout: 20_000,
          },
        )
        expect(r.status).toBe(0)
        expect(String(r.stdout)).toContain('DONE')
        expect(Date.now() - t0).toBeLessThan(15_000)
      } finally {
        stall.stop()
        rmSync(dir, { recursive: true, force: true })
      }
    })
  }, 30_000)

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
