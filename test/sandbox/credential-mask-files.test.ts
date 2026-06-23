import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
} from 'node:http'
import type { Server, AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
  extractAndSubstitute,
  extractPlaceholder,
  MASKED_FILE_STORE_PREFIX,
} from '../../src/sandbox/credential-mask-files.js'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Unit tests for the fake-file store and bind builder. Platform-agnostic;
 * these touch only the host filesystem and the sentinel registry.
 */

const FIXTURE_DIR = join(tmpdir(), 'srt-credmask-fixture-' + Date.now())
const TOKEN_FILE = join(FIXTURE_DIR, 'gh-token')
const TOKEN_CONTENT = 'ghp_realsecret_abcdef0123456789'
const SUBDIR = join(FIXTURE_DIR, 'aws-dir')

const HOSTS_YML = join(FIXTURE_DIR, 'hosts.yml')
const HOSTS_TOKEN = 'gho_realsecret_zyx9876543210'
const HOSTS_CONTENT =
  'github.com:\n' +
  '    user: alice\n' +
  `    oauth_token: ${HOSTS_TOKEN}\n` +
  '    git_protocol: https\n'

beforeAll(() => {
  mkdirSync(SUBDIR, { recursive: true })
  writeFileSync(TOKEN_FILE, TOKEN_CONTENT)
  writeFileSync(HOSTS_YML, HOSTS_CONTENT)
})

afterAll(() => {
  rmSync(FIXTURE_DIR, { recursive: true, force: true })
})

describe('MaskedFileStore', () => {
  test('lazily creates a temp dir under os.tmpdir()', () => {
    const store = new MaskedFileStore()
    expect(store.dirPath).toBeUndefined()
    const fake = store.write('k', 'sentinel')
    expect(store.dirPath).toBeDefined()
    expect(store.dirPath!.startsWith(tmpdir())).toBe(true)
    expect(store.dirPath!).toContain(MASKED_FILE_STORE_PREFIX)
    expect(readFileSync(fake, 'utf8')).toBe('sentinel')
    store.dispose()
  })

  test('store dir is outside the default sandbox-writable temp', () => {
    // The default writable temp inside the sandbox is /tmp/claude (see
    // getDefaultWritePaths). The fake dir must NOT be under it, or the
    // sandboxed process could tamper with the sentinel source.
    const store = new MaskedFileStore()
    store.write('k', 'x')
    expect(store.dirPath!.startsWith('/tmp/claude/')).toBe(false)
    expect(store.dirPath!.startsWith('/private/tmp/claude/')).toBe(false)
    store.dispose()
  })

  test('write is idempotent on key — same fake path, content overwritten', () => {
    const store = new MaskedFileStore()
    const a = store.write('file:/x', 'first')
    const b = store.write('file:/x', 'second')
    expect(b).toBe(a)
    expect(readFileSync(a, 'utf8')).toBe('second')
    expect(readdirSync(store.dirPath!)).toHaveLength(1)
    store.dispose()
  })

  test('dispose removes the temp dir and is idempotent', () => {
    const store = new MaskedFileStore()
    store.write('k', 'x')
    const dir = store.dirPath!
    expect(existsSync(dir)).toBe(true)
    store.dispose()
    expect(existsSync(dir)).toBe(false)
    expect(store.dirPath).toBeUndefined()
    store.dispose() // no-op, no throw
  })
})

describe('extractAndSubstitute', () => {
  test('single match: capture replaced by placeholder, rest preserved', () => {
    const content = 'github.com:\n  oauth_token: ghp_real\n  user: alice\n'
    const out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)')
    expect(out).not.toBeNull()
    expect(out!.captures).toEqual(['ghp_real'])
    expect(out!.fakeContent).toBe(
      `github.com:\n  oauth_token: ${extractPlaceholder(0)}\n  user: alice\n`,
    )
    expect(out!.fakeContent).not.toContain('ghp_real')
  })

  test('multiple distinct matches each get their own placeholder', () => {
    const content =
      'machine a.example.com password tok-A\n' +
      'machine b.example.com password tok-B\n'
    const out = extractAndSubstitute(content, 'password\\s+(\\S+)')!
    expect(out.captures).toEqual(['tok-A', 'tok-B'])
    expect(out.fakeContent).toBe(
      `machine a.example.com password ${extractPlaceholder(0)}\n` +
        `machine b.example.com password ${extractPlaceholder(1)}\n`,
    )
  })

  test('duplicate captures dedupe to one placeholder index', () => {
    const content = 'password tok-X\npassword tok-X\npassword tok-Y\n'
    const out = extractAndSubstitute(content, 'password (\\S+)')!
    expect(out.captures).toEqual(['tok-X', 'tok-Y'])
    expect(out.fakeContent).toBe(
      `password ${extractPlaceholder(0)}\n` +
        `password ${extractPlaceholder(0)}\n` +
        `password ${extractPlaceholder(1)}\n`,
    )
  })

  test('returns null when the pattern matches nothing', () => {
    expect(extractAndSubstitute('no creds here', 'password (\\S+)')).toBeNull()
  })

  test('throws when a match leaves group 1 undefined', () => {
    // Optional group that does not participate — accepting this would
    // mask nothing for that occurrence, so the helper refuses.
    expect(() => extractAndSubstitute('token: \n', 'token: (\\S+)?')).toThrow(
      /capture group 1/,
    )
  })

  test('a capture that is a substring of another does not corrupt the longer one', () => {
    // tok is a prefix of tok-long; longest-first replacement keeps the
    // longer capture intact.
    const content = 'a=tok-long b=tok'
    const out = extractAndSubstitute(content, '[ab]=(\\S+)')!
    expect(out.captures).toEqual(['tok-long', 'tok'])
    expect(out.fakeContent).toBe(
      `a=${extractPlaceholder(0)} b=${extractPlaceholder(1)}`,
    )
  })

  test('overlapping pattern matches are handled by the regex engine, not us', () => {
    // matchAll with /g does not return overlapping matches, so the
    // helper sees only the engine's non-overlapping set. This test pins
    // that assumption: 'aaa' against /(aa)/g matches once at index 0.
    const out = extractAndSubstitute('aaa', '(aa)')!
    expect(out.captures).toEqual(['aa'])
  })

  test('empty captures are skipped, not turned into placeholders', () => {
    // (\S*) can capture the empty string at end-of-line; replacing the
    // empty string would interleave a placeholder between every char.
    const out = extractAndSubstitute('k=v\nk=\n', 'k=(\\S*)')!
    expect(out.captures).toEqual(['v'])
    expect(out.fakeContent).toBe(`k=${extractPlaceholder(0)}\nk=\n`)
  })

  test('placeholders contain NUL so they cannot collide with text content', () => {
    expect(extractPlaceholder(0)).toContain('\0')
    expect(extractPlaceholder(7)).toBe('\0SRT_EXTRACT_7\0')
  })
})

describe('buildMaskedFileBinds', () => {
  test('registers a sentinel keyed on file path and writes it to a fake', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask' }],
      ['api.github.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    expect(binds[0]!.realPath).toBe(TOKEN_FILE)
    const fakeContent = readFileSync(binds[0]!.fakePath, 'utf8')
    expect(fakeContent.startsWith(SENTINEL_PREFIX)).toBe(true)
    // The fake holds the sentinel, never the real bytes.
    expect(fakeContent).not.toContain(TOKEN_CONTENT)
    // The registry maps that sentinel back to the real file content.
    expect(reg.lookupReal(fakeContent)).toBe(TOKEN_CONTENT)
    store.dispose()
  })

  test('a file sentinel only substitutes at its own injectHosts', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask', injectHosts: ['api.github.com'] }],
      ['api.github.com', 'evil.example.com'],
      reg,
      store,
    )
    const sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
    const eq = (h: string, p: string) => h === p

    const toGh = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toGh, 'api.github.com', eq)
    expect(toGh.authorization).toBe(`Bearer ${TOKEN_CONTENT}`)

    const toEvil = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toEvil, 'evil.example.com', eq)
    expect(toEvil.authorization).toBe(`Bearer ${sentinel}`)
    store.dispose()
  })

  test('absent injectHosts → defaults to allowedDomains', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask' }],
      ['fallback.example.com'],
      reg,
      store,
    )
    const sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
    const eq = (h: string, p: string) => h === p
    const headers = { authorization: sentinel }
    reg.substituteInHeaders(headers, 'fallback.example.com', eq)
    expect(headers.authorization).toBe(TOKEN_CONTENT)
    store.dispose()
  })

  test('skips a masked file that does not exist on the host', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
      [{ path: join(FIXTURE_DIR, 'no-such-file'), mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(degradeToDenyPaths).toHaveLength(0)
    expect(reg.size).toBe(0)
    // No fake was written → store dir was never created.
    expect(store.dirPath).toBeUndefined()
    store.dispose()
  })

  test('skips a masked entry that resolves to a directory', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: SUBDIR, mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    store.dispose()
  })

  test('ignores deny-mode entries', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'deny' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    store.dispose()
  })

  test('extract: fake preserves structure with sentinel substituted in', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
      [
        {
          path: HOSTS_YML,
          mode: 'mask',
          extract: 'oauth_token:\\s*(\\S+)',
          injectHosts: ['api.github.com'],
        },
      ],
      ['api.github.com'],
      reg,
      store,
    )
    expect(degradeToDenyPaths).toHaveLength(0)
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    // Structure preserved byte-for-byte except the token span.
    expect(fake).toContain('github.com:\n')
    expect(fake).toContain('    user: alice\n')
    expect(fake).toContain('    git_protocol: https\n')
    expect(fake).not.toContain(HOSTS_TOKEN)
    // The token was replaced by a sentinel registered for #0.
    const m = fake.match(/oauth_token: (\S+)/)
    expect(m![1]!.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(reg.lookupReal(m![1]!)).toBe(HOSTS_TOKEN)
    expect(reg.size).toBe(1)
    store.dispose()
  })

  test('extract with no match degrades the entry to deny', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
      [{ path: HOSTS_YML, mode: 'mask', extract: 'no_such_key: (\\S+)' }],
      ['api.github.com'],
      reg,
      store,
    )
    // Fail-closed: no bind is emitted (the real file is NOT exposed),
    // and the path is reported for the read-deny set.
    expect(binds).toHaveLength(0)
    expect(degradeToDenyPaths).toEqual([HOSTS_YML])
    expect(reg.size).toBe(0)
    expect(store.dirPath).toBeUndefined()
    store.dispose()
  })
})

/**
 * Linux integration for structured (extract) masking via SandboxManager:
 * the bound fake preserves the file's structure with the credential span
 * replaced by a sentinel.
 */
describe.if(isLinux)('structured file masking on Linux (extract)', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-extract-' + Date.now())
  const YML_FILE = join(TEST_DIR, 'hosts.yml')
  const YML_TOKEN = 'gho_struct_real_0123456789abcdef'
  const YML_CONTENT =
    'github.com:\n' +
    '    user: alice\n' +
    `    oauth_token: ${YML_TOKEN}\n` +
    '    git_protocol: https\n'

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
  }

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(YML_FILE, YML_CONTENT)
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [
          {
            path: YML_FILE,
            mode: 'mask',
            extract: 'oauth_token:\\s*(\\S+)',
          },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  test('cat inside the sandbox preserves YAML structure with sentinel', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${YML_FILE}`)
    expect(wrapped).not.toContain(YML_TOKEN)
    const result = runInSandbox(wrapped)
    expect(result.status).toBe(0)
    const seen = result.stdout
    // Every non-credential line is byte-identical to the real file.
    expect(seen).toContain('github.com:\n')
    expect(seen).toContain('    user: alice\n')
    expect(seen).toContain('    git_protocol: https\n')
    // The credential value is gone; a sentinel sits in its place.
    expect(seen).not.toContain(YML_TOKEN)
    const m = seen.match(/oauth_token: (\S+)/)
    expect(m).not.toBeNull()
    expect(m![1]!.startsWith(SENTINEL_PREFIX)).toBe(true)
    // Same line count and same length modulo the swapped span — the
    // rest of the file is untouched.
    expect(seen.split('\n')).toHaveLength(YML_CONTENT.split('\n').length)
    // The host-side registry maps that sentinel back to the real token.
    expect(SandboxManager.getSentinelRegistry().lookupReal(m![1]!)).toBe(
      YML_TOKEN,
    )
  })

  test('the masked file is read-only inside the sandbox', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(
      `sh -c 'echo pwned > ${YML_FILE}'`,
    )
    const result = runInSandbox(wrapped)
    expect(result.status).not.toBe(0)
    expect(readFileSync(YML_FILE, 'utf8')).toBe(YML_CONTENT)
  })
})

/**
 * Linux: an `extract` pattern that matches nothing must NOT bind the
 * real file — that would expose the credential the entry was meant to
 * protect. Instead the entry degrades to deny: reading the file inside
 * the sandbox fails.
 */
describe.if(isLinux)('extract no-match degrades to deny on Linux', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-nomatch-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'hosts.yml')
  const SECRET = 'gho_nomatch_real_0123456789'

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, `oauth_token: ${SECRET}\n`)
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [
          {
            path: SECRET_FILE,
            mode: 'mask',
            extract: 'will_not_match_(\\S+)',
          },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  test('reading the file inside the sandbox is denied (fail-closed)', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    // The real credential never appears in the wrapped command.
    expect(wrapped).not.toContain(SECRET)
    // No --ro-bind <fake> <real> — degraded entries go via denyRead, not
    // the masked-file bind path.
    expect(wrapped).not.toMatch(
      new RegExp(`--ro-bind \\S+\\.fake ${SECRET_FILE.replace(/\//g, '\\/')}`),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    // cat fails: the file is unreadable inside the sandbox, and the
    // real bytes are never exposed on stdout.
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain(SECRET)
  })
})

/**
 * macOS: SBPL cannot redirect a read, so a masked file degrades to a
 * (deny file-read* …) rule — same profile output as mode: "deny". The
 * fakePath is unused. Pure string assertion; runs on any platform.
 */
describe('file masking on macOS degrades to read-deny', () => {
  test('profile contains (deny file-read* …) for the masked path', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath: TOKEN_FILE, fakePath: '/unused' }],
    })
    expect(wrapped).toContain('deny file-read*')
    expect(wrapped).toContain(TOKEN_FILE)
    // The fake path never reaches the profile — SBPL can't bind-mount.
    expect(wrapped).not.toContain('/unused')
  })

  test('still sandboxes when masked files are the only restriction', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
      maskedFileBinds: [{ realPath: TOKEN_FILE, fakePath: '/unused' }],
    })
    expect(wrapped).not.toBe('echo hi')
    expect(wrapped).toContain('deny file-read*')
  })

  test('an extract-mode masked file still degrades to (deny file-read*)', () => {
    // extract changes only the fake-file CONTENT; the macOS path keys
    // off the bind list, not the content, so structured masking is
    // exactly as unsupported as whole-file masking — the file is denied.
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [
        {
          path: HOSTS_YML,
          mode: 'mask',
          extract: 'oauth_token:\\s*(\\S+)',
        },
      ],
      ['api.github.com'],
      reg,
      store,
    )
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      maskedFileBinds: binds,
    })
    expect(wrapped).toContain('deny file-read*')
    expect(wrapped).toContain(HOSTS_YML)
    expect(wrapped).not.toContain(binds[0]!.fakePath)
    // The real credential never reaches the profile.
    expect(wrapped).not.toContain(HOSTS_TOKEN)
    store.dispose()
  })
})

/**
 * SandboxManager-level file masking on Linux: bwrap binds the fake over
 * the real path; the sandboxed process reads the sentinel; the real bytes
 * never appear in the wrapped command string.
 */
describe.if(isLinux)('file masking on Linux (bwrap)', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-linux-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'token')
  const SECRET_CONTENT = 'ghp_linux_real_secret_0123456789'
  const CONTROL_FILE = join(TEST_DIR, 'control.txt')

  function baseConfig(
    overrides: Partial<SandboxRuntimeConfig> = {},
  ): SandboxRuntimeConfig {
    return {
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [TEST_DIR, '/tmp'],
        denyWrite: [],
      },
      credentials: {
        files: [{ path: SECRET_FILE, mode: 'mask' }],
        allowPlaintextInject: true,
      },
      ...overrides,
    }
  }

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
  }

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)
    writeFileSync(CONTROL_FILE, 'control-ok')
    await SandboxManager.reset()
    await SandboxManager.initialize(baseConfig())
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  describe('bwrap argv generation', () => {
    test('emits --ro-bind <fake> <real> with the sentinel as fake content', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      const m = wrapped.match(
        new RegExp(`--ro-bind (\\S+) ${SECRET_FILE.replace(/\//g, '\\/')}\\b`),
      )
      expect(m).not.toBeNull()
      const fakePath = m![1]!
      expect(fakePath).not.toBe('/dev/null')
      const fakeContent = readFileSync(fakePath, 'utf8')
      expect(fakeContent.startsWith(SENTINEL_PREFIX)).toBe(true)
      // The registry maps that sentinel back to the real bytes.
      expect(SandboxManager.getSentinelRegistry().lookupReal(fakeContent)).toBe(
        SECRET_CONTENT,
      )
    })

    test('the real file content never appears in the wrapped command', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      expect(wrapped).not.toContain(SECRET_CONTENT)
    })

    test('a masked file that does not exist on the host emits no bind', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          credentials: {
            files: [{ path: join(TEST_DIR, 'no-such-token'), mode: 'mask' }],
            allowPlaintextInject: true,
          },
        }),
      )
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      expect(wrapped).not.toContain('no-such-token')

      // Restore for the remaining tests.
      await SandboxManager.reset()
      await SandboxManager.initialize(baseConfig())
    })

    test('repeat wraps reuse the same fake file (no per-call leak)', async () => {
      await SandboxManager.wrapWithSandbox('true')
      await SandboxManager.wrapWithSandbox('true')
      const dir = SandboxManager.getMaskedFileStore().dirPath!
      expect(readdirSync(dir)).toHaveLength(1)
    })
  })

  describe('integration', () => {
    test('cat <maskedFile> inside the sandbox returns the sentinel', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      expect(result.stdout.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(result.stdout).not.toContain(SECRET_CONTENT)
    })

    test('the masked file is read-only inside the sandbox', async () => {
      // Even though TEST_DIR is in allowWrite, the --ro-bind on the
      // masked path layers on top — overwriting it would expose a way
      // to swap the sentinel for something the proxy might still inject.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c 'echo pwned > ${SECRET_FILE}'`,
      )
      const result = runInSandbox(wrapped)
      expect(result.status).not.toBe(0)
      // Real file on the host is untouched.
      expect(readFileSync(SECRET_FILE, 'utf8')).toBe(SECRET_CONTENT)
    })

    test('a non-masked sibling file is still readable unchanged', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `cat ${CONTROL_FILE}`,
      )
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      expect(result.stdout).toBe('control-ok')
    })
  })

  test('reset() removes the fake-file temp dir', async () => {
    await SandboxManager.wrapWithSandbox('true')
    const dir = SandboxManager.getMaskedFileStore().dirPath
    expect(dir).toBeDefined()
    expect(existsSync(dir!)).toBe(true)
    await SandboxManager.reset()
    expect(existsSync(dir!)).toBe(false)
    expect(SandboxManager.getMaskedFileStore().dirPath).toBeUndefined()
    // Re-initialize for any following tests.
    await SandboxManager.initialize(baseConfig())
  })
})

/**
 * End-to-end: a token *file* is masked; inside the sandbox a tool reads
 * the file and sends its content as a header. The manager-started proxy
 * substitutes sentinel→real for the file's injectHost only. Reuses the
 * pattern from credential-mask.test.ts (allowPlaintextInject, plain HTTP
 * upstream, SandboxManager's own proxy port).
 */
describe.if(isLinux)('end-to-end file masking via SandboxManager', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-e2e-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'token')
  const SECRET_CONTENT = 'ghp_e2e_real_secret_0123456789'
  const HOST_A = 'localhost'
  const HOST_B = 'localtest.me'

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)

    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [{ path: SECRET_FILE, mode: 'mask', injectHosts: [HOST_A] }],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    await new Promise<void>(r => upstream.close(() => r()))
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  // Async spawn — spawnSync would block the event loop and the
  // in-process proxy/upstream couldn't accept the connection.
  async function curlViaManagerProxy(
    url: string,
    bearer: string,
    resolve?: string,
  ): Promise<number> {
    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    const args = [
      '-sS',
      '--max-time',
      '10',
      '--proxy',
      `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
      '-H',
      `Authorization: Bearer ${bearer}`,
    ]
    if (resolve) args.push('--resolve', resolve)
    args.push(url)
    const child = spawn('curl', args)
    child.stdout.on('data', () => {})
    child.stderr.on('data', () => {})
    return new Promise(r => child.on('close', code => r(code ?? 1)))
  }

  test('cat inside the sandbox + manager proxy → injectHost gets real bytes', async () => {
    // bwrap leg: cat inside the sandbox returns the sentinel.
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    expect(wrapped).not.toContain(SECRET_CONTENT)
    const inSandbox = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(inSandbox.status).toBe(0)
    const sentinel = inSandbox.stdout
    expect(sentinel.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(sentinel).not.toContain(SECRET_CONTENT)

    // Proxy leg: the same sentinel sent through the manager-started
    // proxy reaches HOST_A (injectHost) as the real file content.
    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_A}:${upstreamPort}/`,
      sentinel,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${SECRET_CONTENT}`)
  }, 20000)

  test('a non-injectHost destination receives the sentinel unchanged', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    const sentinel = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    }).stdout

    // HOST_B is allowlisted but NOT in this file's injectHosts. The
    // proxy dials localtest.me (publicly resolves to 127.0.0.1) and
    // forwards the sentinel as-is — fails closed.
    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_B}:${upstreamPort}/`,
      sentinel,
      `${HOST_B}:${upstreamPort}:127.0.0.1`,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
    expect(lastHeaders?.authorization).not.toContain(SECRET_CONTENT)
  }, 20000)
})

/**
 * End-to-end structured (extract) masking: a multi-credential file is
 * masked with a regex; inside the sandbox a tool parses the sentinel out
 * of the preserved structure and sends it as a header; the proxy swaps
 * each sentinel to its own real captured value at the injectHost.
 */
describe.if(isLinux)(
  'end-to-end structured file masking via SandboxManager',
  () => {
    const TEST_DIR = join(tmpdir(), 'srt-credmask-extract-e2e-' + Date.now())
    const HOST_A = 'localhost'
    const HOST_B = 'localtest.me'

    // hosts.yml-style: one credential, structure must survive.
    const YML_FILE = join(TEST_DIR, 'hosts.yml')
    const YML_TOKEN = 'gho_e2e_real_0123456789abcdef'
    const YML_CONTENT =
      'github.com:\n' +
      '    user: alice\n' +
      `    oauth_token: ${YML_TOKEN}\n` +
      '    git_protocol: https\n'

    // .netrc-style: two credentials → two sentinels, each must swap to
    // its own real value at the proxy.
    const NETRC_FILE = join(TEST_DIR, 'netrc')
    const NETRC_TOK_A = 'npm_e2e_real_aaaaaaaa'
    const NETRC_TOK_B = 'npm_e2e_real_bbbbbbbb'
    const NETRC_CONTENT =
      `machine a.example.com login alice password ${NETRC_TOK_A}\n` +
      `machine b.example.com login bob password ${NETRC_TOK_B}\n`

    let upstream: Server
    let upstreamPort: number
    let lastHeaders: IncomingHttpHeaders | undefined

    beforeAll(async () => {
      mkdirSync(TEST_DIR, { recursive: true })
      writeFileSync(YML_FILE, YML_CONTENT)
      writeFileSync(NETRC_FILE, NETRC_CONTENT)

      upstream = createHttpServer((req, res) => {
        lastHeaders = req.headers
        res.writeHead(200)
        res.end('ok')
      })
      await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
      upstreamPort = (upstream.address() as AddressInfo).port

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
        credentials: {
          files: [
            {
              path: YML_FILE,
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
              injectHosts: [HOST_A],
            },
            {
              path: NETRC_FILE,
              mode: 'mask',
              extract: 'password\\s+(\\S+)',
              injectHosts: [HOST_A],
            },
          ],
          allowPlaintextInject: true,
        },
      })
    })

    afterAll(async () => {
      await SandboxManager.reset()
      await new Promise<void>(r => upstream.close(() => r()))
      rmSync(TEST_DIR, { recursive: true, force: true })
    })

    function runInSandbox(wrappedCommand: string) {
      return spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
    }

    async function curlViaManagerProxy(
      url: string,
      bearer: string,
      resolve?: string,
    ): Promise<number> {
      const proxyPort = SandboxManager.getProxyPort()!
      const authToken = SandboxManager.getProxyAuthToken()!
      const args = [
        '-sS',
        '--max-time',
        '10',
        '--proxy',
        `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
        '-H',
        `Authorization: Bearer ${bearer}`,
      ]
      if (resolve) args.push('--resolve', resolve)
      args.push(url)
      const child = spawn('curl', args)
      child.stdout.on('data', () => {})
      child.stderr.on('data', () => {})
      return new Promise(r => child.on('close', code => r(code ?? 1)))
    }

    test('hosts.yml: parse sentinel from structure → upstream gets real token', async () => {
      // bwrap leg: extract the oauth_token field from the masked YAML
      // inside the sandbox — the file parses, and the field value is
      // the sentinel.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "grep oauth_token ${YML_FILE} | awk '{print \\$2}'"`,
      )
      expect(wrapped).not.toContain(YML_TOKEN)
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      const sentinel = result.stdout.trim()
      expect(sentinel.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sentinel).not.toContain(YML_TOKEN)

      // Proxy leg: the sentinel reaches HOST_A as the real token.
      lastHeaders = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_A}:${upstreamPort}/`,
        sentinel,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${YML_TOKEN}`)
    }, 20000)

    test('.netrc: two captures → two sentinels, each swaps to its own value', async () => {
      // bwrap leg: read both password fields inside the sandbox.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "awk '{print \\$NF}' ${NETRC_FILE}"`,
      )
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      const [sA, sB] = result.stdout.trim().split('\n')
      expect(sA!.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sB!.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sA).not.toBe(sB)
      expect(result.stdout).not.toContain(NETRC_TOK_A)
      expect(result.stdout).not.toContain(NETRC_TOK_B)

      // Proxy leg: each sentinel swaps to its own real captured value.
      lastHeaders = undefined
      let exit = await curlViaManagerProxy(
        `http://${HOST_A}:${upstreamPort}/`,
        sA!,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${NETRC_TOK_A}`)

      lastHeaders = undefined
      exit = await curlViaManagerProxy(`http://${HOST_A}:${upstreamPort}/`, sB!)
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${NETRC_TOK_B}`)
    }, 20000)

    test('an extract sentinel does not substitute at a non-injectHost', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "grep oauth_token ${YML_FILE} | awk '{print \\$2}'"`,
      )
      const sentinel = runInSandbox(wrapped).stdout.trim()

      lastHeaders = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_B}:${upstreamPort}/`,
        sentinel,
        `${HOST_B}:${upstreamPort}:127.0.0.1`,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
      expect(lastHeaders?.authorization).not.toContain(YML_TOKEN)
    }, 20000)
  },
)
