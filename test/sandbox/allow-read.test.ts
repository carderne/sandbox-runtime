import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'

function skipIfNotMacOS(): boolean {
  return getPlatform() !== 'macos'
}

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

/**
 * Tests for the allowRead (allowWithinDeny) feature.
 *
 * allowRead re-allows read access within regions blocked by denyRead.
 * allowRead takes precedence over denyRead — the opposite of write,
 * where denyWrite takes precedence over allowWrite.
 */
describe('allowRead precedence over denyRead', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'allow-read-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied')
  const TEST_ALLOWED_SUBDIR = join(TEST_DENIED_DIR, 'allowed')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_ALLOWED_FILE = join(TEST_ALLOWED_SUBDIR, 'visible.txt')
  const TEST_SECRET_CONTENT = 'TOP_SECRET'
  const TEST_ALLOWED_CONTENT = 'VISIBLE_DATA'

  beforeAll(() => {
    if (getPlatform() !== 'macos' && getPlatform() !== 'linux') {
      return
    }

    mkdirSync(TEST_ALLOWED_SUBDIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)
    writeFileSync(TEST_ALLOWED_FILE, TEST_ALLOWED_CONTENT)
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('macOS Seatbelt', () => {
    it('should deny reading a file in a denied directory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })

    it('should allow reading a file in an allowWithinDeny subdirectory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [TEST_ALLOWED_SUBDIR],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_ALLOWED_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
    })

    it('should still deny reading files outside the re-allowed subdirectory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [TEST_ALLOWED_SUBDIR],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })
  })

  describe('Linux bwrap', () => {
    it('should deny reading a file in a denied directory', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [],
      }

      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })

    it('should allow reading a file in an allowWithinDeny subdirectory', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [TEST_ALLOWED_SUBDIR],
      }

      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${TEST_ALLOWED_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
    })

    it('should still deny reading files outside the re-allowed subdirectory', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [TEST_ALLOWED_SUBDIR],
      }

      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })
  })
})

/**
 * Tests that allowRead-only configs (no denyRead) do not trigger sandbox overhead.
 */
describe('allowRead without denyRead does not trigger sandboxing', () => {
  const command = 'echo hello'

  it('returns command unchanged on macOS when only allowWithinDeny is set', () => {
    if (skipIfNotMacOS()) {
      return
    }

    const result = wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [], allowWithinDeny: ['/some/path'] },
      writeConfig: undefined,
    })

    expect(result).toBe(command)
  })

  it('returns command unchanged on Linux when only allowWithinDeny is set', async () => {
    if (skipIfNotLinux()) {
      return
    }

    const result = await wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [], allowWithinDeny: ['/some/path'] },
      writeConfig: undefined,
    })

    expect(result).toBe(command)
  })
})
