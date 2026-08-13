import { describe, expect, it } from 'bun:test'
import { execFileSync, spawnSync } from 'node:child_process'
import { realpathSync } from 'node:fs'
import { join } from 'node:path'
import {
  generateSandboxProfile,
  wrapCommandWithSandboxMacOS,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

const browserTempDir = isMacOS
  ? realpathSync(
      execFileSync('/usr/bin/getconf', ['DARWIN_USER_TEMP_DIR'], {
        encoding: 'utf8',
      }).trim(),
    )
  : ''

function generateProfile(allowBrowserProcess: boolean): string {
  return generateSandboxProfile({
    needsNetworkRestriction: true,
    allowBrowserProcess,
    readConfig: undefined,
    writeConfig: { allowOnly: [], denyWithinAllow: [] },
    logTag: 'BROWSER_TEST',
  })
}

describe.if(isMacOS)('macOS Chromium browser process policy', () => {
  it('adds only the browser-scoped sysctl, loopback, and Darwin temp socket rules', () => {
    const profile = generateProfile(true)

    expect(profile).toContain('(sysctl-name "kern.hv_vmm_present")')
    expect(profile).toContain('(allow network-bind (local ip "*:*")')
    expect(profile).toContain(
      '(allow network-outbound (remote ip "localhost:*")',
    )
    expect(profile).toContain('(allow system-socket (socket-domain AF_UNIX))')
    expect(profile).toContain(
      `(allow network-bind (local unix-socket (subpath "${browserTempDir}")))`,
    )
    expect(profile).toContain(
      `(allow network-outbound (remote unix-socket (subpath "${browserTempDir}")))`,
    )
    expect(profile).toContain(
      `(allow file-read* file-write* (subpath "${browserTempDir}"))`,
    )
    expect(profile).not.toContain('unix-socket (path-regex #"^/")')
  })

  it('does not add Chromium-specific permissions when browser mode is disabled', () => {
    const profile = generateProfile(false)

    expect(profile).not.toContain('(sysctl-name "kern.hv_vmm_present")')
    expect(profile).not.toContain('(allow network-bind (local ip "*:*")')
    expect(profile).not.toContain(
      '(allow system-socket (socket-domain AF_UNIX))',
    )
    expect(profile).not.toContain(browserTempDir)
  })

  it('allows the Chromium sysctl and a ProcessSingleton-shaped Darwin temp socket', () => {
    const socketPath = join(
      browserTempDir,
      `srt-chromium-${process.pid}`,
      'SingletonSocket',
    )
    const script = [
      'import os, socket, subprocess',
      `path = ${JSON.stringify(socketPath)}`,
      'os.makedirs(os.path.dirname(path), mode=0o700)',
      "subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present'], check=True, capture_output=True)",
      'server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
      'server.bind(path)',
      'server.listen(1)',
      "print('BROWSER_POLICY_OK')",
      'server.close()',
      'os.unlink(path)',
      'os.rmdir(os.path.dirname(path))',
    ].join('; ')

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `python3 -c ${JSON.stringify(script)}`,
      needsNetworkRestriction: true,
      allowBrowserProcess: true,
      readConfig: undefined,
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status, result.stderr).toBe(0)
    expect(result.stdout).toContain('BROWSER_POLICY_OK')
  })
})
