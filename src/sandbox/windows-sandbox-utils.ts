import * as fs from 'node:fs'
import * as net from 'node:net'
import * as path from 'node:path'
import { spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  containsGlobCharsWin,
  expandGlobPattern,
} from './sandbox-utils.js'
// Re-export so existing tests (glob-expand.test.ts) and any
// out-of-tree caller keep their import path.
export {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
} from './sandbox-utils.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'

/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * provisions a dedicated `srt-sandbox` local user account, installs a
 * machine-wide WFP filter set keyed on that account's SID, and
 * provides an `exec` subcommand that spawns the target via a two-hop
 * launch (broker → `CreateProcessWithLogonW(runner)` → runner →
 * restricted-token child) under `srt-sandbox`. The sandboxed child
 * reaches the host only via the JS http/socks proxies, which the
 * caller passes in via `--env`.
 *
 * The separate-user account structurally closes the surrogate-spawn
 * class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
 * RunAs="Interactive User" COM): the child's token carries a
 * different user SID, so it cannot reach real-user processes, tasks
 * register under `srt-sandbox`, and the user-SID WFP filter fences
 * `srt-sandbox` egress regardless of how the child was spawned.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration. There is no marker file.
 *
 * Filesystem rules (`denyRead`/`denyWrite`/`allowRead`/`allowWrite`)
 * are enforced via additive explicit ACEs for `<sb-SID>` — see
 * {@link grantWindowsAcl} / {@link stampWindowsAcl}.
 */

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export const DEFAULT_WINDOWS_PROXY_PORT_RANGE: readonly [number, number] = [
  60080, 60089,
]

/**
 * `cannot-read` is the graceful-degrade state when BFE enumeration
 * is access-denied (it is admin-gated). The non-elevated readiness
 * check is {@link verifyWindowsWfpEgress}, not this enum.
 */
export type WindowsWfpStatus = 'absent' | 'installed' | 'cannot-read'

export interface WindowsWfpStatusResult {
  state: WindowsWfpStatus
  /** Live filter count from BFE enum; `0` on `cannot-read`. */
  filters: number
  /** `[low, high]` for the loopback PERMIT, when known. */
  portRange?: [number, number]
  /** Sandbox-user SID read from the first user-keyed filter tag. */
  userSid?: string
  /**
   * Populated only on `cannot-read` (BFE enumeration is admin-gated;
   * a non-elevated caller can't read it). The non-elevated readiness
   * check is {@link verifyWindowsWfpEgress}, not this enum.
   */
  hint?: string
}

/**
 * Result of `srt-win wfp verify` on success (exit 0, `blocked`) —
 * see {@link verifyWindowsWfpEgress}. Any other outcome throws, so
 * the tri-state is unobservable on the return path.
 */
export interface WindowsWfpVerifyResult {
  target: string
  /** Runner's stderr (carries the `BLOCKED (…)` diagnostic line). */
  stderr: string
}

/**
 * State of the `srt-sandbox` local account that `srt-win install`
 * provisions. The sandboxed child runs **as** this account.
 */
export interface WindowsSandboxUserStatus {
  /** The `srt-sandbox` local account exists. */
  provisioned: boolean
  /** `S-1-5-21-…` of `srt-sandbox`, when provisioned. */
  sid?: string
  /** The `sandbox-runtime-users` local group exists. */
  groupExists: boolean
  /** `S-1-5-21-…` of `sandbox-runtime-users`, when it exists. */
  groupSid?: string
  inBuiltinUsers: boolean
  inSandboxGroup: boolean
  hiddenFromLogon: boolean
  /**
   * The credential row is present in `state.db` and readable by
   * THIS process. False when not yet written, or when called from
   * inside the sandbox (the state-DB directory carries an explicit
   * DENY for `sandbox-runtime-users` — machine-scope DPAPI alone
   * is not a confidentiality boundary).
   */
  credPresent: boolean
  /** Setup marker schema version, when the marker row exists. */
  markerVersion?: number
  /**
   * The calling (real) user's SID — the broker's identity, surfaced
   * for diagnostics. The DENY-ACE trustee is `srt-sandbox`'s SID
   * ({@link sid}), not this. Always present.
   */
  realUserSid: string
  /**
   * SHA-1 thumbprint of the install-time CA, when one was
   * installed via `srt-win user trust-ca`. Uppercase hex.
   */
  caCertThumb?: string
  /** PEM-encoded install-time CA certificate, when present. */
  caCertPem?: string
}

/**
 * Inner shell to run `command` under, inside the sandbox. The
 * discriminant picks both the executable and the flag shape (`/c`
 * vs `-Command` vs `-c`); see {@link wrapCommandWithSandboxWindows}.
 *
 * For `kind: 'bash'`, `path` is the absolute Git Bash executable
 * (no fixed install location). It MUST originate from trusted host
 * configuration (user settings / install detection), NEVER from
 * workspace or repository content — the inner shell runs INSIDE the
 * sandbox so an unexpected path is not a sandbox-escape vector, but
 * it would still be an arbitrary-exec footgun if sourced from
 * untrusted input.
 */
export type WindowsBinShell =
  | { kind: 'cmd' }
  | { kind: 'powershell' }
  | { kind: 'pwsh' }
  | { kind: 'bash'; path: string }

/**
 * Adapter from the cross-platform `binShell?: string` surface
 * ({@link SandboxManager.wrapWithSandboxArgv}) to the Windows
 * discriminated union. Throws on any value outside the recognised
 * set — there is no silent fallback to cmd.exe.
 *
 * Uses `path.win32` explicitly so the function (and its unit test)
 * is platform-independent.
 */
export function parseWindowsBinShell(raw?: string): WindowsBinShell {
  if (raw === undefined) return { kind: 'cmd' }
  // bash/sh: path semantics — match on basename, keep the caller's
  // absolute path verbatim.
  const base = path.win32.basename(raw).toLowerCase()
  if (
    base === 'bash' ||
    base === 'bash.exe' ||
    base === 'sh' ||
    base === 'sh.exe'
  ) {
    if (!path.win32.isAbsolute(raw)) {
      throw new Error(
        `binShell bash path must be absolute (got ${JSON.stringify(raw)}); ` +
          `pass the resolved Git Bash install path`,
      )
    }
    return { kind: 'bash', path: raw }
  }
  // cmd/powershell/pwsh: token semantics — match on the FULL string,
  // not basename, so an absolute path to pwsh.exe (whose path we'd
  // otherwise discard) falls through to the explicit throw rather
  // than silently degrading to a PATH lookup.
  switch (raw.toLowerCase()) {
    case 'pwsh':
    case 'pwsh.exe':
      return { kind: 'pwsh' }
    case 'powershell':
    case 'powershell.exe':
      return { kind: 'powershell' }
    case 'cmd':
    case 'cmd.exe':
      return { kind: 'cmd' }
    default:
      throw new Error(
        `unrecognised binShell ${JSON.stringify(raw)}: expected ` +
          `'cmd' | 'powershell' | 'pwsh' or an absolute path to bash.exe/sh.exe`,
      )
  }
}

export interface WindowsSandboxParams {
  command: string
  /** JS HTTP proxy port — fed to `generateProxyEnvVars` for the env overlay. */
  httpProxyPort?: number
  /** JS SOCKS proxy port — fed to `generateProxyEnvVars` for the env overlay. */
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /**
   * `mode: 'mask'` credential env vars — sentinel values the
   * sandboxed child should see in place of the real credentials.
   * Threaded through the `--env` overlay so the runner forwards
   * them into the child's fresh profile env (the broker's own
   * environment never reaches the child, so an `env -u`-style
   * scrub is structurally moot — there is no `unsetEnvVars`).
   * Applied BEFORE the proxy assignments so the sandbox's own
   * proxy plumbing survives even if a caller masks one of those
   * names — same precedence as macOS/Linux.
   */
  setEnvVars?: Readonly<Record<string, string>>
  /**
   * Per-exec read-deny paths, applied via an additive
   * `(D;OICI;FA;;;<sb-SID>)` ACE under the `srt-win exec`
   * process's own PID and released after the child exits. Same
   * disk-first chokepoint as the session-level
   * {@link stampWindowsAcl}; same fail-closed semantics (exec
   * fails if any path cannot be stamped).
   *
   * Normalized concrete paths — globs expanded by the caller via
   * {@link expandWindowsFsDenyPaths}, the same as session-level.
   * `srt-win exec`'s `canonicalize_ace_targets` hard-fails on a
   * glob (it never expands), so a `*`/`?` reaching this field is
   * a caller bug.
   */
  denyRead?: readonly string[]
  /** Per-exec write-deny paths — see {@link denyRead}. */
  denyWrite?: readonly string[]
  /**
   * PEM-encoded CA certificate file. Same parameter macOS/Linux
   * thread to {@link generateProxyEnvVars} for the env-var trust
   * layer (`NODE_EXTRA_CA_CERTS` etc.). NOT passed to `srt-win
   * exec` — schannel-level trust under the sandbox user is set
   * separately via `srt-win user trust-ca` /
   * {@link windowsTrustCa}; per-exec only sets the env-var layer.
   *
   * Currently NOT forwarded to the child: the bundle file lives in
   * the broker's `%TEMP%`, which the `srt-sandbox` user cannot
   * read, so OpenSSL clients (msys2 curl, openssl-backed git, node,
   * python) would fail with `ACCESS_DENIED` on the bundle. The
   * schannel-level trust set via {@link windowsTrustCa} is the only
   * CA-trust path until working-tree/profile grants land.
   */
  caCertPath?: string
  /**
   * Inner shell. Defaults to `{ kind: 'cmd' }`. The child's post-`/c`
   * (or `-Command` / `-c`) content is **passthrough** — `&` chains,
   * `"…"`/`'…'` quotes exactly as written. The security boundary is at
   * the OUTER spawn (this argv is spawned with `shell:false`); the
   * inner shell runs INSIDE the sandbox so its metachars are the
   * user's tool. See {@link parseWindowsBinShell} for the
   * cross-platform string adapter.
   */
  binShell?: WindowsBinShell
}

// ────────────────────────────────────────────────────────────────────
// Binary resolution
// ────────────────────────────────────────────────────────────────────

function repoRoot(): string {
  // src/sandbox/windows-sandbox-utils.ts → repo root (compiled: dist/sandbox/…)
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '..', '..')
}

const nodeArchToDir: Record<string, string> = { x64: 'x64', arm64: 'arm64' }

/**
 * Locate `srt-win.exe`. Resolution order:
 *   1. `SRT_WIN_PATH` env var (CI sets this to the freshly-built binary).
 *   2. `<root>/vendor/srt-win/{arch}/srt-win.exe` (prebuilt — published npm
 *      package, or after `npm run build:srt-win` locally).
 *   3. `<root>/vendor/srt-win-src/target/release/srt-win.exe` (local
 *      `cargo build --release` fallback for development).
 *   4. `<root>/vendor/srt-win/target/release/srt-win.exe` (transitional:
 *      stale local build from before the srt-win-src rename).
 *
 * `<root>` is {@link repoRoot} — `__dirname/../..`, which resolves to the
 * repo root from `src/sandbox/` and `dist/sandbox/` alike, and to the
 * package root when installed under `node_modules`.
 *
 * Resolution via the optional `@anthropic-ai/sandbox-runtime-win32-*`
 * platform packages is added separately.
 *
 * @throws if none exist.
 */
export function getSrtWinPath(): string {
  const envPath = process.env.SRT_WIN_PATH
  if (envPath && fs.existsSync(envPath)) {
    return envPath
  }
  const root = repoRoot()
  const arch = nodeArchToDir[process.arch]
  const candidates: string[] = []
  if (arch) {
    candidates.push(path.join(root, 'vendor', 'srt-win', arch, 'srt-win.exe'))
  }
  candidates.push(
    path.join(
      root,
      'vendor',
      'srt-win-src',
      'target',
      'release',
      'srt-win.exe',
    ),
    // transitional: stale local build from before the srt-win-src rename
    path.join(root, 'vendor', 'srt-win', 'target', 'release', 'srt-win.exe'),
  )
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  throw new Error(
    `srt-win.exe not found. Set SRT_WIN_PATH or build with ` +
      `\`cargo build --release --manifest-path vendor/srt-win-src/Cargo.toml\`. ` +
      `Looked in: ${[envPath, ...candidates].filter(Boolean).join(', ')}`,
  )
}

// ────────────────────────────────────────────────────────────────────
// Internal: spawn helpers
// ────────────────────────────────────────────────────────────────────

interface RunResult {
  status: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
}

function runSrtWin(
  args: string[],
  timeoutMs = 15_000,
  stdin?: string,
): RunResult {
  const exe = getSrtWinPath()
  const r = spawnSync(exe, args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    ...(stdin !== undefined ? { input: stdin } : {}),
  })
  if (r.error) {
    throw new Error(`srt-win ${args[0]}: spawn failed: ${r.error.message}`)
  }
  return {
    status: r.status,
    signal: r.signal,
    stdout: (r.stdout ?? '').trim(),
    stderr: (r.stderr ?? '').trim(),
  }
}

function runSrtWinJson<T>(args: string[], opts?: { timeoutMs?: number }): T {
  const r = runSrtWin(args, opts?.timeoutMs)
  if (r.status !== 0) {
    throw new Error(
      `srt-win ${args.join(' ')} exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
  try {
    return JSON.parse(r.stdout) as T
  } catch (e) {
    throw new Error(
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
    )
  }
}

/**
 * As {@link runSrtWinJson} but parses stdout BEFORE checking the
 * exit code, so a non-zero exit with the per-path JSON intact
 * still surfaces every entry. For best-effort teardown helpers
 * (`acl restore`/`acl revoke`).
 */
function runSrtWinJsonAllowFail<T>(
  args: string[],
  timeoutMs: number,
): { ok: boolean; json: T; stderr: string } {
  const r = runSrtWin(args, timeoutMs)
  let json: T
  try {
    json = JSON.parse(r.stdout) as T
  } catch (e) {
    throw new Error(
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
    )
  }
  return { ok: r.status === 0, json, stderr: r.stderr }
}

// ────────────────────────────────────────────────────────────────────
// Status / install API
// ────────────────────────────────────────────────────────────────────

/**
 * Query the WFP filter set under the given sublayer via live BFE
 * enumeration. `installed` means at least one srt-win-tagged
 * `block-user` filter is present. Detection is **tag-based**
 * (providerData JSON); filters installed by other tooling without the
 * tag are not counted.
 *
 * BFE enumeration is admin-gated — a non-elevated caller gets
 * `state:"cannot-read"` with a `hint` (not an error). The
 * non-elevated readiness check is {@link verifyWindowsWfpEgress}.
 */
export function getWindowsWfpStatus(
  opts: { sublayerGuid?: string } = {},
): WindowsWfpStatusResult {
  const args = ['wfp', 'status']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  const raw = runSrtWinJson<{
    state: WindowsWfpStatus
    filters: number
    port_range?: [number, number]
    user_sid?: string
    hint?: string
  }>(args)
  return {
    state: raw.state,
    filters: raw.filters,
    ...(raw.port_range && { portRange: raw.port_range }),
    ...(raw.user_sid && { userSid: raw.user_sid }),
    ...(raw.hint && { hint: raw.hint }),
  }
}

/**
 * Behavioral proof that the WFP egress fence is active for the
 * sandbox user. Binds a local listener on an ephemeral loopback port
 * outside the WFP loopback-permit range, then spawns `srt-win
 * runner` as the sandbox user (via `CreateProcessWithLogonW`) to
 * attempt a direct TCP connect to it. The WFP block-user filter
 * fires at `ALE_AUTH_CONNECT` — before any packet leaves — so an
 * active fence yields WSAEACCES immediately and a missing fence lets
 * the connect through (the kernel completes the handshake against
 * the listening socket's backlog; no event-loop tick required, so
 * the synchronous `runSrtWin` is safe). Does not require elevation
 * and does not depend on any external host.
 *
 * `initialize()` calls this once per session, so a stale install
 * (sandbox user provisioned but filters since removed) fails closed
 * at session start instead of running every exec with full egress.
 *
 * @param opts.target overrides the probe target (skips the local
 *   listener bind).
 * @param opts.proxyPortRange the WFP loopback-permit range the
 *   listener must avoid. Default
 *   {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
 * @throws on any outcome other than `blocked` (exit 0).
 */
export async function verifyWindowsWfpEgress(
  opts: {
    target?: string
    proxyPortRange?: readonly [number, number]
  } = {},
): Promise<WindowsWfpVerifyResult> {
  let target = opts.target
  let server: net.Server | undefined
  if (!target) {
    // Bind ephemeral; retry if it lands inside the WFP
    // loopback-permit range (a port in-range would be PERMITted
    // even with the fence active → false `connected`).
    const [lo, hi] = opts.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE
    for (let i = 0; i < 5; i++) {
      const s = net.createServer()
      s.listen(0, '127.0.0.1')
      await once(s, 'listening')
      const p = (s.address() as net.AddressInfo).port
      if (p < lo || p > hi) {
        server = s
        target = `127.0.0.1:${p}`
        break
      }
      s.close()
    }
    if (!target) {
      throw new Error(
        `verifyWindowsWfpEgress: could not bind a loopback ` +
          `listener outside the WFP permit range [${lo},${hi}] in ` +
          `5 attempts`,
      )
    }
  }
  try {
    // 30s: first call after install may create the sandbox user's
    // profile (LOGON_WITH_PROFILE) via CreateProcessWithLogonW —
    // same budget as windowsTrustCa, plus the runner's own 2s
    // connect timeout.
    const r = runSrtWin(['wfp', 'verify', '--target', target], 30_000)
    logForDebugging(
      `[Sandbox Windows] wfp verify exit=${r.status}: ${r.stderr || r.stdout}`,
    )
    let raw: { egress_probe: string; target: string }
    try {
      raw = JSON.parse(r.stdout)
    } catch {
      // status=null → spawnSync killed the child (timeout or external
      // signal). Include signal + stderr so the CI log self-explains
      // instead of just `exited null with unparseable output ""`.
      throw new Error(
        `WFP egress fence could not be verified — \`srt-win wfp ` +
          `verify\` exited ${r.status}` +
          (r.signal ? ` (signal ${r.signal})` : '') +
          ` with unparseable output ${JSON.stringify(r.stdout)} ` +
          `(stderr: ${JSON.stringify(r.stderr)})`,
      )
    }
    if (r.status === 3) {
      throw new Error(
        `WFP egress fence is not active — direct outbound from the ` +
          `sandbox user to ${raw.target} succeeded. Re-run ` +
          `\`srt-win install\` (one UAC prompt). (${r.stderr})`,
      )
    }
    if (r.status !== 0) {
      throw new Error(
        `WFP egress fence could not be verified — probe to ` +
          `${raw.target} was '${raw.egress_probe}' (exit ` +
          `${r.status}). The fence may be absent. Re-run \`srt-win ` +
          `install\`. (${r.stderr})`,
      )
    }
    return { target: raw.target, stderr: r.stderr }
  } finally {
    server?.close()
  }
}

/**
 * Query the sandbox user account's provisioning state. Each field
 * is independently observed so a half-provisioned install (e.g.
 * user exists but credential file missing) is distinguishable.
 * Does not require elevation.
 */
export function getWindowsSandboxUserStatus(): WindowsSandboxUserStatus {
  const raw = runSrtWinJson<{
    user: {
      exists: boolean
      sid?: string
      group_exists: boolean
      group_sid?: string
      in_builtin_users: boolean
      in_sandbox_group: boolean
      hidden_from_logon: boolean
    }
    cred_present: boolean
    marker_version?: number | null
    real_user_sid: string
    ca_cert_thumb?: string | null
    ca_cert_pem?: string | null
  }>(['user', 'status'])
  return {
    provisioned: raw.user.exists,
    ...(raw.user.sid && { sid: raw.user.sid }),
    groupExists: raw.user.group_exists,
    ...(raw.user.group_sid && { groupSid: raw.user.group_sid }),
    inBuiltinUsers: raw.user.in_builtin_users,
    inSandboxGroup: raw.user.in_sandbox_group,
    hiddenFromLogon: raw.user.hidden_from_logon,
    credPresent: raw.cred_present,
    ...(typeof raw.marker_version === 'number' && {
      markerVersion: raw.marker_version,
    }),
    realUserSid: raw.real_user_sid,
    ...(raw.ca_cert_thumb && { caCertThumb: raw.ca_cert_thumb }),
    ...(raw.ca_cert_pem && { caCertPem: raw.ca_cert_pem }),
  }
}

/**
 * Read back the persistent MITM CA the sandbox was installed with
 * (via `srt-win user trust-ca` / {@link windowsTrustCa}).
 * Returns `null` when no CA was installed. The PEM is what `srt-win
 * user status` reconstructs from the DER stored in `state.db`.
 *
 * On Windows, `tlsTerminate` requires this CA to be present in the
 * sandbox user's `CurrentUser\Root` (schannel-level trust is an
 * install-time concern, not per-session); the host calls this from
 * `initialize()` to fail early with an actionable message when it
 * isn't.
 *
 * @param status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to avoid a second
 *   `srt-win user status` spawn.
 */
export function getWindowsSandboxCaCert(
  status?: WindowsSandboxUserStatus,
): { pem: string; thumb: string } | null {
  const u = status ?? getWindowsSandboxUserStatus()
  if (!u.caCertThumb || !u.caCertPem) return null
  return { pem: u.caCertPem, thumb: u.caCertThumb }
}

/**
 * Install (or replace) the MITM CA in the **sandbox user's**
 * `CurrentUser\Root` and record it in `state.db` (so
 * {@link getWindowsSandboxCaCert} surfaces its thumbprint + PEM).
 * Thin wrapper around `srt-win user trust-ca <path>`. Does NOT
 * require elevation. Persistent until {@link uninstallWindowsSandbox}
 * deletes the sandbox user's profile.
 *
 * The CA has a separate lifecycle from {@link installWindowsSandbox}
 * — install provisions the account/filters and never touches the CA;
 * call this AFTER install when `tlsTerminate` will be used.
 *
 * @throws when the sandbox user is not provisioned, the file is not a
 *   parseable X.509 certificate, or the registry write into the
 *   sandbox user's hive fails.
 */
export function windowsTrustCa(caCertPath: string): void {
  // 60s: first call may create the sandbox user's profile
  // (LOGON_WITH_PROFILE) via the one-shot CreateProcessWithLogonW.
  const r = runSrtWin(['user', 'trust-ca', caCertPath], 60_000)
  logForDebugging(
    `[Sandbox Windows] user trust-ca exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new Error(
      `srt-win user trust-ca '${caCertPath}' failed (exit ` +
        `${r.status}): ${r.stderr || r.stdout}`,
    )
  }
}

export interface WindowsInstallOptions {
  /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
  sublayerGuid?: string
  /**
   * Loopback PERMIT port range. Must match what
   * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
   * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
   */
  proxyPortRange?: readonly [number, number]
  /**
   * Replace an existing install whose configuration differs
   * (different port range under the same sublayer). Without this,
   * install refuses with "already installed with different config"
   * rather than silently overwriting.
   */
  force?: boolean
}

export interface WindowsInstallResult {
  /** Post-install WFP state. */
  wfp: WindowsWfpStatusResult
  /** Post-install sandbox-user state. */
  user: WindowsSandboxUserStatus
  /**
   * `true` if the user dismissed the UAC prompt. Not an error —
   * the install simply didn't happen. Re-run when the user is
   * ready to grant elevation.
   */
  cancelled?: true
}

/**
 * One-shot install: provisions the `srt-sandbox` user account and
 * installs the user-SID-keyed WFP filter set — all in a single
 * self-elevating process (one UAC prompt). Idempotent; re-running
 * rotates the sandbox user's password.
 *
 * Network for the calling user is **not disrupted**: the filters key
 * on the `srt-sandbox` user's SID, so the broker, services, and
 * every other principal fall through to default-permit. No logout
 * is required.
 *
 * Returns the post-call WFP + sandbox-user state. If the user
 * cancels the UAC prompt this returns `{cancelled: true, …}` rather
 * than throwing — cancellation is a user choice, not an error.
 *
 * @throws on user/WFP creation failure, or if filters already exist
 *   under `sublayerGuid` with a different port range and `force` is
 *   not set.
 */
export function installWindowsSandbox(
  opts: WindowsInstallOptions = {},
): WindowsInstallResult {
  const args = ['install']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.proxyPortRange) {
    args.push(
      '--proxy-port-range',
      `${opts.proxyPortRange[0]}-${opts.proxyPortRange[1]}`,
    )
  }
  if (opts.force) args.push('--force')

  const r = runSrtWin(args, 60_000)
  logForDebugging(
    `[Sandbox Windows] install exit=${r.status}: ${r.stderr || r.stdout}`,
  )

  // srt-win install exit-code contract:
  //   0  ok
  //   10 user cancelled UAC elevation
  //   12 WFP install failed
  //   13 already installed with different config (use --force)
  //   14 sandbox-user provisioning failed
  //   1  other error (stderr has detail)
  const out = r.stderr || r.stdout
  switch (r.status) {
    case 0:
      break
    case 10:
      return {
        wfp: getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid }),
        user: getWindowsSandboxUserStatus(),
        cancelled: true,
      }
    case 12:
      throw new Error(`srt-win install: WFP filter install failed: ${out}`)
    case 14:
      throw new Error(
        `srt-win install: sandbox user provisioning failed: ${out}`,
      )
    case 13:
      throw new Error(
        `srt-win install: filters already exist under this sublayer with ` +
          `a different port range. Pass {force: true} to replace, or ` +
          `pick a different sublayerGuid. Output: ${out}`,
      )
    default:
      throw new Error(`srt-win install failed (exit ${r.status}): ${out}`)
  }

  return {
    wfp: getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid }),
    user: getWindowsSandboxUserStatus(),
  }
}

/**
 * Remove the WFP filter set under `sublayerGuid` and the
 * `srt-sandbox` account, its credential file, and the setup marker
 * (one UAC prompt). Idempotent.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export function uninstallWindowsSandbox(
  opts: { sublayerGuid?: string; keepUser?: boolean } = {},
): {
  cancelled?: true
} {
  const args = ['uninstall']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.keepUser) args.push('--keep-user')
  const r = runSrtWin(args)
  logForDebugging(
    `[Sandbox Windows] uninstall exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status === 10) return { cancelled: true }
  if (r.status !== 0) {
    throw new Error(
      `srt-win uninstall failed (exit ${r.status}): ${r.stderr || r.stdout}`,
    )
  }
  return {}
}

/**
 * Expand glob patterns in `patterns` to concrete paths via the
 * single platform-aware {@link normalizePathForSandbox} chokepoint
 * (Linux/macOS parity: point-in-time expansion at session
 * initialize, not per-exec). Non-glob paths are normalized and
 * returned 1:1. Missing paths are dropped (statSync probe).
 * Directory targets are accepted — the additive sandbox-user ACE
 * carries `(OI)(CI)` so it covers the subtree.
 */
export function expandWindowsFsDenyPaths(
  patterns: readonly string[],
): string[] {
  const out = new Set<string>()
  for (const raw of patterns) {
    const norm = normalizePathForSandbox(raw)
    const candidates = containsGlobCharsWin(norm)
      ? expandGlobPattern(norm, { caseInsensitive: true })
      : [norm]
    for (const c of candidates) {
      const st = fs.statSync(c, { throwIfNoEntry: false })
      if (!st) continue
      out.add(c)
    }
  }
  return [...out]
}

export interface WindowsAclStampOptions {
  /** Paths the sandboxed child must not read. */
  denyRead: readonly string[]
  /** Paths the sandboxed child must not write (read stays allowed). */
  denyWrite: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
}

/**
 * Apply the file-deny ACE set for one host session: an additive
 * `(D;OICI;mask;;;<sb-SID>)` on the target plus a
 * `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent — no
 * PROTECTED rewrite, no SD snapshot. Idempotent and refcounted via
 * srt-win's `working_aces` table.
 *
 * Inputs are passed verbatim to `srt-win` (which canonicalizes and
 * rejects globs). Callers that accept globs should pre-expand via
 * {@link expandWindowsFsDenyPaths}.
 *
 * @throws on exit ≠ 0 — including exit 2 (one or more inputs
 *   skipped). srt-win stamps the resolvable inputs before exiting
 *   2, so on throw the caller should call {@link restoreWindowsAcl}
 *   to release whatever WAS stamped.
 */
export function stampWindowsAcl(opts: WindowsAclStampOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({
    denyRead: opts.denyRead,
    denyWrite: opts.denyWrite,
  })
  const r = runSrtWin(
    [
      'acl',
      'stamp',
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    60_000,
    stdin,
  )
  logForDebugging(
    `[Sandbox Windows] acl stamp exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new Error(
      `srt-win acl stamp exited ${r.status} ` +
        (r.status === 2 ? '(partial — some inputs skipped)' : '(failed)') +
        `: ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * Per-path outcome from `srt-win acl restore --json` /
 * `revoke --json`. The status set is intentionally loose: the
 * pre-/post- same-user-removal `srt-win` builds emit different
 * vocabularies for `restore` (`restored`/`leftChanged`/… vs
 * `revoked`/`stillHeld`/…). Callers (`reset()`) only log these,
 * so the union is whatever the binary on PATH says.
 */
export interface WindowsAclAceOutcome {
  path: string
  status: string
}

/**
 * Release this holder's deny ACEs and remove the sandbox-user ACE
 * on any path whose refcount falls to zero. Best-effort (does not
 * throw on per-path anomalies); returns per-path outcomes for the
 * caller to surface. Returns `undefined` only when `srt-win`
 * itself failed (no JSON to parse).
 */
export function restoreWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  // Don't let a teardown helper throw — the caller's reset() must
  // complete. runSrtWinJsonAllowFail parses stdout before checking
  // the exit code, so a non-zero exit with the per-path JSON intact
  // still surfaces every entry to reset()'s loop. Only spawn-fail
  // / unparseable output throws → log and return undefined.
  try {
    const r = runSrtWinJsonAllowFail<
      | WindowsAclAceOutcome[]
      | { paths?: WindowsAclAceOutcome[]; parents?: WindowsAclAceOutcome[] }
    >(
      [
        'acl',
        'restore',
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      60_000,
    )
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl restore exited non-zero (per-path ` +
          `outcomes preserved): ${r.stderr}`,
        { level: 'error' },
      )
    }
    // Pre- same-user-removal builds emit `{paths, parents}`; post-
    // emit a flat array. Flatten either so reset()'s logging loop
    // is shape-agnostic across the transition.
    return Array.isArray(r.json)
      ? r.json
      : [...(r.json.paths ?? []), ...(r.json.parents ?? [])]
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl restore: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

export interface WindowsAclGrantOptions {
  /** Paths to grant `MODIFY_NO_FDC` on (the working tree, `allowWrite`). */
  write: readonly string[]
  /** Paths to grant `FILE_GENERIC_READ|EXECUTE` on (`allowRead`). */
  read: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
}

/**
 * Apply per-session additive `(OI)(CI)` ALLOW ACEs for the sandbox
 * user on each path. The sandbox user has no inherent rights on
 * real-user-owned files; this is what makes the working tree (and
 * explicit `allowRead`/`allowWrite` paths) reachable from the
 * child. Idempotent and refcounted via srt-win's `working_aces`
 * table.
 *
 * @throws on exit ≠ 0. On throw the caller should call
 *   {@link revokeWindowsAcl} to release whatever WAS granted.
 */
export function grantWindowsAcl(opts: WindowsAclGrantOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({ read: opts.read, write: opts.write })
  const r = runSrtWin(
    [
      'acl',
      'grant',
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    60_000,
    stdin,
  )
  logForDebugging(
    `[Sandbox Windows] acl grant exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new Error(
      `srt-win acl grant exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 */
export function revokeWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  try {
    const r = runSrtWinJsonAllowFail<WindowsAclAceOutcome[]>(
      [
        'acl',
        'revoke',
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      60_000,
    )
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl revoke exited non-zero: ${r.stderr}`,
        { level: 'error' },
      )
    }
    return r.json
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl revoke: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

// ────────────────────────────────────────────────────────────────────
// Wrap
// ────────────────────────────────────────────────────────────────────

/**
 * Build the spawn descriptor for running `command` inside the Windows
 * sandbox: an `argv` array plus the `env` to spawn it with.
 *
 * Caller MUST spawn the result with `{shell: false}` — that is the
 * security boundary that keeps untrusted bytes off the host's shell
 * (the inner `cmd.exe /c` runs INSIDE the sandbox; see
 * `vendor/srt-win-src/src/launch.rs` `build_cmdline` for the passthrough
 * rationale) — AND with the returned `env`.
 *
 * Proxy configuration is single-sourced by {@link generateProxyEnvVars}
 * (the same canonical builder used on macOS/Linux). `srt-win exec`
 * takes no `--http-proxy` / `--socks-proxy` flags and synthesizes no
 * proxy env. The two-hop runner starts with the SANDBOX user's
 * profile env (`USERPROFILE`/`TEMP` isolated) and overlays exactly
 * what we pass as `--env` — built here from the broker's `PATH` plus
 * the generated proxy set.
 */
export function wrapCommandWithSandboxWindows(p: WindowsSandboxParams): {
  argv: string[]
  env: NodeJS.ProcessEnv
} {
  const exe = getSrtWinPath()
  // Generated proxy + CA-trust env. Single-sourced here so the
  // same object feeds (a) the spawn env merge below and (b) the
  // explicit `--env` overlay for the runner.
  //
  // The CA-bundle path is OMITTED: it points into the broker's
  // `%TEMP%\srt-sandbox-…`, which the `srt-sandbox` user cannot
  // read — OpenSSL-backed clients (msys2 curl, openssl-backed git,
  // node, python) would fail to open it (curl exit 77 etc.).
  // Schannel-level trust comes from the registry write `srt-win user
  // trust-ca` did at install time; the env-var bundle layer lands
  // with the working-tree/profile-grant work.
  if (p.caCertPath !== undefined) {
    logForDebugging(
      `[Sandbox Windows] caCertPath '${p.caCertPath}' not forwarded ` +
        `(broker %TEMP% is unreadable by srt-sandbox); schannel ` +
        `trust via 'srt-win user trust-ca' is the only CA-trust ` +
        `path for the two-hop launch`,
    )
  }
  const generated = envListToObject(
    generateProxyEnvVars(
      p.httpProxyPort,
      p.socksProxyPort,
      undefined, // caCertPath — see above
      p.proxyAuthToken,
    ),
  )
  // TMPDIR is a POSIX path meant for the macOS/Linux FS sandbox — it
  // serves no purpose on Windows and breaks msys2 tools (mktemp etc.).
  delete generated.TMPDIR

  const argv: string[] = [exe, 'exec']
  // Required while srt-win still has LaunchMode::SameUser as
  // default; dropped in the Rust same-user-removal PR. `--env`
  // on main carries `requires = "as_sandbox_user"`, so this
  // must precede the overlay below.
  argv.push('--as-sandbox-user')
  for (const d of p.denyRead ?? []) argv.push('--deny-read', d)
  for (const d of p.denyWrite ?? []) argv.push('--deny-write', d)
  // The two-hop runner starts with the SANDBOX user's profile env
  // (USERPROFILE/TEMP isolated) and overlays exactly what we pass as
  // `--env`. The broker does NOT enumerate its own env — the overlay
  // is built here from the broker's PATH, the mode:'mask' sentinel
  // set, and the generated proxy set. Sentinels precede `generated`
  // so a caller masking e.g. `HTTPS_PROXY` cannot break the
  // sandbox's own proxy plumbing — same precedence as the
  // macOS/Linux `env -u … VAR=… sandbox-exec` order.
  const overlay: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    PATHEXT: process.env.PATHEXT,
    ...(p.setEnvVars ?? {}),
    ...generated,
  }
  for (const [k, v] of Object.entries(overlay)) {
    if (v !== undefined) argv.push('--env', `${k}=${v}`)
  }
  argv.push('--')

  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const sh = p.binShell ?? { kind: 'cmd' }
  switch (sh.kind) {
    case 'bash':
      // Git Bash: invoke the caller-supplied path directly with
      // `-c <command>`. `command` is a fully-assembled bash command
      // string with its own internal quoting; srt-win's `build_cmdline`
      // takes the generic non-cmd branch and MSVCRT-quotes it as a
      // SINGLE argv element, so bash receives it intact as argv[2].
      argv.push(sh.path, '-c', p.command)
      break
    case 'pwsh':
      argv.push('pwsh.exe', '-NoProfile', '-Command', p.command)
      break
    case 'powershell':
      argv.push(
        path.join(
          systemRoot,
          'System32',
          'WindowsPowerShell',
          'v1.0',
          'powershell.exe',
        ),
        '-NoProfile',
        '-Command',
        p.command,
      )
      break
    case 'cmd':
      // cmd /d (no AutoRun) /s (strip first+last quote of post-/c by
      // position) /c (run-then-exit). The `command` string lands as a
      // single argv element; srt-win's build_cmdline wraps it in one
      // outer "…" pair for /s to consume. See launch.rs.
      argv.push(
        path.join(systemRoot, 'System32', 'cmd.exe'),
        '/d',
        '/s',
        '/c',
        p.command,
      )
      break
  }

  // CreateProcessW's lpCommandLine is capped at 32 767 WCHARs.
  // Node's `shell:false` spawn builds it by MSVCRT-quoting each
  // argv element and joining with spaces; ~30 000 leaves headroom
  // for the quote overhead the estimate doesn't model.
  const cmdlineEstimate = argv.reduce((n, a) => n + a.length + 3, 0)
  if (cmdlineEstimate > 30_000) {
    throw new Error(
      `Windows sandbox argv is ~${cmdlineEstimate} chars ` +
        `(CreateProcessW limit is 32 767). Shorten the command, ` +
        `or move broad globs to session-level filesystem.denyRead.`,
    )
  }

  // The two-hop runner starts with a FRESH `srt-sandbox` profile
  // env (`lpEnvironment = NULL` + `LOGON_WITH_PROFILE`), so the
  // broker process's environment never reaches the child. The
  // returned `env` is the spawn env for the broker (srt-win)
  // process only; the child sees the `--env` overlay built into
  // `argv` above (PATH/PATHEXT + mode:'mask' sentinels + proxy).
  const env: NodeJS.ProcessEnv = { ...process.env, ...generated }
  return { argv, env }
}

/**
 * Parse a list of `KEY=VALUE` strings (as produced by
 * {@link generateProxyEnvVars}) into an object. Splits on the FIRST
 * `=` only, so values containing `=` survive intact.
 */
function envListToObject(list: string[]): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {}
  for (const entry of list) {
    const eq = entry.indexOf('=')
    if (eq === -1) continue
    out[entry.slice(0, eq)] = entry.slice(eq + 1)
  }
  return out
}

// ────────────────────────────────────────────────────────────────────
// Dependency / readiness check
// ────────────────────────────────────────────────────────────────────

/**
 * Install instructions, surfaced verbatim in error messages.
 */
export function windowsInstallInstructions(
  sublayerGuid: string | undefined,
): string {
  const sl = sublayerGuid ? ` --sublayer-guid ${sublayerGuid}` : ''
  return (
    `Windows sandbox needs a one-time install (one UAC prompt):\n` +
    `  npx sandbox-runtime windows-install\n` +
    `  — or call installWindowsSandbox(), or run ` +
    `\`srt-win.exe install${sl}\` directly.\n` +
    `No logout is needed: the WFP filter keys on the dedicated ` +
    `\`srt-sandbox\` user's SID, so your network is unaffected.`
  )
}

/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 */
export function checkWindowsDependencies(
  sublayerGuid?: string,
): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []

  // 1. Binary present.
  let exe: string
  try {
    exe = getSrtWinPath()
  } catch (e) {
    return { errors: [(e as Error).message], warnings }
  }
  logForDebugging(`[Sandbox Windows] using srt-win at ${exe}`)

  // 2. Sandbox user provisioned + credential readable.
  let us: WindowsSandboxUserStatus
  try {
    us = getWindowsSandboxUserStatus()
  } catch (e) {
    errors.push(`srt-win user status failed: ${(e as Error).message}`)
    return { errors, warnings }
  }
  if (!us.provisioned || !us.credPresent) {
    errors.push(
      `Sandbox user is not provisioned (user=${us.provisioned}, ` +
        `cred=${us.credPresent}). ` +
        windowsInstallInstructions(sublayerGuid),
    )
  }

  // 3. WFP filters installed under the sublayer. BFE enumeration is
  // admin-gated; `cannot-read` is informational only — the
  // BEHAVIORAL check (`verifyWindowsWfpEgress`) runs at
  // `initialize()` and is what actually fails closed.
  let ws: WindowsWfpStatusResult
  try {
    ws = getWindowsWfpStatus({ sublayerGuid })
  } catch (e) {
    errors.push(`srt-win wfp status failed: ${(e as Error).message}`)
    return { errors, warnings }
  }
  if (ws.state === 'cannot-read') {
    logForDebugging(
      `[Sandbox Windows] wfp status cannot-read (non-elevated): ${ws.hint}`,
    )
  } else if (ws.state !== 'installed') {
    // 'absent'. If the user is also not-provisioned, the user-state
    // error above already gave the right instruction; don't repeat.
    if (us.provisioned && us.credPresent) {
      errors.push(
        `WFP filters not installed under sublayer ` +
          `${sublayerGuid ?? '(default)'}. ` +
          windowsInstallInstructions(sublayerGuid),
      )
    }
  } else if (ws.portRange) {
    logForDebugging(
      `[Sandbox Windows] WFP installed: ${ws.filters} filters, ` +
        `proxy port range ${ws.portRange[0]}-${ws.portRange[1]}`,
    )
  }

  return { errors, warnings }
}
