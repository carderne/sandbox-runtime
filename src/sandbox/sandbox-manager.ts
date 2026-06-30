import { createHttpProxyServer } from './http-proxy.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { createMuxProxyServer, type MuxProxyServer } from './mux-proxy.js'
import { listenInRange } from './listen-in-range.js'
import { SentinelRegistry } from './credential-sentinel.js'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
} from './credential-mask-files.js'
import { createMitmCA, disposeMitmCA, type MitmCA } from './mitm-ca.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { getPlatform, getWslVersion } from '../utils/platform.js'
import * as fs from 'fs'
import { randomBytes, X509Certificate } from 'node:crypto'
import type {
  CredentialsConfig,
  SandboxRuntimeConfig,
  SeccompConfig,
} from './sandbox-config.js'
import type {
  SandboxAskCallback,
  CredentialRestrictionConfig,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from './sandbox-schemas.js'
import {
  wrapCommandWithSandboxLinux,
  initializeLinuxNetworkBridge,
  type LinuxNetworkBridgeContext,
  checkLinuxDependencies,
  type SandboxDependencyCheck,
  cleanupBwrapMountPoints,
} from './linux-sandbox-utils.js'
import {
  wrapCommandWithSandboxMacOS,
  startMacOSSandboxLogMonitor,
} from './macos-sandbox-utils.js'
import {
  checkWindowsDependencies,
  wrapCommandWithSandboxWindows,
  parseWindowsBinShell,
  expandWindowsFsDenyPaths,
  stampWindowsAcl,
  restoreWindowsAcl,
  grantWindowsAcl,
  revokeWindowsAcl,
  getWindowsSandboxUserStatus,
  getWindowsSandboxCaCert,
  verifyWindowsWfpEgress,
  WINDOWS_ACL_PATH_OK,
  WINDOWS_ACL_PARENT_OK,
  DEFAULT_WINDOWS_GROUP_NAME,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  type WindowsGroupRef,
} from './windows-sandbox-utils.js'
import {
  getDefaultWritePaths,
  containsGlobChars,
  removeTrailingGlobSuffix,
  expandGlobPattern,
} from './sandbox-utils.js'
import { SandboxViolationStore } from './sandbox-violation-store.js'
import type { MutateForwardedHeaders } from './request-filter.js'
import {
  canonicalizeHost,
  isValidHost,
  redactUrl,
  resolveParentProxy,
} from './parent-proxy.js'
import { matchesDomainPattern } from './domain-pattern.js'
import type { ChildProcess } from 'node:child_process'
import type { ResolvedParentProxy } from './parent-proxy.js'
import { EOL } from 'node:os'

interface HostNetworkManagerContext {
  httpProxyPort: number
  socksProxyPort: number
  linuxBridge: LinuxNetworkBridgeContext | undefined
}

// ============================================================================
// Private Module State
// ============================================================================

let config: SandboxRuntimeConfig | undefined
let httpProxyServer: ReturnType<typeof createHttpProxyServer> | undefined
let socksProxyServer: SocksProxyWrapper | undefined
let muxProxyServer: MuxProxyServer | undefined
let managerContext: HostNetworkManagerContext | undefined
let initializationPromise: Promise<HostNetworkManagerContext> | undefined
let cleanupRegistered = false
let logMonitorShutdown: (() => void) | undefined
let parentProxy: ResolvedParentProxy | undefined
let mitmCA: MitmCA | undefined
// Per-session proxy auth token. Generated at proxy start, exported only into
// the sandbox child env, checked on every CONNECT/request — so a host process
// dialing 127.0.0.1:<proxyPort> can't reach the filter callback.
let proxyAuthToken: string | undefined
// Windows: the resolved access set that was actually applied at
// initialize(). `undefined` means no stamp/grant was applied
// (gates passing `--holder-pid` to exec — which engages the
// per-exec dir/file fence — and running `acl restore`/`acl revoke`
// at reset()).
let windowsFsStampedSet:
  | ReturnType<typeof computeWindowsFsAccessSet>
  | undefined
// The group reference that was passed to `srt-win acl stamp`.
// reset() restores against THIS, not the current config — a
// group change between stamp and restore would otherwise
// target the wrong group's broker DACL.
let windowsFsStampedGroup: WindowsGroupRef | undefined
// SIDs captured at initialize() under `asSandboxUser`: the sandbox
// user (revoke target) and the real user (stamp trustee). reset()
// uses these so a config change between init and reset can't strand
// state under a different SID.
let windowsFsSbUserSids: { sb: string } | undefined
// The RAW config inputs that produced `windowsFsStampedSet`.
// updateConfig() compares these (not the resolved set) so it never
// re-expands globs — see `sameWindowsStampSet`.
let windowsFsRawInputs: ReturnType<typeof rawWindowsFsInputs> | undefined
// `verifyWindowsWfpEgress()` is once per session (it spawns a
// CreateProcessWithLogonW runner; first call may create the sandbox
// user's profile). updateConfig()'s reset+reinit on FS-config
// changes shouldn't re-run it — the WFP fence isn't config-scoped.
// Cleared by reset() so tests that explicitly reset re-verify.
let windowsWfpVerified = false
const sandboxViolationStore = new SandboxViolationStore()
// Per-session sentinel↔real-value map for masked credentials. Lives only in
// process memory; never written to disk or logged. Cleared on reset().
const sentinelRegistry = new SentinelRegistry()
// Temp dir holding the sentinel-content fake files for masked credential
// files. Created lazily on first masked file; removed on reset().
const maskedFileStore = new MaskedFileStore()

// ============================================================================
// Private Helper Functions (not exported)
// ============================================================================

function registerCleanup(): void {
  if (cleanupRegistered) {
    return
  }
  const cleanupHandler = () =>
    reset().catch(e => {
      logForDebugging(`Cleanup failed in registerCleanup ${e}`, {
        level: 'error',
      })
    })
  process.once('exit', cleanupHandler)
  process.once('SIGINT', cleanupHandler)
  process.once('SIGTERM', cleanupHandler)
  cleanupRegistered = true
}

async function filterNetworkRequest(
  port: number,
  host: string,
  sandboxAskCallback?: SandboxAskCallback,
): Promise<boolean> {
  if (!config) {
    logForDebugging('No config available, denying network request')
    return false
  }

  // Reject hosts containing control characters before pattern matching.
  // `matchesDomainPattern` uses string suffix matching which is trivially
  // fooled by e.g. `evil.com\x00.allowed.com` — the null byte passes
  // `.endsWith()` but truncates at the libc DNS layer. The SOCKS path is the
  // main exposure (DOMAINNAME is unvalidated bytes); HTTP is protected by
  // llhttp/URL parsing, but we check here for defence in depth.
  if (!isValidHost(host)) {
    logForDebugging(`Denying malformed host: ${JSON.stringify(host)}:${port}`, {
      level: 'error',
    })
    return false
  }

  // Canonicalize so string comparisons match what getaddrinfo() will dial.
  // Without this, inet_aton shorthand like `2852039166` (= 169.254.169.254)
  // or `127.1` slips past a denylist entry for the dotted-decimal form.
  const canonicalHost = canonicalizeHost(host) ?? host

  // Check denied domains first
  for (const deniedDomain of config.network.deniedDomains) {
    if (matchesDomainPattern(canonicalHost, deniedDomain)) {
      logForDebugging(`Denied by config rule: ${host}:${port}`)
      return false
    }
  }

  // Check allowed domains
  for (const allowedDomain of config.network.allowedDomains) {
    if (matchesDomainPattern(canonicalHost, allowedDomain)) {
      logForDebugging(`Allowed by config rule: ${host}:${port}`)
      return true
    }
  }

  // No matching rules - ask user or deny. strictAllowlist makes the
  // allowlist deterministic enforcement: never fall through to the callback.
  if (!sandboxAskCallback || config.network.strictAllowlist) {
    logForDebugging(`No matching config rule, denying: ${host}:${port}`)
    return false
  }

  logForDebugging(`No matching config rule, asking user: ${host}:${port}`)
  try {
    const userAllowed = await sandboxAskCallback({ host, port })
    if (userAllowed) {
      logForDebugging(`User allowed: ${host}:${port}`)
      return true
    } else {
      logForDebugging(`User denied: ${host}:${port}`)
      return false
    }
  } catch (error) {
    logForDebugging(`Error in permission callback: ${error}`, {
      level: 'error',
    })
    return false
  }
}

/**
 * Get the MITM proxy socket path for a given host, if configured.
 * Returns the socket path if the host matches any MITM domain pattern,
 * otherwise returns undefined.
 */
/**
 * Build the header-mutation callback that substitutes sentinel→real for
 * masked credentials. Returns undefined when no `credentials` block is
 * configured — wiring the seam at all is unnecessary then.
 *
 * Per-host gating happens inside the registry: each sentinel carries its
 * own injectHosts list and substitutes independently, so credential A's
 * sentinel cannot be laundered through credential B's allowed host. The
 * returned closure does not log header values; the registry holds the only
 * copy of the real value.
 */
function buildCredentialInjector(): MutateForwardedHeaders | undefined {
  if (!config?.credentials) return undefined
  return (headers, destHost) => {
    sentinelRegistry.substituteInHeaders(
      headers,
      destHost,
      matchesDomainPattern,
    )
  }
}

function getMitmSocketPath(host: string): string | undefined {
  if (!config?.network.mitmProxy) {
    return undefined
  }

  const { socketPath, domains } = config.network.mitmProxy

  for (const pattern of domains) {
    if (matchesDomainPattern(host, pattern)) {
      logForDebugging(`Host ${host} matches MITM pattern ${pattern}`)
      return socketPath
    }
  }

  return undefined
}

/**
 * Per-host TLS-termination opt-out from network.tlsTerminate.excludeDomains.
 * Only consulted by the HTTP proxy when tlsTerminate is enabled; exempted
 * hosts fall back to the opaque CONNECT tunnel (still allowlist-filtered),
 * so mTLS / cert-pinning clients can complete their own handshake.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) — otherwise a spelling the allowlist accepts after
 * canonicalization (`127.1`, a trailing-dot FQDN) would dodge the exclusion
 * and get terminated anyway.
 */
function shouldTerminateTLSForHost(host: string): boolean {
  const excludeDomains = config?.network.tlsTerminate?.excludeDomains
  if (!excludeDomains?.length) return true
  const canonicalHost = canonicalizeHost(host) ?? host
  for (const pattern of excludeDomains) {
    if (!matchesDomainPattern(canonicalHost, pattern)) continue
    logForDebugging(
      `Host ${host} matches tlsTerminate.excludeDomains pattern ${pattern}; skipping TLS termination`,
    )
    // Masked-credential substitution only happens on the terminated path,
    // so a credential whose injectHosts cover this host can never be
    // injected here — the upstream gets the placeholder. Config validation
    // rejects the fully-contradictory spellings; this flags the partial
    // ones (e.g. default injectHosts = allowedDomains) at the moment they
    // actually bite.
    const masked = sentinelRegistry.namesInjectableAt(
      canonicalHost,
      matchesDomainPattern,
    )
    if (masked.length > 0) {
      logForDebugging(
        `tlsTerminate.excludeDomains: masked credential(s) ${masked.join(', ')} ` +
          `are configured for injection at ${host}, but its connections are ` +
          `not terminated, so the upstream will receive the placeholder`,
        { level: 'error' },
      )
    }
    return false
  }
  return true
}

async function startMuxProxyServer(
  sandboxAskCallback: SandboxAskCallback | undefined,
  portRange: readonly [number, number] | undefined,
): Promise<number> {
  const injectCredentials = buildCredentialInjector()
  httpProxyServer = createHttpProxyServer({
    filter: (port: number, host: string) =>
      filterNetworkRequest(port, host, sandboxAskCallback),
    getMitmSocketPath,
    mitmCA,
    shouldTerminateTLS: shouldTerminateTLSForHost,
    filterRequest: config?.network.filterRequest,
    // TLS-terminated path always gets the injector; the plain-HTTP path
    // only when explicitly opted in. Without the opt-in, a sentinel sent
    // over plain HTTP reaches the upstream unchanged (fails closed).
    mutateHeaders: injectCredentials,
    mutateHeadersPlaintext: config?.credentials?.allowPlaintextInject
      ? injectCredentials
      : undefined,
    parentProxy,
    proxyAuthToken,
  })

  socksProxyServer = createSocksProxyServer({
    filter: (port: number, host: string) =>
      filterNetworkRequest(port, host, sandboxAskCallback),
    parentProxy,
    proxyAuthToken,
  })

  muxProxyServer = createMuxProxyServer({
    httpServer: httpProxyServer,
    handleSocksConnection: s => socksProxyServer!.handleConnection(s),
    httpBackendPortRange: portRange,
  })

  const mux = muxProxyServer
  // Backend first so the front-end never accepts a connection that would
  // dispatch to an unbound backend. On Windows the backend's port is
  // excluded when binding the front-end in the same WFP range.
  const backendPort = await mux.listenHttpBackend()
  await listenInRange(
    mux.server,
    p => mux.server.listen(p, '127.0.0.1'),
    portRange,
    backendPort !== undefined ? new Set([backendPort]) : new Set(),
  )
  const muxPort = mux.getPort()
  if (muxPort === undefined) {
    throw new Error('Failed to get mux proxy server port')
  }
  mux.unref()
  logForDebugging(`Mux proxy (HTTP+SOCKS) listening on localhost:${muxPort}`)
  return muxPort
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

async function initialize(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback?: SandboxAskCallback,
  enableLogMonitor = false,
): Promise<void> {
  // Return if already initializing
  if (initializationPromise) {
    await initializationPromise
    return
  }

  // Store config for use by other functions
  config = runtimeConfig

  // Resolve parent/upstream proxy from config or HTTP_PROXY env before we
  // start our own listeners (which will later shadow those vars in the child).
  parentProxy = resolveParentProxy(runtimeConfig.network.parentProxy)
  if (parentProxy) {
    logForDebugging(
      `Parent proxy configured: http=${redactUrl(parentProxy.httpUrl)} ` +
        `https=${redactUrl(parentProxy.httpsUrl)}`,
    )
  }

  // Load TLS-termination CA if configured. Throws on unreadable/non-PEM —
  // tlsTerminate is explicit opt-in, so a bad config is a hard error.
  if (runtimeConfig.network.tlsTerminate && runtimeConfig.network.mitmProxy) {
    throw new Error(
      'network.tlsTerminate and network.mitmProxy are mutually exclusive',
    )
  }
  mitmCA = runtimeConfig.network.tlsTerminate
    ? createMitmCA(runtimeConfig.network.tlsTerminate)
    : undefined

  // Check dependencies
  const deps = checkDependencies()
  if (deps.errors.length > 0) {
    throw new Error(
      `Sandbox dependencies not available: ${deps.errors.join(', ')}`,
    )
  }

  // Start log monitor for macOS if enabled
  if (enableLogMonitor && getPlatform() === 'macos') {
    logMonitorShutdown = startMacOSSandboxLogMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      config.ignoreViolations,
    )
    logForDebugging('Started macOS sandbox log monitor')
  }

  // Register cleanup handlers first time
  registerCleanup()

  // Windows: apply the file-deny stamp set BEFORE any sandboxed
  // child can be spawned. Synchronous (spawnSync) and independent
  // of the network proxies, so do it here rather than inside the
  // initializationPromise. Throws on any failure (including a
  // partial — exit 2 means at least one input was skipped):
  // fail-closed at session start.
  if (getPlatform() === 'windows') {
    // One outer catch clears `config` so any readiness throw
    // leaves the manager uninitialised (the FS-stamp block below
    // has its own catch — it must restore on partial failure).
    try {
      // Separate-user opt-in: refuse early when the config asks
      // for it but the account isn't provisioned. Doing this at
      // initialize() (not wrap-time) means the host gets a single
      // actionable error before any per-exec work happens, instead
      // of exit-15 on every command.
      if (runtimeConfig.windows?.asSandboxUser) {
        const u = getWindowsSandboxUserStatus()
        if (!u.provisioned || !u.credPresent) {
          throw new Error(
            `windows.asSandboxUser is set but the sandbox user is ` +
              `not provisioned (user=${u.provisioned}, cred=` +
              `${u.credPresent}). Run \`npx sandbox-runtime ` +
              `windows-install\` (one UAC prompt) to provision it.`,
          )
        }
        // Behavioral proof the WFP egress fence is active for the
        // sandbox user — BFE enumeration (`wfp status`) is
        // admin-gated, so this is the non-elevated readiness check.
        // Fails closed: a stale install (user provisioned but
        // filters since removed) throws here instead of running
        // every exec with full egress. After the user-status check
        // so the not-provisioned message is the actionable one.
        // Once per session — the fence isn't config-scoped.
        if (!windowsWfpVerified) {
          await verifyWindowsWfpEgress({
            proxyPortRange: runtimeConfig.windows?.proxyPortRange,
          })
          windowsWfpVerified = true
        }
        // schannel-level trust under the sandbox user is
        // install-time (cert lifecycle = sandbox-user lifecycle),
        // not per-session. The env-var trust layer covers OpenSSL
        // clients regardless, but System32 curl / IWR / .NET /
        // default-backend git only trust what's in the sandbox
        // user's `CurrentUser\Root` — which `srt-win exec` does
        // not (and must not) write. Gate only on `asSandboxUser`:
        // the same-user path lands on the REAL user's Root, which
        // is out of scope (env-var trust only). Compare
        // thumbprints so a stale install-time CA doesn't pass the
        // gate while schannel rejects the session's proxy-minted
        // leaves.
        if (runtimeConfig.network.tlsTerminate && mitmCA) {
          const installed = getWindowsSandboxCaCert(u)
          const sessionThumb = new X509Certificate(mitmCA.certPem).fingerprint
            .replace(/:/g, '')
            .toUpperCase()
          if (!installed) {
            throw new Error(
              `tlsTerminate with windows.asSandboxUser requires the ` +
                `sandbox to be installed with this CA (thumb=` +
                `${sessionThumb}): run \`srt-win user trust-ca ` +
                `${mitmCA.certPath}\`. Per-exec installs into the ` +
                `sandbox user's Root store are not supported.`,
            )
          }
          if (installed.thumb !== sessionThumb) {
            throw new Error(
              `tlsTerminate with windows.asSandboxUser: the sandbox's ` +
                `installed CA (thumb=${installed.thumb}) doesn't ` +
                `match this session's CA (thumb=${sessionThumb}). ` +
                `Run \`srt-win user trust-ca ${mitmCA.certPath}\` ` +
                `to update it.`,
            )
          }
        }
      }
    } catch (e) {
      config = undefined
      throw e
    }
    try {
      const acc = computeWindowsFsAccessSet(runtimeConfig)
      const group = getWindowsGroupRef()
      const asSbUser = runtimeConfig.windows?.asSandboxUser ?? false
      // Under separate-user, grant FIRST so the sandbox user has
      // working-tree access by the time the stamp runs (the stamp
      // PROTECTEDs paths inside it). The two are independent
      // refcounted state-DB sets keyed on the same holder PID.
      let sids: { sb: string } | undefined
      if (asSbUser) {
        const u = getWindowsSandboxUserStatus()
        if (!u.sid) {
          throw new Error(
            'windows.asSandboxUser: sandbox user SID missing from ' +
              '`srt-win user status` (provisioned but in an inconsistent state)',
          )
        }
        sids = { sb: u.sid }
        // Record module-level state BEFORE the first acl call so the
        // catch's best-effort revoke/restore can address whatever
        // partially landed.
        windowsFsSbUserSids = sids
        if (acc.grantRead.length > 0 || acc.grantWrite.length > 0) {
          grantWindowsAcl({
            group,
            sandboxUserSid: sids.sb,
            read: acc.grantRead,
            write: acc.grantWrite,
          })
        }
      }
      if (acc.denyRead.length > 0 || acc.denyWrite.length > 0) {
        stampWindowsAcl({
          group,
          denyRead: acc.denyRead,
          denyWrite: acc.denyWrite,
          ...(asSbUser && sids ? { sandboxUserSid: sids.sb } : {}),
        })
      }
      // Only record when something was actually applied — gates
      // passing `--holder-pid` to exec (per-exec deny self-registers
      // under its own PID when there is no session-level holder) and
      // running revoke/restore at reset(). Recorded AFTER success —
      // the catch below clears `config`, and a non-undefined
      // stampedSet would leave reset()/updateConfig() seeing state
      // that never landed.
      const anyApplied =
        acc.grantRead.length > 0 ||
        acc.grantWrite.length > 0 ||
        acc.denyRead.length > 0 ||
        acc.denyWrite.length > 0
      if (anyApplied) {
        windowsFsStampedSet = acc
        windowsFsStampedGroup = group
        logForDebugging(
          `[Sandbox Windows] fs applied: ` +
            `${acc.grantWrite.length} grantWrite, ` +
            `${acc.grantRead.length} grantRead, ` +
            `${acc.denyRead.length} denyRead, ` +
            `${acc.denyWrite.length} denyWrite`,
        )
      }
      windowsFsRawInputs = rawWindowsFsInputs(runtimeConfig)
    } catch (e) {
      // Best-effort release of whatever WAS applied before the
      // failure (exit-2 partial stamps/grants the resolvable
      // inputs; harmless if nothing was — no holds for this PID).
      const g = getWindowsGroupRef()
      if (windowsFsSbUserSids) {
        revokeWindowsAcl({ group: g, sandboxUserSid: windowsFsSbUserSids.sb })
      }
      restoreWindowsAcl({ group: g, sandboxUserSid: windowsFsSbUserSids?.sb })
      windowsFsSbUserSids = undefined
      config = undefined
      throw e
    }
  }

  // Initialize network infrastructure
  initializationPromise = (async () => {
    try {
      // On Windows the WFP loopback permit covers a fixed port
      // range, so the proxies must bind inside it. Other platforms
      // bake the actual ephemeral port into the sandbox profile, so
      // they keep using port 0.
      const portRange: readonly [number, number] | undefined =
        getPlatform() === 'windows'
          ? (config.windows?.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE)
          : undefined

      // The auth token is only set when this process owns the proxy; an
      // external proxy (config.network.httpProxyPort) handles its own auth,
      // and embedding our token in its URL would be wrong.
      proxyAuthToken =
        config.network.httpProxyPort !== undefined
          ? undefined
          : randomBytes(16).toString('hex')

      // The mux front-end serves both protocols on one port. Each side's
      // reported port is the external override if configured, else the mux
      // port — so the public config.network.{http,socks}ProxyPort contract
      // is unchanged. The mux is skipped only when BOTH are external.
      const needLocalProxy =
        config.network.httpProxyPort === undefined ||
        config.network.socksProxyPort === undefined
      const muxPort = needLocalProxy
        ? await startMuxProxyServer(sandboxAskCallback, portRange)
        : undefined
      const httpProxyPort = config.network.httpProxyPort ?? muxPort!
      const socksProxyPort = config.network.socksProxyPort ?? muxPort!
      if (config.network.httpProxyPort !== undefined) {
        logForDebugging(`Using external HTTP proxy on port ${httpProxyPort}`)
      }
      if (config.network.socksProxyPort !== undefined) {
        logForDebugging(`Using external SOCKS proxy on port ${socksProxyPort}`)
      }

      // Initialize platform-specific infrastructure
      let linuxBridge: LinuxNetworkBridgeContext | undefined
      if (getPlatform() === 'linux') {
        linuxBridge = await initializeLinuxNetworkBridge(
          httpProxyPort,
          socksProxyPort,
          config.socatPath,
        )
      }

      const context: HostNetworkManagerContext = {
        httpProxyPort,
        socksProxyPort,
        linuxBridge,
      }
      managerContext = context
      logForDebugging('Network infrastructure initialized')
      return context
    } catch (error) {
      // Clear state on error so initialization can be retried
      initializationPromise = undefined
      managerContext = undefined
      reset().catch(e => {
        logForDebugging(`Cleanup failed in initializationPromise ${e}`, {
          level: 'error',
        })
      })
      throw error
    }
  })()

  await initializationPromise
}

function isSupportedPlatform(): boolean {
  const platform = getPlatform()
  if (platform === 'linux') {
    // WSL1 doesn't support bubblewrap
    return getWslVersion() !== '1'
  }
  return platform === 'macos' || platform === 'windows'
}

/**
 * Resolve the Windows group reference from config. Used by both the
 * dependency check and `wrapWithSandbox` so they agree.
 */
function getWindowsGroupRef(): WindowsGroupRef {
  return {
    groupName: config?.windows?.groupName ?? DEFAULT_WINDOWS_GROUP_NAME,
    groupSid: config?.windows?.groupSid,
  }
}

function isSandboxingEnabled(): boolean {
  // Sandboxing is enabled if config has been set (via initialize())
  return config !== undefined
}

/**
 * Check sandbox dependencies for the current platform
 * @param ripgrepConfig - Ripgrep command to check. If not provided, uses config from initialization or defaults to 'rg'
 * @returns { warnings, errors } - errors mean sandbox cannot run, warnings mean degraded functionality
 */
function checkDependencies(ripgrepConfig?: {
  command: string
  args?: string[]
}): SandboxDependencyCheck {
  if (!isSupportedPlatform()) {
    return { errors: ['Unsupported platform'], warnings: [] }
  }

  const errors: string[] = []
  const warnings: string[] = []

  const platform = getPlatform()
  if (platform === 'linux') {
    // ripgrep is Linux-only: it's used by linuxGetMandatoryDenyPaths() to
    // expand glob deny-patterns to concrete paths for bwrap. macOS seatbelt
    // profiles take regex patterns directly, so rg is never invoked there.
    const rgToCheck = ripgrepConfig ?? config?.ripgrep ?? { command: 'rg' }
    if (whichSync(rgToCheck.command) === null) {
      errors.push(`ripgrep (${rgToCheck.command}) not found`)
    }

    const linuxDeps = checkLinuxDependencies({
      seccompConfig: config?.seccomp,
      bwrapPath: config?.bwrapPath,
      socatPath: config?.socatPath,
    })
    errors.push(...linuxDeps.errors)
    warnings.push(...linuxDeps.warnings)
  } else if (platform === 'windows') {
    const winDeps = checkWindowsDependencies(
      getWindowsGroupRef(),
      config?.windows?.wfpSublayerGuid,
    )
    errors.push(...winDeps.errors)
    warnings.push(...winDeps.warnings)
  }

  return { errors, warnings }
}

/**
 * Build the read-deny / env-unset / env-set maps implied by the
 * `credentials` config.
 *
 * Only explicitly declared sources are restricted: `mode: 'deny'` file
 * entries join the read-deny set, `mode: 'deny'` env vars are unset, and
 * `mode: 'mask'` env vars are set to a per-session sentinel registered in
 * {@link sentinelRegistry}. A masked var with no value in the host
 * environment is skipped — there is nothing to protect, and emitting an
 * unset var would change tool behaviour (presence checks would pass where
 * they didn't before).
 */
function getCredentialRestrictions(
  credentials: CredentialsConfig | undefined,
  allowedDomains: readonly string[] | undefined,
): CredentialRestrictionConfig {
  if (!credentials) {
    return {
      denyReadPaths: [],
      unsetEnvVars: [],
      setEnvVars: {},
      maskedFileBinds: [],
      maskedFileStoreDir: undefined,
    }
  }

  const denyReadPaths = getCredentialDenyReadPaths(credentials)

  const unsetEnvVars: string[] = []
  const setEnvVars: Record<string, string> = {}
  for (const v of credentials.envVars ?? []) {
    if (v.mode === 'deny') {
      unsetEnvVars.push(v.name)
    } else if (v.mode === 'mask') {
      const real = process.env[v.name]
      if (real === undefined) continue
      // Effective injectHosts: per-entry narrows; if unset, default to
      // every reachable host (network.allowedDomains). injectHosts is an
      // *optional narrowing*, not a required allowlist. Trade-off: a
      // masked credential with no injectHosts is injectable at every host
      // the sandbox can reach — narrow it explicitly when the credential
      // should only go to a subset.
      const injectHosts = v.injectHosts ?? allowedDomains ?? []
      setEnvVars[v.name] = sentinelRegistry.register(v.name, real, injectHosts)
    }
  }

  // Masked files: read the real bytes on the host, register a sentinel,
  // write it to a fake file in the manager-owned temp dir. Missing/unreadable
  // entries are skipped (same posture as an unset masked env var).
  // degradeToDenyPaths carries paths whose extract pattern matched
  // nothing with onExtractNoMatch: "deny" — merged into denyReadPaths
  // below so both the read-deny config and the platform builders see them.
  const files = credentials.files ?? []
  const { binds: maskedFileBinds, degradeToDenyPaths } = buildMaskedFileBinds(
    files,
    allowedDomains ?? [],
    sentinelRegistry,
    maskedFileStore,
  )

  return {
    denyReadPaths: [...new Set([...denyReadPaths, ...degradeToDenyPaths])],
    unsetEnvVars: [...new Set(unsetEnvVars)],
    setEnvVars,
    maskedFileBinds,
    maskedFileStoreDir: maskedFileStore.dirPath,
  }
}

/**
 * Pure (side-effect-free) chokepoint for credential file-deny
 * paths — `credentials.files` entries with `mode: 'deny'`. Any
 * code that needs the credential→denyRead contribution routes
 * through here so a comparison predicate can read it without
 * touching {@link sentinelRegistry}.
 */
function getCredentialDenyReadPaths(
  credentials: CredentialsConfig | undefined,
): string[] {
  const files = credentials?.files ?? []
  return [...new Set(files.filter(f => f.mode === 'deny').map(f => f.path))]
}

/** Order-insensitive string-set equality. */
function setEq(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false
  const bs = new Set(b)
  return a.every(v => bs.has(v))
}

/**
 * Union the explicit `filesystem.denyRead` with credential-derived
 * deny paths. The single source of "what files does this config
 * want read-denied" — all platforms route through here so a new
 * credential kind that contributes deny paths reaches every
 * backend.
 */
function unionDenyReadPaths(
  denyRead: readonly string[],
  credentialRestrictions: CredentialRestrictionConfig,
): string[] {
  return [...new Set([...denyRead, ...credentialRestrictions.denyReadPaths])]
}

function getFsReadConfig(): FsReadRestrictionConfig {
  if (!config || config.filesystem.disabled) {
    return { denyOnly: [], allowWithinDeny: [] }
  }

  // Credential deny paths are unioned with the caller's denyRead — never
  // replacing it — so explicit filesystem restrictions always survive.
  const rawDenyRead = unionDenyReadPaths(
    config.filesystem.denyRead,
    getCredentialRestrictions(
      config.credentials,
      config.network.allowedDomains,
    ),
  )

  const denyPaths: string[] = []
  for (const p of rawDenyRead) {
    const stripped = removeTrailingGlobSuffix(p)
    if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
      // Expand glob to concrete paths on Linux (bubblewrap doesn't support globs)
      const expanded = expandGlobPattern(p)
      logForDebugging(
        `[Sandbox] Expanded glob pattern "${p}" to ${expanded.length} paths on Linux`,
      )
      denyPaths.push(...expanded)
    } else {
      denyPaths.push(stripped)
    }
  }

  // Process allowRead paths (re-allow within denied regions)
  const allowPaths: string[] = []
  for (const p of config.filesystem.allowRead ?? []) {
    const stripped = removeTrailingGlobSuffix(p)
    if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
      const expanded = expandGlobPattern(p)
      logForDebugging(
        `[Sandbox] Expanded allowRead glob pattern "${p}" to ${expanded.length} paths on Linux`,
      )
      allowPaths.push(...expanded)
    } else {
      allowPaths.push(stripped)
    }
  }

  return {
    denyOnly: denyPaths,
    allowWithinDeny: allowPaths,
  }
}

function getFsWriteConfig(): FsWriteRestrictionConfig {
  if (!config) {
    return { allowOnly: getDefaultWritePaths(), denyWithinAllow: [] }
  }

  if (config.filesystem.disabled) {
    return { allowOnly: ['/'], denyWithinAllow: [] }
  }

  // Filter out glob patterns on Linux/WSL for allowWrite (bubblewrap doesn't support globs)
  const allowPaths = config.filesystem.allowWrite
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux/WSL: ${path}`)
        return false
      }
      return true
    })

  // Filter out glob patterns on Linux/WSL for denyWrite (bubblewrap doesn't support globs)
  const denyPaths = config.filesystem.denyWrite
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux/WSL: ${path}`)
        return false
      }
      return true
    })

  // Build allowOnly list: default paths + configured allow paths
  const allowOnly = [...getDefaultWritePaths(), ...allowPaths]

  return {
    allowOnly,
    denyWithinAllow: denyPaths,
  }
}

/**
 * Build the Windows file-access set (deny stamps + sandbox-user
 * grants) from `runtimeConfig`. Globs are expanded to concrete
 * paths (point-in-time — a path appearing after this returns is NOT
 * covered). Directory handling is per-mode (see below). Throws on
 * any unsupported config field that would otherwise be silently
 * dropped.
 *
 * `denyRead` ← `filesystem.denyRead` ∪ `credentials`-derived deny
 *              paths (via {@link getCredentialDenyReadPaths}).
 * `denyWrite` ← `filesystem.denyWrite`.
 *
 * Under the **same-user model** (the default), `allowRead` /
 * `allowWrite` are not supported (throws if non-empty so the
 * caller never silently runs with a weaker-than-configured policy)
 * — the same-user backend is deny-listed only.
 *
 * Under the **separate-user model** (`windows.asSandboxUser`), the
 * sandbox user has no inherent rights on real-user-owned files,
 * so `allowWrite` (the working-tree roots) becomes a per-session
 * `MODIFY_NO_FDC` ALLOW ACE for `<sb-SID>`, `allowRead` a
 * `READ|EXECUTE` ALLOW ACE, and `denyRead`/`denyWrite` become an
 * explicit DENY ACE for `<sb-SID>` on the target plus a
 * `(OI)(CI) FILE_DELETE_CHILD` DENY on its parent. Directory
 * targets are accepted in this mode (the `(OI)(CI)` ACEs cover the
 * subtree).
 */
function computeWindowsFsAccessSet(c: SandboxRuntimeConfig): {
  grantRead: string[]
  grantWrite: string[]
  denyRead: string[]
  denyWrite: string[]
} {
  const fs = c.filesystem
  // filesystem.disabled bypasses ALL filesystem rule generation —
  // same as the macOS/Linux wrapWithSandbox path (readConfig /
  // writeConfig left undefined). On Windows this means no ACL
  // stamp/grant; credential FILE denies are dropped along with the
  // rest (credential ENV scrubbing is independent and still applied
  // at wrap time).
  if (fs?.disabled) {
    return { grantRead: [], grantWrite: [], denyRead: [], denyWrite: [] }
  }
  const asSbUser = c.windows?.asSandboxUser ?? false
  if (!asSbUser) {
    if (fs?.allowRead?.length) {
      throw new Error(
        `filesystem.allowRead is not supported on Windows without ` +
          `windows.asSandboxUser. Remove the entries or narrow ` +
          `filesystem.denyRead to exclude them.`,
      )
    }
    if (fs?.allowWrite?.length) {
      throw new Error(
        `filesystem.allowWrite is not supported on Windows without ` +
          `windows.asSandboxUser — the same-user backend is deny-listed ` +
          `only. Remove the allowWrite entries or set windows.asSandboxUser.`,
      )
    }
  }
  const expand = (p: readonly string[]) =>
    expandWindowsFsDenyPaths(p, { allowDirs: asSbUser })
  const denyRead = expand([
    ...new Set([
      ...(fs?.denyRead ?? []),
      ...getCredentialDenyReadPaths(c.credentials),
    ]),
  ])
  const denyWrite = expand(fs?.denyWrite ?? [])
  return {
    // Grants are separate-user-mode only — same-user already has
    // full host-user access (and `allowRead`/`allowWrite` threw
    // above). `allowRead` under SandboxUser also serves as
    // `allowWithinDeny`: a file under a denied dir gets an explicit
    // ACE for the sandbox user, overriding what it would inherit
    // from the PROTECTED parent.
    grantRead: asSbUser ? expand(fs?.allowRead ?? []) : [],
    grantWrite: asSbUser ? expand(fs?.allowWrite ?? []) : [],
    denyRead,
    denyWrite,
  }
}

/**
 * Snapshot the raw config fields that feed
 * {@link computeWindowsFsAccessSet}. Used by updateConfig() to
 * short-circuit the resolved-set diff (which re-runs glob
 * expansion) when nothing relevant changed.
 */
function rawWindowsFsInputs(c: SandboxRuntimeConfig) {
  // Keyed exactly on what {@link computeWindowsFsAccessSet} reads.
  // `network.allowedDomains` does NOT feed file-deny (only mask
  // injectHosts), so a network-only updateConfig hits the cache.
  return {
    disabled: c.filesystem.disabled ?? false,
    asSbUser: c.windows?.asSandboxUser ?? false,
    denyRead: [...c.filesystem.denyRead],
    denyWrite: [...c.filesystem.denyWrite],
    allowRead: [...(c.filesystem.allowRead ?? [])],
    allowWrite: [...c.filesystem.allowWrite],
    credFiles: getCredentialDenyReadPaths(c.credentials),
  }
}

function sameRawWindowsFsInputs(
  a: ReturnType<typeof rawWindowsFsInputs>,
  b: ReturnType<typeof rawWindowsFsInputs>,
): boolean {
  return (
    a.disabled === b.disabled &&
    a.asSbUser === b.asSbUser &&
    setEq(a.denyRead, b.denyRead) &&
    setEq(a.denyWrite, b.denyWrite) &&
    setEq(a.allowRead, b.allowRead) &&
    setEq(a.allowWrite, b.allowWrite) &&
    setEq(a.credFiles, b.credFiles)
  )
}

/**
 * True when `newConfig`'s file-deny inputs match what was
 * stamped at initialize(). Compares raw inputs only (cheap,
 * order-insensitive); never re-expands globs — updateConfig is
 * warn-only on Windows and the resolved set wouldn't be used.
 */
function sameWindowsStampSet(newConfig: SandboxRuntimeConfig): boolean {
  return (
    windowsFsRawInputs !== undefined &&
    sameRawWindowsFsInputs(windowsFsRawInputs, rawWindowsFsInputs(newConfig))
  )
}

function getNetworkRestrictionConfig(): NetworkRestrictionConfig {
  if (!config) {
    return {}
  }

  // Preserve an explicitly-empty allowlist: consumers need to distinguish
  // "no network restriction configured" (absent) from "allowlist configured
  // with zero entries" (block-all / ask-only). Stripping the empty array
  // made a host app's restriction-status UI report an airgapped config as
  // unrestricted. deniedHosts keeps the strip — an empty denylist and an
  // absent one are semantically identical.
  const allowedHosts = config.network.allowedDomains
  const deniedHosts = config.network.deniedDomains

  return {
    allowedHosts,
    ...(deniedHosts.length > 0 && { deniedHosts }),
  }
}

function getAllowUnixSockets(): string[] | undefined {
  return config?.network?.allowUnixSockets
}

function getAllowAllUnixSockets(): boolean | undefined {
  return config?.network?.allowAllUnixSockets
}

function getAllowLocalBinding(): boolean | undefined {
  return config?.network?.allowLocalBinding
}

function getAllowMachLookup(): string[] | undefined {
  return config?.network?.allowMachLookup
}

function getIgnoreViolations(): Record<string, string[]> | undefined {
  return config?.ignoreViolations
}

function getEnableWeakerNestedSandbox(): boolean | undefined {
  return config?.enableWeakerNestedSandbox
}

function getEnableWeakerNetworkIsolation(): boolean | undefined {
  return config?.enableWeakerNetworkIsolation
}

function getAllowAppleEvents(): boolean | undefined {
  return config?.allowAppleEvents
}

function getRipgrepConfig(): { command: string; args?: string[] } {
  return config?.ripgrep ?? { command: 'rg' }
}

function getMandatoryDenySearchDepth(): number {
  return config?.mandatoryDenySearchDepth ?? 3
}

function getAllowGitConfig(): boolean {
  return config?.filesystem?.allowGitConfig ?? false
}

function getSeccompConfig(): SeccompConfig | undefined {
  return config?.seccomp
}

function getProxyAuthToken(): string | undefined {
  return proxyAuthToken
}

function getProxyPort(): number | undefined {
  return managerContext?.httpProxyPort
}

function getSocksProxyPort(): number | undefined {
  return managerContext?.socksProxyPort
}

function getLinuxHttpSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.httpSocketPath
}

function getLinuxSocksSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.socksSocketPath
}

/**
 * Wait for network initialization to complete if already in progress
 * Returns true if initialized successfully, false otherwise
 */
async function waitForNetworkInitialization(): Promise<boolean> {
  if (!config) {
    return false
  }
  if (initializationPromise) {
    try {
      await initializationPromise
      return true
    } catch {
      return false
    }
  }
  return managerContext !== undefined
}

async function wrapWithSandbox(
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
): Promise<string> {
  const platform = getPlatform()

  // filesystem.disabled bypasses ALL filesystem rule generation. Both
  // platform wrappers treat readConfig/writeConfig === undefined as "no
  // filesystem restrictions" (seatbelt emits `(allow file-write*)`; bwrap
  // skips the `--ro-bind / /` root and all path binds).
  //
  // Precedence: when a caller passes a per-call filesystem override at all,
  // its `disabled` (defaulting to false) wins outright. A global
  // disabled=true must not silently discard a per-call tightening that
  // omits the new key.
  const fsDisabled =
    customConfig?.filesystem !== undefined
      ? (customConfig.filesystem.disabled ?? false)
      : (config?.filesystem.disabled ?? false)

  // Credential env handling is independent of filesystem policy: unsetEnvVars /
  // setEnvVars must be applied even when fsDisabled (the credential file
  // deny-reads are dropped, but env scrubbing still happens).
  const credentialRestrictions = getCredentialRestrictions(
    customConfig?.credentials ?? config?.credentials,
    customConfig?.network?.allowedDomains ?? config?.network?.allowedDomains,
  )

  // Get configs - use custom if provided, otherwise fall back to main config
  // If neither exists, defaults to empty arrays (most restrictive)
  // Always include default system write paths (like /dev/null, /tmp/claude)
  //
  // Strip trailing /** and filter remaining globs on Linux (bwrap needs
  // real paths, not globs; macOS subpath matching is also recursive so
  // stripping is harmless there).
  let writeConfig: FsWriteRestrictionConfig | undefined
  let readConfig: FsReadRestrictionConfig | undefined
  if (!fsDisabled) {
    const stripWriteGlobs = (paths: string[]): string[] =>
      paths
        .map(p => removeTrailingGlobSuffix(p))
        .filter(p => {
          if (getPlatform() === 'linux' && containsGlobChars(p)) {
            logForDebugging(
              `[Sandbox] Skipping glob write pattern on Linux: ${p}`,
            )
            return false
          }
          return true
        })
    const userAllowWrite = stripWriteGlobs(
      customConfig?.filesystem?.allowWrite ??
        config?.filesystem.allowWrite ??
        [],
    )
    writeConfig = {
      allowOnly: [...getDefaultWritePaths(), ...userAllowWrite],
      denyWithinAllow: stripWriteGlobs(
        customConfig?.filesystem?.denyWrite ??
          config?.filesystem.denyWrite ??
          [],
      ),
    }

    // Credential deny paths are unioned with the caller's denyRead — never
    // replacing it — so explicit filesystem restrictions always survive.
    const rawDenyRead = unionDenyReadPaths(
      customConfig?.filesystem?.denyRead ?? config?.filesystem.denyRead ?? [],
      credentialRestrictions,
    )
    const expandedDenyRead: string[] = []
    for (const p of rawDenyRead) {
      const stripped = removeTrailingGlobSuffix(p)
      if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
        expandedDenyRead.push(...expandGlobPattern(p))
      } else {
        expandedDenyRead.push(stripped)
      }
    }
    const rawAllowRead =
      customConfig?.filesystem?.allowRead ?? config?.filesystem.allowRead ?? []
    const expandedAllowRead: string[] = []
    for (const p of rawAllowRead) {
      const stripped = removeTrailingGlobSuffix(p)
      if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
        expandedAllowRead.push(...expandGlobPattern(p))
      } else {
        expandedAllowRead.push(stripped)
      }
    }
    // The TLS-termination CA cert and the trust bundle the env vars point at
    // (NODE_EXTRA_CA_CERTS etc.) must be readable by the child, even if their
    // paths fall under a user-configured denyRead.
    if (mitmCA) {
      expandedAllowRead.push(mitmCA.certPath, mitmCA.trustBundlePath)
    }
    readConfig = {
      denyOnly: expandedDenyRead,
      allowWithinDeny: expandedAllowRead,
    }
  }

  // Check if network config is specified - this determines if we need network restrictions
  // Network restriction is needed when:
  // 1. customConfig has network.allowedDomains defined (even if empty array = block all)
  // 2. OR config has network.allowedDomains defined (even if empty array = block all)
  // An empty allowedDomains array means "no domains allowed" = block all network access
  const hasNetworkConfig =
    customConfig?.network?.allowedDomains !== undefined ||
    config?.network?.allowedDomains !== undefined

  // Network RESTRICTION is needed whenever network config is specified
  // This includes empty allowedDomains which means "block all network"
  const needsNetworkRestriction = hasNetworkConfig

  // Network PROXY is needed whenever network config is specified
  // Even with empty allowedDomains, we route through proxy so that:
  // 1. updateConfig() can enable network access for already-running processes
  // 2. The proxy blocks all requests when allowlist is empty
  const needsNetworkProxy = hasNetworkConfig

  // Wait for network initialization only if proxy is actually needed
  if (needsNetworkProxy) {
    await waitForNetworkInitialization()
  }

  // Check custom config to allow pseudo-terminal (can be applied dynamically)
  const allowPty = customConfig?.allowPty ?? config?.allowPty

  switch (platform) {
    case 'macos':
      // macOS sandbox profile supports glob patterns directly, no ripgrep needed
      return wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction,
        // Only pass proxy ports if proxy is running (when there are domains to filter)
        httpProxyPort: needsNetworkProxy ? getProxyPort() : undefined,
        socksProxyPort: needsNetworkProxy ? getSocksProxyPort() : undefined,
        proxyAuthToken: needsNetworkProxy ? proxyAuthToken : undefined,
        caCertPath: mitmCA?.trustBundlePath,
        readConfig,
        writeConfig,
        unsetEnvVars: credentialRestrictions.unsetEnvVars,
        setEnvVars: credentialRestrictions.setEnvVars,
        maskedFileBinds: credentialRestrictions.maskedFileBinds,
        allowUnixSockets: getAllowUnixSockets(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
        allowLocalBinding: getAllowLocalBinding(),
        allowMachLookup: getAllowMachLookup(),
        ignoreViolations: getIgnoreViolations(),
        allowPty,
        allowGitConfig: getAllowGitConfig(),
        enableWeakerNetworkIsolation: getEnableWeakerNetworkIsolation(),
        allowAppleEvents: getAllowAppleEvents(),
        binShell,
      })

    case 'linux':
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction,
        // Only pass socket paths if proxy is running (when there are domains to filter)
        httpSocketPath: needsNetworkProxy
          ? getLinuxHttpSocketPath()
          : undefined,
        socksSocketPath: needsNetworkProxy
          ? getLinuxSocksSocketPath()
          : undefined,
        httpProxyPort: needsNetworkProxy
          ? managerContext?.httpProxyPort
          : undefined,
        socksProxyPort: needsNetworkProxy
          ? managerContext?.socksProxyPort
          : undefined,
        proxyAuthToken: needsNetworkProxy ? proxyAuthToken : undefined,
        caCertPath: mitmCA?.trustBundlePath,
        readConfig,
        writeConfig,
        unsetEnvVars: credentialRestrictions.unsetEnvVars,
        setEnvVars: credentialRestrictions.setEnvVars,
        maskedFileBinds: credentialRestrictions.maskedFileBinds,
        maskedFileStoreDir: credentialRestrictions.maskedFileStoreDir,
        enableWeakerNestedSandbox: getEnableWeakerNestedSandbox(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
        binShell,
        ripgrepConfig: getRipgrepConfig(),
        mandatoryDenySearchDepth: getMandatoryDenySearchDepth(),
        allowGitConfig: getAllowGitConfig(),
        seccompConfig: getSeccompConfig(),
        bwrapPath: config?.bwrapPath,
        socatPath: config?.socatPath,
        abortSignal,
      })

    case 'windows':
      // Windows wraps to an argv array, not a shell string. Forcing
      // callers through wrapWithSandboxArgv() means they spawn with
      // {shell:false}, which is the security boundary that keeps the
      // user's command bytes off the HOST shell.
      throw new Error(
        'wrapWithSandbox() returns a shell string and is not supported ' +
          'on Windows. Use SandboxManager.wrapWithSandboxArgv() and ' +
          'spawn the result with {shell: false}.',
      )

    default:
      // Unsupported platform - this should not happen since isSandboxingEnabled() checks platform support
      throw new Error(
        `Sandbox configuration is not supported on platform: ${platform}`,
      )
  }
}

/**
 * Wrap `command` for the sandbox and return a spawn descriptor:
 * `{ argv, env }`, suitable for
 * `spawn(argv[0], argv.slice(1), {shell: false, env})`.
 *
 * On Windows this is the ONLY supported wrap method (see
 * {@link wrapWithSandbox}); `env` carries the full proxy set that the
 * sandboxed child inherits (`srt-win exec` forwards its environment
 * verbatim — see {@link wrapCommandWithSandboxWindows}). On
 * macOS/Linux `argv` is `[binShell, '-c', <wrapWithSandbox result>]`
 * (proxy env is baked into that command) and `env` is the unchanged
 * `process.env`, so callers can spawn uniformly across platforms.
 */
async function wrapWithSandboxArgv(
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }> {
  const platform = getPlatform()

  if (platform === 'windows') {
    const hasNetworkConfig =
      customConfig?.network?.allowedDomains !== undefined ||
      config?.network?.allowedDomains !== undefined
    if (hasNetworkConfig) {
      await waitForNetworkInitialization()
    }
    const credentialRestrictions = getCredentialRestrictions(
      customConfig?.credentials ?? config?.credentials,
      customConfig?.network?.allowedDomains ?? config?.network?.allowedDomains,
    )
    // Per-exec FILE denies (customConfig only — the session-level
    // config's denies were already stamped at initialize()).
    // Paths go through `expandWindowsFsDenyPaths` — the SAME
    // chokepoint the session-level set uses (point-in-time glob
    // expand, normalize, missing→drop, dir→throw under
    // same-user) — so a per-exec entry resolves identically to
    // its session-level equivalent. macOS/Linux per-exec already
    // reuses session-level expansion; Windows now matches.
    //
    // The dedup against `windowsFsStampedSet` is an OPTIMIZATION,
    // not a correctness gate: re-stamping a session-held path
    // under the exec's distinct holder is refcount-safe but
    // wastes a SetSecurityInfo round-trip. The mask-escalation /
    // hardlink-alias guard lives in srt-win's `ensure_stamped`
    // (`refuse_escalation = true`), NOT here — canonical-path
    // identity and concurrent holders are only visible to Rust.
    //
    // filesystem.disabled bypasses ALL filesystem rule generation
    // — including credential-derived file denies — same ordering
    // as session-level `computeWindowsFsAccessSet` (credential ENV
    // scrubbing is independent and still applied at wrap time).
    // allowRead/allowWrite throw, also matching session-level:
    // the Windows file-deny sandbox is deny-only.
    const fsCfg = customConfig?.filesystem
    let perExecDenyRead: string[] = []
    let perExecDenyWrite: string[] = []
    if (!fsCfg?.disabled) {
      if (fsCfg?.allowRead?.length) {
        throw new Error(
          `Per-exec filesystem.allowRead (re-allow within denyRead) is ` +
            `not supported on Windows. Remove the entries or narrow ` +
            `filesystem.denyRead to exclude them.`,
        )
      }
      if (fsCfg?.allowWrite?.length) {
        throw new Error(
          `Per-exec filesystem.allowWrite is not supported on Windows — ` +
            `the Windows sandbox is deny-listed only (the child writes ` +
            `wherever the host user can, minus filesystem.denyWrite). ` +
            `Remove the allowWrite entries.`,
        )
      }
      const rawRead = [
        ...(fsCfg?.denyRead ?? []),
        ...getCredentialDenyReadPaths(customConfig?.credentials),
      ]
      const rawWrite = fsCfg?.denyWrite ?? []
      // Skip on the dominant path (no per-exec fs or
      // credential-file deny) — this used to call
      // `computeWindowsFsAccessSet` (glob walk + statSync per
      // match) on every exec, including with
      // `customConfig === undefined`.
      if (rawRead.length > 0 || rawWrite.length > 0) {
        const sessRead = new Set(windowsFsStampedSet?.denyRead ?? [])
        const sessWrite = new Set(windowsFsStampedSet?.denyWrite ?? [])
        const asSbUser = config?.windows?.asSandboxUser ?? false
        const expand = (raw: readonly string[]) =>
          expandWindowsFsDenyPaths(raw, { allowDirs: asSbUser })
        perExecDenyRead = expand(rawRead).filter(p => !sessRead.has(p))
        perExecDenyWrite = expand(rawWrite).filter(
          p => !sessRead.has(p) && !sessWrite.has(p),
        )
      }
    }
    // Per-exec deny rides on argv (`acl stamp` reads stdin, but
    // exec's stdin belongs to the child). The CreateProcessW
    // length check lives in `wrapCommandWithSandboxWindows`
    // where the full argv (incl. shell + user command) is known.
    //
    // Credential env restrictions are passed INTO the wrapper so it
    // can apply them BEFORE merging the proxy env (same precedence
    // as the macOS/Linux `env -u … VAR=… sandbox-exec` order — the
    // sandbox's own proxy plumbing must survive a caller listing
    // e.g. HTTPS_PROXY as a denied credential). The `denyReadPaths`
    // half of the SESSION-level credentials is already unioned into
    // the stamp set at initialize() time via
    // `computeWindowsFsAccessSet`.
    return wrapCommandWithSandboxWindows({
      command,
      group: getWindowsGroupRef(),
      httpProxyPort: hasNetworkConfig ? getProxyPort() : undefined,
      socksProxyPort: hasNetworkConfig ? getSocksProxyPort() : undefined,
      proxyAuthToken: hasNetworkConfig ? proxyAuthToken : undefined,
      unsetEnvVars: credentialRestrictions.unsetEnvVars,
      setEnvVars: credentialRestrictions.setEnvVars,
      // Engage the session-level fence only when this session
      // actually stamped — keeps `srt-win exec` standalone (no
      // state-DB dependency) when no file-deny is configured. The
      // per-exec deny below opens its own fence under the exec's
      // own PID regardless.
      holderPid: windowsFsStampedSet ? process.pid : undefined,
      denyRead: perExecDenyRead,
      denyWrite: perExecDenyWrite,
      // Opt-in two-hop separate-user launch. Additive — defaults
      // false, the same-user deny-only-group path is unchanged.
      // Provisioning was checked at initialize().
      asSandboxUser: config?.windows?.asSandboxUser ?? false,
      caCertPath: mitmCA?.trustBundlePath,
      binShell: parseWindowsBinShell(binShell),
    })
  }

  // macOS/Linux: delegate to the existing string wrapper, then put
  // the result behind `<shell> -c` so the caller's argv-spawn works.
  const wrapped = await wrapWithSandbox(
    command,
    binShell,
    customConfig,
    abortSignal,
  )
  const shell = binShell ?? '/bin/bash'
  return { argv: [shell, '-c', wrapped], env: process.env }
}

/**
 * Get the current sandbox configuration
 * @returns The current configuration, or undefined if not initialized
 */
function getConfig(): SandboxRuntimeConfig | undefined {
  return config
}

/**
 * Update the sandbox configuration in place.
 *
 * **Network/allowlist changes are a live swap**: the running
 * http/socks proxies read `config.network.allowedDomains` /
 * `deniedDomains` per-request (via `filterNetworkRequest`), so
 * reassigning `config` here takes effect on the next connection
 * with no proxy rebind and no port change — on every platform,
 * including Windows. This is what lets a host enable/deny domains
 * for already-running sandboxed children.
 *
 * Filesystem changes (denyRead/denyWrite) are NOT applied live:
 * macOS bakes them into the seatbelt profile at wrap time, and
 * Windows applies the ACL stamp once at `initialize()` (a live
 * swap would mean releasing all of this holder's claims and
 * re-stamping, which opens an unprotected window). To change FS
 * restrictions, `reset()` then `initialize()` with the new
 * config; on Windows, calling this with a config whose file-deny
 * inputs (`filesystem.denyRead`/`denyWrite`, `credentials.files`)
 * differ from those passed at `initialize()` logs a warning and
 * the stamped set stays as-is.
 *
 * @param newConfig - The new configuration to use
 */
function updateConfig(newConfig: SandboxRuntimeConfig): void {
  if (
    getPlatform() === 'windows' &&
    config &&
    (newConfig.windows?.groupSid !== config.windows?.groupSid ||
      newConfig.windows?.groupName !== config.windows?.groupName)
  ) {
    throw new Error(
      'Changing the Windows sandbox group requires reset() and ' +
        're-initialize().',
    )
  }
  if (
    getPlatform() === 'windows' &&
    config &&
    !sameWindowsStampSet(newConfig)
  ) {
    logForDebugging(
      `[Sandbox Windows] updateConfig: the resolved file-deny set ` +
        `(filesystem.denyRead/denyWrite ∪ credentials.files) changed but ` +
        `the ACL stamp is session-wide — call reset() then initialize() ` +
        `to apply. The previously-stamped set stays in effect.`,
      { level: 'warn' },
    )
  }
  // Deep clone the config to avoid mutations. structuredClone cannot clone
  // functions, so pull filterRequest out, clone the rest, and put it back —
  // a function reference is immutable in the sense that matters here.
  const { filterRequest, ...rest } = newConfig.network
  config = structuredClone({ ...newConfig, network: rest })
  config.network.filterRequest = filterRequest
  // Re-resolve parent proxy so hot-reload picks up changes. Note: the proxy
  // servers capture `parentProxy` by value at creation, so changes here take
  // effect only on re-initialize. This keeps the state consistent for the
  // next initialize() call.
  parentProxy = resolveParentProxy(newConfig.network.parentProxy)
  logForDebugging('Sandbox configuration updated')
}

/**
 * Lightweight cleanup to call after each sandboxed command completes.
 *
 * On Linux, bwrap creates empty files on the host filesystem as mount points
 * when protecting non-existent deny paths (e.g. ~/.bashrc, ~/.gitconfig).
 * These persist after bwrap exits. This function removes them.
 *
 * Safe to call on any platform — it's a no-op on macOS.
 * Also called automatically by reset() and on process exit as safety nets.
 */
function cleanupAfterCommand(): void {
  cleanupBwrapMountPoints()
}

/**
 * How long to wait for a bridge process to exit after SIGTERM before
 * escalating to SIGKILL.
 *
 * socat exits within ~10ms of SIGTERM; this is purely a safety margin.
 * Keep it well below bun's default 5s test/hook timeout: when a bridge's
 * `'exit'` event is missed entirely (a Linux-only Bun pidfd notification
 * bug, oven-sh/bun#30301), this timer is the only thing that lets `reset()`
 * make progress, and a 5000ms value here loses the race against the hook
 * timer by a couple of milliseconds — that race was the dominant CI flake.
 */
const BRIDGE_EXIT_TIMEOUT_MS = 1500

/**
 * SIGTERM a bridge process and resolve once it has exited.
 *
 * Returns immediately if the process has already exited (`.exitCode` /
 * `.signalCode` set) — registering `.once('exit')` after the event has
 * already been emitted produces a listener that never fires.
 *
 * Falls back to SIGKILL after {@link BRIDGE_EXIT_TIMEOUT_MS}.
 */
function killBridgeProcess(proc: ChildProcess, label: string): Promise<void> {
  // Already exited → 'exit' already emitted → a fresh once('exit') would
  // never fire. Don't wait on it.
  if (!proc.pid || proc.exitCode !== null || proc.signalCode !== null) {
    return Promise.resolve()
  }

  try {
    process.kill(proc.pid, 'SIGTERM')
    logForDebugging(`Sent SIGTERM to ${label} bridge process`)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
      logForDebugging(`Error killing ${label} bridge: ${err}`, {
        level: 'error',
      })
    }
    // ESRCH = process already gone; nothing to wait for either way.
    return Promise.resolve()
  }

  return new Promise<void>(resolve => {
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve()
    }
    proc.once('exit', () => {
      logForDebugging(`${label} bridge process exited`)
      done()
    })
    const timer = setTimeout(() => {
      // Re-check liveness — the 'exit' may have raced us.
      if (proc.exitCode === null && proc.signalCode === null) {
        logForDebugging(`${label} bridge did not exit, forcing SIGKILL`, {
          level: 'warn',
        })
        try {
          if (proc.pid) process.kill(proc.pid, 'SIGKILL')
        } catch {
          // Process may have already exited
        }
      }
      done()
    }, BRIDGE_EXIT_TIMEOUT_MS)
    // The bridge process is being torn down; this timer must not be the
    // only thing keeping the event loop alive.
    timer.unref?.()
  })
}

/**
 * Forcibly close an http.Server, including any in-flight requests.
 *
 * Plain `server.close()` waits for every active request to finish.
 * The proxy may be mid-upstream-request when reset() runs (e.g. a test's
 * curl was killed by --max-time while the proxy was still dialing the
 * real example.com / api.github.com), and `dialDirect()` allows up to
 * 30s before giving up. Combined with a socat fork that hasn't yet seen
 * its unix-socket EOF, that leaves a fully-open inbound connection and
 * `server.close()` never calls back. `closeAllConnections()` (Node 18.2+,
 * also implemented in Bun) tears down those sockets so `close()` resolves
 * immediately.
 */
function forceCloseHttpServer(
  server: ReturnType<typeof createHttpProxyServer>,
): Promise<void> {
  return new Promise<void>(resolve => {
    // Must run *before* close(): in Bun, close() also detaches the
    // underlying handle, so a closeAllConnections() called afterwards
    // becomes a no-op and the close callback waits for the in-flight
    // request to drain — defeating the purpose. With closeAllConnections()
    // first, the connections are gone by the time close() runs and its
    // callback fires immediately (Bun reports "Server is not running.",
    // Node reports no error). Verified against both orderings.
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections()
    }
    server.close(error => {
      if (error && error.message !== 'Server is not running.') {
        logForDebugging(`Error closing HTTP proxy server: ${error.message}`, {
          level: 'error',
        })
      }
      resolve()
    })
  })
}

async function reset(): Promise<void> {
  // Windows: release this session's file-deny stamps. Best-effort
  // — log anomalies (relocated/missing/tampered/…) rather than
  // throw, so teardown always completes. The on-disk hash-ACE
  // marker means a stamp left in place is recoverable later via
  // `srt-win acl recover`.
  if (windowsFsStampedSet) {
    const group = windowsFsStampedGroup ?? getWindowsGroupRef()
    if (windowsFsSbUserSids) {
      const rv = revokeWindowsAcl({
        group,
        sandboxUserSid: windowsFsSbUserSids.sb,
      })
      for (const e of rv ?? []) {
        if (e.status !== 'revoked' && e.status !== 'stillHeld') {
          logForDebugging(
            `[Sandbox Windows] grant revoke: '${e.path}' ${e.status}`,
            { level: 'warn' },
          )
        }
      }
    }
    const r = restoreWindowsAcl({
      group,
      sandboxUserSid: windowsFsSbUserSids?.sb,
    })
    if (r) {
      for (const e of r.paths ?? []) {
        if (!WINDOWS_ACL_PATH_OK.has(e.status)) {
          const tail =
            e.status === 'missing'
              ? ' — file no longer exists; snapshot row kept for tracking'
              : (e.movedTo ? ` (now at '${e.movedTo}')` : '') +
                ' — stamp left in place; resolve and run ' +
                '`srt-win acl recover` to clear'
          logForDebugging(
            `[Sandbox Windows] file-deny restore: '${e.path}' ` +
              `${e.status}${tail}`,
            { level: 'warn' },
          )
        }
      }
      for (const e of r.parents ?? []) {
        if (!WINDOWS_ACL_PARENT_OK.has(e.status)) {
          logForDebugging(
            `[Sandbox Windows] file-deny restore: parent ` +
              `'${e.path}' ${e.status}` +
              (e.error ? `: ${e.error}` : ''),
            { level: 'warn' },
          )
        }
      }
    }
  }
  windowsFsStampedSet = undefined
  windowsFsStampedGroup = undefined
  windowsFsSbUserSids = undefined
  windowsFsRawInputs = undefined
  windowsWfpVerified = false

  // Clean up any leftover bwrap mount points. Force past the
  // active-sandbox counter — reset() means the session is over.
  cleanupBwrapMountPoints({ force: true })

  // Stop log monitor
  if (logMonitorShutdown) {
    logMonitorShutdown()
    logMonitorShutdown = undefined
  }

  if (managerContext?.linuxBridge) {
    const {
      httpSocketPath,
      socksSocketPath,
      httpBridgeProcess,
      socksBridgeProcess,
    } = managerContext.linuxBridge

    // Kill both bridges and wait for them to exit
    await Promise.all([
      killBridgeProcess(httpBridgeProcess, 'HTTP'),
      killBridgeProcess(socksBridgeProcess, 'SOCKS'),
    ])

    // Clean up sockets
    if (httpSocketPath) {
      try {
        fs.rmSync(httpSocketPath, { force: true })
        logForDebugging('Cleaned up HTTP socket')
      } catch (err) {
        logForDebugging(`HTTP socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }

    if (socksSocketPath) {
      try {
        fs.rmSync(socksSocketPath, { force: true })
        logForDebugging('Cleaned up SOCKS socket')
      } catch (err) {
        logForDebugging(`SOCKS socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }
  }

  // Close servers in parallel (only if they exist, i.e., were started by us)
  const closePromises: Promise<void>[] = []

  if (mitmCA) {
    closePromises.push(disposeMitmCA(mitmCA))
  }

  if (muxProxyServer) {
    closePromises.push(
      muxProxyServer.close().catch((error: Error) => {
        logForDebugging(`Error closing mux proxy server: ${error.message}`, {
          level: 'error',
        })
      }),
    )
  }

  if (httpProxyServer) {
    closePromises.push(forceCloseHttpServer(httpProxyServer))
  }

  if (socksProxyServer) {
    const socksClose = socksProxyServer.close().catch((error: Error) => {
      logForDebugging(`Error closing SOCKS proxy server: ${error.message}`, {
        level: 'error',
      })
    })
    closePromises.push(socksClose)
  }

  // Wait for all servers to close
  await Promise.all(closePromises)

  // Clear references
  muxProxyServer = undefined
  httpProxyServer = undefined
  proxyAuthToken = undefined
  socksProxyServer = undefined
  managerContext = undefined
  initializationPromise = undefined
  parentProxy = undefined
  mitmCA = undefined
  sentinelRegistry.clear()
  maskedFileStore.dispose()
}

function getSandboxViolationStore() {
  return sandboxViolationStore
}

function annotateStderrWithSandboxFailures(
  command: string,
  stderr: string,
): string {
  if (!config) {
    return stderr
  }

  const violations = sandboxViolationStore.getViolationsForCommand(command)
  if (violations.length === 0) {
    return stderr
  }

  let annotated = stderr
  annotated += EOL + '<sandbox_violations>' + EOL
  for (const violation of violations) {
    annotated += violation.line + EOL
  }
  annotated += '</sandbox_violations>'

  return annotated
}

/**
 * Returns glob patterns from Edit/Read permission rules that are not
 * fully supported on Linux. Returns empty array on macOS or when
 * sandboxing is disabled.
 *
 * Patterns ending with /** are excluded since they work as subpaths.
 */
function getLinuxGlobPatternWarnings(): string[] {
  // Only warn on Linux/WSL (bubblewrap doesn't support globs)
  // macOS supports glob patterns via regex conversion
  if (getPlatform() !== 'linux' || !config || config.filesystem.disabled) {
    return []
  }

  const globPatterns: string[] = []

  // Check filesystem paths for glob patterns
  // Note: denyRead is excluded because globs are now expanded to concrete paths on Linux
  const allPaths = [
    ...config.filesystem.allowWrite,
    ...config.filesystem.denyWrite,
  ]

  for (const path of allPaths) {
    // Strip trailing /** since that's just a subpath (directory and everything under it)
    const pathWithoutTrailingStar = removeTrailingGlobSuffix(path)

    // Only warn if there are still glob characters after removing trailing /**
    if (containsGlobChars(pathWithoutTrailingStar)) {
      globPatterns.push(path)
    }
  }

  return globPatterns
}

// ============================================================================
// Public API Interface
// ============================================================================

/**
 * Interface for the sandbox manager API
 */
export interface ISandboxManager {
  initialize(
    runtimeConfig: SandboxRuntimeConfig,
    sandboxAskCallback?: SandboxAskCallback,
    enableLogMonitor?: boolean,
  ): Promise<void>
  isSupportedPlatform(): boolean
  isSandboxingEnabled(): boolean
  checkDependencies(ripgrepConfig?: {
    command: string
    args?: string[]
  }): SandboxDependencyCheck
  getFsReadConfig(): FsReadRestrictionConfig
  getFsWriteConfig(): FsWriteRestrictionConfig
  getNetworkRestrictionConfig(): NetworkRestrictionConfig
  getAllowUnixSockets(): string[] | undefined
  getAllowLocalBinding(): boolean | undefined
  getAllowMachLookup(): string[] | undefined
  getIgnoreViolations(): Record<string, string[]> | undefined
  getEnableWeakerNestedSandbox(): boolean | undefined
  getProxyPort(): number | undefined
  getProxyAuthToken(): string | undefined
  getSocksProxyPort(): number | undefined
  getLinuxHttpSocketPath(): string | undefined
  getLinuxSocksSocketPath(): string | undefined
  waitForNetworkInitialization(): Promise<boolean>
  wrapWithSandbox(
    command: string,
    binShell?: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
  ): Promise<string>
  wrapWithSandboxArgv(
    command: string,
    binShell?: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
  ): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }>
  getSandboxViolationStore(): SandboxViolationStore
  annotateStderrWithSandboxFailures(command: string, stderr: string): string
  getLinuxGlobPatternWarnings(): string[]
  getConfig(): SandboxRuntimeConfig | undefined
  getMitmCA(): MitmCA | undefined
  getSentinelRegistry(): SentinelRegistry
  getMaskedFileStore(): MaskedFileStore
  updateConfig(newConfig: SandboxRuntimeConfig): void
  cleanupAfterCommand(): void
  reset(): Promise<void>
}

// ============================================================================
// Export as Namespace with Interface
// ============================================================================

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  checkDependencies,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getAllowMachLookup,
  getIgnoreViolations,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getProxyAuthToken,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  wrapWithSandboxArgv,
  cleanupAfterCommand,
  reset,
  getMitmCA: () => mitmCA,
  getSentinelRegistry: () => sentinelRegistry,
  getMaskedFileStore: () => maskedFileStore,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
  getConfig,
  updateConfig,
} as const
