import type { Socket } from 'net'
import { createServer } from '@pondwader/socks5-server'
import { logForDebugging } from '../utils/debug.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import type { AuthenticatedAttemptCredential } from './sandbox-attempt-types.js'
import {
  connectViaParentProxy,
  dialDirect,
  isValidHost,
  selectParentProxyUrl,
  shouldBypassParentProxy,
} from './parent-proxy.js'

export interface SocksProxyServerOptions {
  filter(port: number, host: string): Promise<boolean> | boolean

  /**
   * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
   * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
   * NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy

  /**
   * Per-session token (same value as the HTTP proxy's). When set, the
   * server requires SOCKS5 username/password auth and only accepts
   * user "srt" with this token as the password.
   */
  proxyAuthToken?: string

  /** Resolve an active per-attempt proxy credential for denial attribution. */
  resolveAttemptProxyToken?: (
    token: string,
  ) => AuthenticatedAttemptCredential | undefined

  /** Allow legacy SOCKS clients that do not offer username/password auth. */
  allowUnauthenticated?: boolean
}

export interface SocksProxyWrapper {
  /**
   * Hand an already-accepted socket to the SOCKS state machine. Used by the
   * mux front-end after first-byte sniffing. The socket must carry the full
   * SOCKS greeting starting at byte 0 (i.e. any peeked bytes already
   * `unshift()`ed back). Replicates the library's own accept path
   * (`setNoDelay()` + `_handleConnection`) and tracks the socket so
   * `close()` can force-destroy it.
   */
  handleConnection(socket: Socket): void
  /** Force-destroy all injected connections. */
  close(): Promise<void>
}

export function createSocksProxyServer(
  options: SocksProxyServerOptions,
): SocksProxyWrapper {
  const authenticatedServer = createServer()
  const unauthenticatedServer = createServer()
  const allowUnauthenticated =
    options.allowUnauthenticated ?? !options.proxyAuthToken
  const attemptByConnection = new WeakMap<
    object,
    AuthenticatedAttemptCredential
  >()

  authenticatedServer.setAuthHandler((conn, accept, deny) => {
    if (conn.username === 'srt') {
      if (conn.password === options.proxyAuthToken) {
        accept()
        return
      }
      const attempt = options.resolveAttemptProxyToken?.(conn.password)
      if (attempt) {
        attemptByConnection.set(conn, attempt)
        accept()
        return
      }
    }
    logForDebugging('SOCKS auth rejected', { level: 'error' })
    deny()
  })

  const validateRuleset = async (conn: {
    destAddress: string
    destPort: number
  }): Promise<boolean> => {
    try {
      const hostname = conn.destAddress
      const port = conn.destPort

      // SOCKS5 DOMAINNAME is a raw length-prefixed byte string with zero
      // validation from the protocol or the library. Reject control chars
      // (null bytes, CRLF) here so they never reach the allowlist matcher,
      // where string suffix matching would be trivially fooled.
      if (!isValidHost(hostname)) {
        logForDebugging(
          `Rejecting malformed SOCKS host: ${JSON.stringify(hostname)}`,
          { level: 'error' },
        )
        return false
      }

      logForDebugging(`Connection request to ${hostname}:${port}`)

      const allowed = await options.filter(port, hostname)

      if (!allowed) {
        attemptByConnection.get(conn)?.recordNetworkDenial('socks-proxy')
        logForDebugging(`Connection blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        return false
      }

      logForDebugging(`Connection allowed to ${hostname}:${port}`)
      return true
    } catch (error) {
      logForDebugging(`Error validating connection: ${error}`, {
        level: 'error',
      })
      return false
    }
  }

  authenticatedServer.setRulesetValidator(validateRuleset)
  unauthenticatedServer.setRulesetValidator(validateRuleset)

  // Override the default connection handler so we can route through a parent
  // HTTP proxy when one is configured. The default handler does a straight
  // net.connect() which fails when direct egress is blocked.
  type ConnectionHandler = Parameters<
    typeof authenticatedServer.setConnectionHandler
  >[0]
  const handleUpstreamConnection = (
    conn: Parameters<ConnectionHandler>[0],
    sendStatus: Parameters<ConnectionHandler>[1],
  ): void => {
    const host = conn.destAddress
    const port = conn.destPort

    // Track client liveness so we can abort the upstream dial if they bail.
    let clientGone = false
    let upstreamRef: Socket | undefined
    conn.socket.once('close', () => {
      clientGone = true
      upstreamRef?.destroy()
    })
    conn.socket.on('error', () => upstreamRef?.destroy())

    // SOCKS is an opaque TCP tunnel — semantically identical to HTTP
    // CONNECT — so always prefer HTTPS_PROXY if set, regardless of dest port.
    const parentUrl =
      options.parentProxy && !shouldBypassParentProxy(options.parentProxy, host)
        ? selectParentProxyUrl(options.parentProxy, { isHttps: true })
        : undefined

    const open = parentUrl
      ? connectViaParentProxy(parentUrl, host, port)
      : dialDirect(host, port)

    open
      .then(upstream => {
        upstreamRef = upstream
        upstream.on('error', () => conn.socket.destroy())
        if (clientGone) {
          upstream.destroy()
          return
        }
        sendStatus('REQUEST_GRANTED')
        upstream.pipe(conn.socket)
        conn.socket.pipe(upstream)
        upstream.on('close', () => conn.socket.destroy())
      })
      .catch(err => {
        logForDebugging(
          `SOCKS connect to ${host}:${port} failed: ${(err as Error).message}`,
          { level: 'error' },
        )
        if (!clientGone) {
          try {
            sendStatus('HOST_UNREACHABLE')
          } catch {
            // socket may have closed between the check and the write
          }
        }
      })
  }

  authenticatedServer.setConnectionHandler(handleUpstreamConnection)
  unauthenticatedServer.setConnectionHandler(handleUpstreamConnection)

  // Track every injected client socket so close() can tear them down
  // immediately. A SOCKS connection mid-`dialDirect()` (30s timeout) or
  // mid-relay would otherwise hold reset() open past bun's test timeout.
  // The library's internal net.Server is never .listen()ed — the mux owns
  // accept — so there's no listener to close; we only destroy sockets.
  const openSockets = new Set<Socket>()

  return {
    handleConnection(socket: Socket): void {
      socket.setNoDelay()
      openSockets.add(socket)
      socket.once('close', () => openSockets.delete(socket))
      void routeGreeting(
        socket,
        authenticatedServer,
        unauthenticatedServer,
        allowUnauthenticated,
      )
    },
    async close(): Promise<void> {
      for (const socket of openSockets) socket.destroy()
      openSockets.clear()
    },
  }
}

type SocksServer = ReturnType<typeof createServer>

const GREETING_TIMEOUT_MS = 2_000

async function routeGreeting(
  socket: Socket,
  authenticatedServer: SocksServer,
  unauthenticatedServer: SocksServer,
  allowUnauthenticated: boolean,
): Promise<void> {
  const greeting = await readGreeting(socket)
  if (!greeting) return
  socket.pause()
  socket.unshift(greeting)

  if (greeting[0] !== 0x05) {
    authenticatedServer._handleConnection(socket)
    return
  }

  const methodCount = greeting[1]!
  const methods = greeting.subarray(2, 2 + methodCount)
  if (methods.includes(0x02)) {
    authenticatedServer._handleConnection(socket)
  } else if (allowUnauthenticated && methods.includes(0x00)) {
    unauthenticatedServer._handleConnection(socket)
  } else {
    socket.write(Buffer.from([0x05, 0xff]))
    socket.destroy()
  }
}

function readGreeting(socket: Socket): Promise<Buffer | undefined> {
  return new Promise(resolve => {
    let buffered = Buffer.alloc(0)
    const timer = setTimeout(() => {
      socket.destroy()
      done()
    }, GREETING_TIMEOUT_MS)
    timer.unref()

    const done = (value?: Buffer): void => {
      clearTimeout(timer)
      socket.removeListener('data', onData)
      socket.removeListener('close', onClose)
      socket.removeListener('error', onClose)
      socket.pause()
      resolve(value)
    }
    const onClose = (): void => done()
    const onData = (chunk: Buffer): void => {
      buffered = Buffer.concat([buffered, chunk])
      if (buffered.length < 1) return
      if (buffered[0] !== 0x05) return done(buffered)
      if (buffered.length < 2) return
      const methodCount = buffered[1]!
      if (methodCount === 0 || methodCount > 128) return done(buffered)
      if (buffered.length >= 2 + methodCount) done(buffered)
    }

    socket.on('data', onData)
    socket.once('close', onClose)
    socket.once('error', onClose)
    socket.resume()
  })
}
