import { once } from 'node:events'
import { createServer, connect, type Server } from 'node:net'
import { afterEach, describe, expect, it } from 'bun:test'
import {
  createHttpProxyServer,
  type HttpProxyServerOptions,
} from '../../src/sandbox/http-proxy.js'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import type { AuthenticatedAttemptCredential } from '../../src/sandbox/sandbox-attempt-types.js'

const openServers = new Set<Server>()

afterEach(async () => {
  await Promise.all(
    [...openServers].map(
      server => new Promise<void>(resolve => server.close(() => resolve())),
    ),
  )
  openServers.clear()
})

function basic(token: string): string {
  return Buffer.from(`srt:${token}`).toString('base64')
}

async function listen(server: Server): Promise<number> {
  openServers.add(server)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return (server.address() as { port: number }).port
}

function exchange(port: number, payload: string | Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let settled = false
    const socket = connect(port, '127.0.0.1', () => socket.write(payload))
    const finish = (): void => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(Buffer.concat(chunks))
    }
    socket.on('data', chunk => {
      chunks.push(chunk)
      const bytes = Buffer.concat(chunks)
      if (
        bytes.toString().includes('\r\n\r\n') &&
        (bytes.toString().includes('407') ||
          bytes.toString().includes('403') ||
          bytes.toString().includes('502'))
      ) {
        finish()
      }
      if (bytes.length >= 14 && bytes[0] === 0x05) finish()
    })
    socket.on('close', finish)
    socket.on('error', reject)
    setTimeout(finish, 2_000).unref()
  })
}

function attemptRecorder(recorded: string[]): AuthenticatedAttemptCredential {
  return {
    recordNetworkDenial: source => recorded.push(source),
  }
}

describe('HTTP proxy attempt attribution', () => {
  async function startHttpProxy(
    recorded: string[],
    overrides: Partial<HttpProxyServerOptions> = {},
  ): Promise<number> {
    const attempt = attemptRecorder(recorded)
    const proxy = createHttpProxyServer({
      filter: () => false,
      proxyAuthToken: 'session-token',
      resolveAttemptProxyToken: token =>
        token === 'attempt-token' ? attempt : undefined,
      ...overrides,
    })
    return listen(proxy)
  }

  function connectRequest(token: string): string {
    return (
      'CONNECT denied.example:443 HTTP/1.1\r\n' +
      'Host: denied.example:443\r\n' +
      `Proxy-Authorization: Basic ${basic(token)}\r\n\r\n`
    )
  }

  it('records an allowlist denial only for an active attempt credential', async () => {
    const recorded: string[] = []
    const port = await startHttpProxy(recorded)

    expect(
      (await exchange(port, connectRequest('attempt-token'))).toString(),
    ).toContain('403 Forbidden')
    expect(recorded).toEqual(['http-proxy'])

    expect(
      (await exchange(port, connectRequest('session-token'))).toString(),
    ).toContain('403 Forbidden')
    expect(recorded).toEqual(['http-proxy'])

    expect(
      (await exchange(port, connectRequest('unknown-token'))).toString(),
    ).toContain('407 Proxy Authentication Required')
    expect(recorded).toEqual(['http-proxy'])
  })

  it('records plain-HTTP filter denials and thrown filters exactly once', async () => {
    const recorded: string[] = []
    const deniedPort = await startHttpProxy(recorded, {
      filter: () => true,
      filterRequest: async () => ({ action: 'deny', reason: 'blocked body' }),
    })
    const denied = await exchange(
      deniedPort,
      'GET http://example.invalid/path HTTP/1.1\r\n' +
        'Host: example.invalid\r\n' +
        `Proxy-Authorization: Basic ${basic('attempt-token')}\r\n` +
        'Connection: close\r\n\r\n',
    )
    expect(denied.toString()).toContain('403 Forbidden')
    expect(recorded).toEqual(['http-proxy'])

    const thrownPort = await startHttpProxy(recorded, {
      filter: () => true,
      filterRequest: async () => {
        throw new Error('policy failed')
      },
    })
    const thrown = await exchange(
      thrownPort,
      'GET http://example.invalid/path HTTP/1.1\r\n' +
        'Host: example.invalid\r\n' +
        `Proxy-Authorization: Basic ${basic('attempt-token')}\r\n` +
        'Connection: close\r\n\r\n',
    )
    expect(thrown.toString()).toContain('403 Forbidden')
    expect(recorded).toEqual(['http-proxy', 'http-proxy'])
  })

  it('does not record an allowed request whose upstream connection fails', async () => {
    const recorded: string[] = []
    const port = await startHttpProxy(recorded, { filter: () => true })
    const response = await exchange(
      port,
      'GET http://127.0.0.1:1/path HTTP/1.1\r\n' +
        'Host: 127.0.0.1:1\r\n' +
        `Proxy-Authorization: Basic ${basic('attempt-token')}\r\n` +
        'Connection: close\r\n\r\n',
    )

    expect(response.toString()).toContain('502 Bad Gateway')
    expect(recorded).toEqual([])
  })
})

describe('SOCKS proxy attempt attribution', () => {
  function socksRequest(options: {
    token?: string
    methods?: number[]
  }): Buffer {
    const methods = options.methods ?? (options.token ? [0x02] : [0x00])
    const greeting = Buffer.from([0x05, methods.length, ...methods])
    const auth = options.token
      ? Buffer.concat([
          Buffer.from([0x01, 0x03]),
          Buffer.from('srt'),
          Buffer.from([Buffer.byteLength(options.token)]),
          Buffer.from(options.token),
        ])
      : Buffer.alloc(0)
    const host = Buffer.from('denied.example')
    const request = Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
      host,
      Buffer.from([0x01, 0xbb]),
    ])
    return Buffer.concat([greeting, auth, request])
  }

  async function startSocksProxy(
    recorded: string[],
    allowUnauthenticated = false,
  ): Promise<{ port: number; close(): Promise<void> }> {
    const attempt = attemptRecorder(recorded)
    const proxy = createSocksProxyServer({
      filter: () => false,
      proxyAuthToken: 'session-token',
      resolveAttemptProxyToken: token =>
        token === 'attempt-token' ? attempt : undefined,
      allowUnauthenticated,
    })
    const front = createServer(socket => proxy.handleConnection(socket))
    const port = await listen(front)
    return {
      port,
      async close(): Promise<void> {
        await proxy.close()
      },
    }
  }

  it('records a denied authenticated attempt but not session or unknown credentials', async () => {
    const recorded: string[] = []
    const proxy = await startSocksProxy(recorded)
    try {
      const attempt = await exchange(
        proxy.port,
        socksRequest({ token: 'attempt-token' }),
      )
      expect(attempt.subarray(0, 4)).toEqual(
        Buffer.from([0x05, 0x02, 0x01, 0x00]),
      )
      expect(attempt[5]).toBe(0x02)
      expect(recorded).toEqual(['socks-proxy'])

      const session = await exchange(
        proxy.port,
        socksRequest({ token: 'session-token' }),
      )
      expect(session[5]).toBe(0x02)
      expect(recorded).toEqual(['socks-proxy'])

      const unknown = await exchange(
        proxy.port,
        socksRequest({ token: 'unknown-token' }),
      )
      expect(unknown.subarray(0, 4)).toEqual(
        Buffer.from([0x05, 0x02, 0x01, 0x01]),
      )
      expect(recorded).toEqual(['socks-proxy'])
    } finally {
      await proxy.close()
    }
  })

  it('prefers attributed auth when both methods are offered', async () => {
    const recorded: string[] = []
    const proxy = await startSocksProxy(recorded, true)
    try {
      const reply = await exchange(
        proxy.port,
        socksRequest({ token: 'attempt-token', methods: [0x00, 0x02] }),
      )
      expect(reply.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x02]))
      expect(recorded).toEqual(['socks-proxy'])
    } finally {
      await proxy.close()
    }
  })

  it('keeps unauthenticated compatibility traffic unattributed', async () => {
    const recorded: string[] = []
    const proxy = await startSocksProxy(recorded, true)
    try {
      const reply = await exchange(proxy.port, socksRequest({}))
      expect(reply.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x00]))
      expect(reply[3]).toBe(0x02)
      expect(recorded).toEqual([])
    } finally {
      await proxy.close()
    }
  })
})
