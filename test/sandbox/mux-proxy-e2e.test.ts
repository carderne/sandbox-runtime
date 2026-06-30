import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { connect, type Socket } from 'node:net'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

/**
 * End-to-end: SandboxManager.initialize() starts the mux, then we drive
 * both protocols against the SAME port and check the real HTTP/SOCKS
 * backends respond. Runs on all platforms; on Windows the HTTP backend
 * uses a localhost TCP port inside the WFP range, elsewhere a unix
 * socket. Uses a denied host so no real egress happens — the test only
 * needs to see the protocol-correct refusal.
 */
describe('mux-proxy end-to-end via SandboxManager', () => {
  let port: number
  let authToken: string

  beforeAll(async () => {
    const config: SandboxRuntimeConfig = {
      network: {
        // Nothing allowed — we only assert the protocol-level response,
        // never the upstream dial.
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }
    await SandboxManager.initialize(config)
    port = SandboxManager.getProxyPort()!
    // The proxy requires auth; SandboxManager exposes the token for the
    // env-var builder, so reuse that.
    authToken = SandboxManager.getProxyAuthToken()!
    expect(SandboxManager.getSocksProxyPort()).toBe(port)
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  function exchange(
    write: (sock: Socket) => void,
    doneWhen: (buf: Buffer) => boolean,
  ): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = []
      const c = connect(port, '127.0.0.1', () => write(c))
      const finish = (): void => {
        c.destroy()
        resolve(Buffer.concat(chunks))
      }
      c.on('data', d => {
        chunks.push(d)
        if (doneWhen(Buffer.concat(chunks))) finish()
      })
      c.on('close', finish)
      c.on('error', reject)
      setTimeout(finish, 4_000).unref()
    })
  }

  it('HTTP CONNECT to a denied host returns 403 from the real http-proxy', async () => {
    const basic = Buffer.from(`srt:${authToken}`).toString('base64')
    const reply = await exchange(
      c =>
        c.write(
          `CONNECT denied.example:443 HTTP/1.1\r\n` +
            `Host: denied.example:443\r\n` +
            `Proxy-Authorization: Basic ${basic}\r\n\r\n`,
        ),
      buf => buf.toString().includes('\r\n\r\n'),
    )
    expect(reply.toString()).toMatch(/^HTTP\/1\.1 403 /)
  })

  it('HTTP CONNECT without auth returns 407 from the real http-proxy', async () => {
    const reply = await exchange(
      c =>
        c.write(
          `CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n`,
        ),
      buf => buf.toString().includes('\r\n\r\n'),
    )
    expect(reply.toString()).toMatch(/^HTTP\/1\.1 407 /)
  })

  it('SOCKS5 greeting on the same port gets a SOCKS method-select reply', async () => {
    // Offer user/pass (0x02); server should select it: [0x05, 0x02].
    const reply = await exchange(
      c => c.write(Buffer.from([0x05, 0x01, 0x02])),
      buf => buf.length >= 2,
    )
    expect(reply.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x02]))
  })

  it('SOCKS5 full handshake to a denied host returns CONNECTION_NOT_ALLOWED', async () => {
    const reply = await exchange(
      c => {
        // Greeting: VER=5, NMETHODS=1, METHODS=[user/pass]
        c.write(Buffer.from([0x05, 0x01, 0x02]))
        // Auth: VER=1, ULEN=3, "srt", PLEN, token
        const tok = Buffer.from(authToken)
        c.write(
          Buffer.concat([
            Buffer.from([0x01, 3]),
            Buffer.from('srt'),
            Buffer.from([tok.length]),
            tok,
          ]),
        )
        // CONNECT: VER=5, CMD=1, RSV=0, ATYP=3(domain), len, host, port
        const host = Buffer.from('denied.example')
        c.write(
          Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
            host,
            Buffer.from([0x01, 0xbb]), // 443
          ]),
        )
      },
      // method-select(2) + auth-status(2) + connect-reply(>=7)
      buf => buf.length >= 2 + 2 + 7,
    )
    // [0..1] method-select: 05 02
    expect(reply.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x02]))
    // [2..3] auth status: 01 00 (success)
    expect(reply.subarray(2, 4)).toEqual(Buffer.from([0x01, 0x00]))
    // [4] VER=5, [5] REP — 0x02 = connection not allowed by ruleset
    expect(reply[4]).toBe(0x05)
    expect(reply[5]).toBe(0x02)
  })
})
