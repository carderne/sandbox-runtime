import { describe, expect, it } from 'bun:test'
import { equal, rejects } from 'node:assert/strict'
import { createServer, request } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  createSandboxManager,
  SandboxManager,
  type ISandboxManager,
} from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

const config: SandboxRuntimeConfig = {
  network: { allowedDomains: ['127.0.0.1'], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
}

function throughProxy(manager: ISandboxManager, originPort: number) {
  return new Promise<{ status: number | undefined; body: string }>(
    (resolve, reject) => {
      const token = manager.getProxyAuthToken()
      const req = request(
        {
          host: '127.0.0.1',
          port: manager.getProxyPort(),
          path: `http://127.0.0.1:${originPort}/`,
          headers: {
            'Proxy-Authorization': `Basic ${Buffer.from(`srt:${token}`).toString('base64')}`,
          },
        },
        res => {
          let body = ''
          res.on('data', chunk => {
            body += chunk.toString()
          })
          res.on('error', reject)
          res.on('end', () => resolve({ status: res.statusCode, body }))
        },
      )
      req.on('error', reject)
      req.end()
    },
  )
}

describe('independent sandbox managers', () => {
  it.if(isLinux || isMacOS)(
    'isolates policies and survives another session shutting down',
    async () => {
      const parent = createSandboxManager()
      const child = createSandboxManager()
      const origin = createServer((_req, res) => res.end('ok'))
      await new Promise<void>(resolve => origin.listen(0, '127.0.0.1', resolve))
      const originPort = (origin.address() as AddressInfo).port
      try {
        await Promise.all([
          parent.initialize(config),
          child.initialize({
            ...config,
            network: { allowedDomains: [], deniedDomains: [] },
          }),
          SandboxManager.initialize(config),
        ])
        const port = parent.getProxyPort()
        expect(port).not.toBe(child.getProxyPort())
        expect(port).not.toBe(SandboxManager.getProxyPort())
        expect(parent.getProxyAuthToken()).not.toBe(child.getProxyAuthToken())
        expect(await throughProxy(parent, originPort)).toEqual({
          status: 200,
          body: 'ok',
        })
        expect((await throughProxy(child, originPort)).status).toBe(403)

        child.updateConfig({
          ...config,
          filesystem: { ...config.filesystem, allowWrite: ['/tmp/child-only'] },
        })
        expect(await throughProxy(child, originPort)).toEqual({
          status: 200,
          body: 'ok',
        })
        expect(parent.getConfig()?.filesystem.allowWrite).toEqual([])
        child.updateConfig({
          ...config,
          network: { allowedDomains: [], deniedDomains: [] },
        })
        expect((await throughProxy(child, originPort)).status).toBe(403)
        expect((await throughProxy(parent, originPort)).status).toBe(200)

        const wrapped = await parent.wrapWithSandbox('printf parent-survived')
        await Promise.all([child.reset(), SandboxManager.reset()])
        expect(parent.getProxyPort()).toBe(port)
        expect(await throughProxy(parent, originPort)).toEqual({
          status: 200,
          body: 'ok',
        })
        try {
          const result = await spawnAsync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 5000,
          })
          equal(result.status, 0, result.stderr)
          expect(result.stdout).toBe('parent-survived')
        } finally {
          parent.cleanupAfterCommand()
        }
        await rejects(
          child.wrapWithSandbox('true'),
          /network proxy is not initialized/,
        )
        await child.initialize(config)
        expect(parent.getProxyPort()).toBe(port)
        expect(child.getProxyPort()).not.toBe(port)
      } finally {
        await Promise.all([
          parent.reset(),
          child.reset(),
          SandboxManager.reset(),
        ])
        origin.closeAllConnections()
        await new Promise<void>(resolve => origin.close(() => resolve()))
      }
    },
    15_000,
  )

  it.if(isLinux || isMacOS)(
    'waits for initialization during teardown and releases process listeners',
    async () => {
      const manager = createSandboxManager()
      const before = ['exit', 'SIGINT', 'SIGTERM'].map(event =>
        process.listenerCount(event),
      )
      const starting = manager.initialize(config)
      const stopping = manager.reset()
      await Promise.all([starting, stopping, manager.reset()])
      expect(manager.getProxyPort()).toBeUndefined()
      expect(
        ['exit', 'SIGINT', 'SIGTERM'].map(event =>
          process.listenerCount(event),
        ),
      ).toEqual(before)
      try {
        await manager.initialize(config)
        expect(manager.getProxyPort()).toBeDefined()
      } finally {
        await manager.reset()
      }
    },
    15_000,
  )

  it.if(isWindows)(
    'fails closed until Windows ACL ownership can support independent managers',
    async () => {
      await rejects(
        createSandboxManager().initialize(config),
        /Use SandboxManager on Windows/,
      )
    },
  )
})
