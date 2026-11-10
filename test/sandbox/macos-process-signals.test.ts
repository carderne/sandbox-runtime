import { describe, expect, it } from 'bun:test'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { createSandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'
import { isMacOS } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

describe.if(isMacOS)('macOS process signals', () => {
  // Catches: commands cannot stop an earlier process after opting in, or gain that permission by default.
  it('requires opt-in to terminate a process outside its sandbox', async () => {
    const manager = createSandboxManager()
    const target = spawn('/bin/sleep', ['60'], { stdio: 'ignore' })
    await once(target, 'spawn')
    const exited = once(target, 'exit')
    const config = SandboxRuntimeConfigSchema.parse({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    try {
      await manager.initialize(config)
      const signalTarget = async (allowProcessSignals?: boolean) => {
        const command = await manager.wrapWithSandbox(
          `/bin/kill -TERM ${target.pid}`,
          undefined,
          { allowProcessSignals },
        )
        try {
          return await spawnAsync(command, { timeout: 5000 })
        } finally {
          manager.cleanupAfterCommand()
        }
      }

      const denied = await signalTarget()
      expect(denied.status).not.toBe(0)
      expect(denied.stderr).toContain('Operation not permitted')
      expect(denied.stderr).toContain(String(target.pid))
      expect(target.signalCode).toBeNull()

      manager.updateConfig(
        SandboxRuntimeConfigSchema.parse({
          ...config,
          allowProcessSignals: true,
        }),
      )
      const overridden = await signalTarget(false)
      expect(overridden.status).not.toBe(0)
      expect(overridden.stderr).toContain('Operation not permitted')
      expect(overridden.stderr).toContain(String(target.pid))
      expect(target.signalCode).toBeNull()

      const allowed = await signalTarget()
      expect(allowed.status, allowed.stderr).toBe(0)
      expect((await exited)[1]).toBe('SIGTERM')
    } finally {
      if (target.exitCode === null && target.signalCode === null) {
        target.kill('SIGTERM')
      }
      await exited
      await manager.reset()
    }
  }, 15_000)
})
