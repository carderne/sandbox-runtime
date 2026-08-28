import { generateProxyEnvVars } from './sandbox-utils.js'

export function buildSandboxAttemptEnvironment(options: {
  env?: NodeJS.ProcessEnv
  sandboxHttpProxyPort?: number
  sandboxSocksProxyPort?: number
  runtimeOwnsHttpProxy: boolean
  runtimeOwnsSocksProxy: boolean
  attemptProxyToken: string
  legacySshProxyToken?: string
  caCertPath?: string
  skipTmpdir?: boolean
}): NodeJS.ProcessEnv {
  const tokens = {
    http: options.runtimeOwnsHttpProxy ? options.attemptProxyToken : undefined,
    socks: options.runtimeOwnsSocksProxy
      ? options.attemptProxyToken
      : undefined,
    ssh: options.runtimeOwnsHttpProxy ? options.legacySshProxyToken : undefined,
  }
  const assignments = generateProxyEnvVars(
    options.sandboxHttpProxyPort,
    options.sandboxSocksProxyPort,
    options.caCertPath,
    tokens,
    options.skipTmpdir,
  )
  const overlay: NodeJS.ProcessEnv = {}
  for (const assignment of assignments) {
    const equals = assignment.indexOf('=')
    if (equals >= 0) {
      overlay[assignment.slice(0, equals)] = assignment.slice(equals + 1)
    }
  }
  return { ...(options.env ?? process.env), ...overlay }
}
