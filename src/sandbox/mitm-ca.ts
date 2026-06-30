/**
 * MITM CA loader/generator for the in-process TLS-terminating proxy.
 *
 * The CA is supplied via `network.tlsTerminate.{caCertPath,caKeyPath}` (see
 * sandbox-config.ts). If both paths are omitted, SRT generates an ephemeral
 * RSA-2048 self-signed CA into a temp directory; the cert path is what the
 * trust env vars point at. The caller is responsible for cleaning up via
 * `disposeMitmCA()` (SandboxManager.reset() does this).
 */

import forge from 'node-forge'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { rootCertificates, type SecureContext } from 'node:tls'
import { logForDebugging } from '../utils/debug.js'
import type { LeafCert } from './mitm-leaf.js'

const { pki, md, random, util } = forge

/**
 * Matches one PEM CERTIFICATE block. Used to extract just the certificates
 * out of files listed in tlsTerminate.extraCaCertPaths before they are
 * copied into the (world-readable) trust bundle.
 */
const PEM_CERT_BLOCK =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g

export type MitmCA = {
  certPath: string
  keyPath: string
  /**
   * PEM bundle the sandboxed child's trust env vars point at: this CA
   * followed by the host's regular roots (Node's bundled Mozilla store plus
   * the parent's NODE_EXTRA_CA_CERTS, if any) and any configured
   * tlsTerminate.extraCaCertPaths. Most of the per-tool vars
   * (SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, ...) REPLACE the
   * tool's trust store rather than extend it, so pointing them at the CA
   * alone would leave the child unable to verify any real certificate —
   * which matters for connections SRT does not terminate
   * (tlsTerminate.excludeDomains). Always lives in an SRT-owned temp dir.
   */
  trustBundlePath: string
  certPem: string
  keyPem: string
  /** Parsed CA certificate (issuer for minted leaf certs). */
  cert: forge.pki.Certificate
  /** Parsed CA private key. RSA only. */
  key: forge.pki.rsa.PrivateKey
  /** Per-hostname cache of leaf certs minted against this CA. */
  leafCerts: Map<string, LeafCert>
  /** Per-hostname cache of TLS SecureContexts wrapping the leaf certs. */
  secureContexts: Map<string, SecureContext>
  /**
   * True when SRT generated this CA into a temp directory. disposeMitmCA()
   * removes that directory; user-supplied CAs are left alone.
   */
  ephemeral: boolean
}

/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
export function createMitmCA(opts: {
  caCertPath?: string
  caKeyPath?: string
  /** PEM CA files appended to the trust bundle; unreadable paths skipped. */
  extraCaCertPaths?: string[]
}): MitmCA {
  if (opts.caCertPath && opts.caKeyPath) {
    return loadCA(opts.caCertPath, opts.caKeyPath, opts.extraCaCertPaths)
  }
  if (opts.caCertPath || opts.caKeyPath) {
    throw new Error(
      'tlsTerminate: caCertPath and caKeyPath must be provided together',
    )
  }
  return generateEphemeralCA(opts.extraCaCertPaths)
}

/**
 * Remove the SRT-owned temp directories for this CA: the trust-bundle dir
 * always, and the cert/key dir too when SRT generated the CA (for an
 * ephemeral CA they are the same directory). User-supplied CA files are
 * left alone.
 */
export async function disposeMitmCA(ca: MitmCA): Promise<void> {
  const dirs = new Set([dirname(ca.trustBundlePath)])
  if (ca.ephemeral) dirs.add(dirname(ca.certPath))
  for (const dir of dirs) {
    try {
      await rm(dir, { recursive: true, force: true })
    } catch (err) {
      logForDebugging(`[mitm-ca] cleanup failed: ${(err as Error).message}`, {
        level: 'warn',
      })
    }
  }
}

/**
 * Write the child-facing trust bundle into `dir` and return its path: the
 * MITM CA first, then the roots the host would normally trust, so HTTPS
 * clients in the sandbox accept proxy-minted leaves AND can still verify the
 * real certificate of any host SRT tunnels opaquely instead of terminating
 * (tlsTerminate.excludeDomains). Bundling Node's root store is best-effort
 * compatibility — a tool with its own CA file config is unaffected. Extra
 * roots from tlsTerminate.extraCaCertPaths go last, with the same append
 * semantics as NODE_EXTRA_CA_CERTS.
 */
function writeTrustBundle(
  dir: string,
  caCertPem: string,
  extraCaCertPaths?: string[],
): string {
  const parts = [caCertPem.trim(), ...rootCertificates]
  // Honour extra roots the parent process trusts (e.g. a corporate CA).
  const extra = process.env.NODE_EXTRA_CA_CERTS
  if (extra) {
    try {
      parts.push(readFileSync(extra, 'utf8').trim())
    } catch {
      // Missing/unreadable NODE_EXTRA_CA_CERTS: ignore, same as Node does.
    }
  }
  // Honour site-local roots from config (tlsTerminate.extraCaCertPaths),
  // e.g. an internal mTLS CA presented by excluded/passthrough hosts. Paths
  // may exist on only some hosts, so a missing file is skipped, not fatal —
  // but log it, or a typo'd path is undiagnosable.
  for (const extraPath of extraCaCertPaths ?? []) {
    let raw: string
    try {
      raw = readFileSync(extraPath, 'utf8')
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? String(err)
      logForDebugging(
        `[mitm-ca] extraCaCertPaths: cannot read ${extraPath} (${code}); ` +
          `skipping`,
        { level: 'warn' },
      )
      continue
    }
    // Append only the CERTIFICATE blocks. The bundle is world-readable
    // (0o644) and handed to the sandboxed child, so anything else the file
    // carries (e.g. the key of a combined cert+key PEM) must not be copied.
    const certs = raw.match(PEM_CERT_BLOCK)
    if (!certs) {
      logForDebugging(
        `[mitm-ca] extraCaCertPaths: ${extraPath} has no PEM CERTIFICATE ` +
          `block; skipping`,
        { level: 'warn' },
      )
      continue
    }
    parts.push(...certs)
  }
  const path = join(dir, 'trust-bundle.crt')
  writeFileSync(path, parts.join('\n') + '\n', { mode: 0o644 })
  return path
}

function loadCA(
  certPath: string,
  keyPath: string,
  extraCaCertPaths?: string[],
): MitmCA {
  const certPem = readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath')
  const keyPem = readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath')

  let cert: forge.pki.Certificate
  let key: forge.pki.PrivateKey
  try {
    cert = pki.certificateFromPem(certPem)
    key = pki.privateKeyFromPem(keyPem)
  } catch (err) {
    throw new Error(
      `tlsTerminate: failed to parse CA from ${certPath}: ` +
        (err as Error).message,
    )
  }
  if (!('n' in key) || !('d' in key)) {
    // node-forge can only sign with RSA private keys.
    throw new Error(`tlsTerminate.caKeyPath: CA key at ${keyPath} must be RSA`)
  }

  // The CA files are the user's; the trust bundle still needs an SRT-owned
  // directory of its own.
  const bundleDir = mkdtempSync(join(tmpdir(), 'srt-ca-'))
  const trustBundlePath = writeTrustBundle(bundleDir, certPem, extraCaCertPaths)

  logForDebugging(`[mitm-ca] loaded CA from ${certPath}`)
  return {
    certPath,
    keyPath,
    trustBundlePath,
    certPem,
    keyPem,
    cert,
    key: key as forge.pki.rsa.PrivateKey,
    leafCerts: new Map(),
    secureContexts: new Map(),
    ephemeral: false,
  }
}

function generateEphemeralCA(extraCaCertPaths?: string[]): MitmCA {
  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = randomSerial()
  cert.validity.notBefore = daysFromNow(-1)
  cert.validity.notAfter = daysFromNow(825)
  const subject = [
    { name: 'commonName', value: 'sandbox-runtime ephemeral CA' },
    { name: 'organizationName', value: 'sandbox-runtime' },
  ]
  cert.setSubject(subject)
  cert.setIssuer(subject)
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
    },
    { name: 'subjectKeyIdentifier' },
  ])
  cert.sign(keys.privateKey, md.sha256.create())

  const certPem = pki.certificateToPem(cert)
  const keyPem = pki.privateKeyToPem(keys.privateKey)

  // Write to disk so trust env vars (NODE_EXTRA_CA_CERTS etc.) can point at
  // a real path. mkdtemp gives us an unguessable per-process directory.
  const dir = mkdtempSync(join(tmpdir(), 'srt-ca-'))
  const certPath = join(dir, 'ca.crt')
  const keyPath = join(dir, 'ca.key')
  writeFileSync(certPath, certPem, { mode: 0o644 })
  writeFileSync(keyPath, keyPem, { mode: 0o600 })
  const trustBundlePath = writeTrustBundle(dir, certPem, extraCaCertPaths)

  logForDebugging(`[mitm-ca] generated ephemeral CA at ${certPath}`)
  return {
    certPath,
    keyPath,
    trustBundlePath,
    certPem,
    keyPem,
    cert,
    key: keys.privateKey,
    leafCerts: new Map(),
    secureContexts: new Map(),
    ephemeral: true,
  }
}

function readPem(path: string, label: string, field: string): string {
  let pem: string
  try {
    pem = readFileSync(path, 'utf8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? String(err)
    throw new Error(`${field}: cannot read ${path} (${code})`)
  }
  // Accept either the exact label or a prefixed variant (e.g. "RSA PRIVATE KEY",
  // "EC PRIVATE KEY") for the key case.
  if (!new RegExp(`-----BEGIN [A-Z ]*${label}-----`).test(pem)) {
    throw new Error(`${field}: ${path} is not a PEM ${label}`)
  }
  return pem
}

function randomSerial(): string {
  // 16 random bytes, high bit cleared so the DER INTEGER stays positive.
  const bytes = random.getBytesSync(16)
  const hex = util.bytesToHex(bytes)
  const firstNibble = parseInt(hex[0]!, 16) & 0x7
  return firstNibble.toString(16) + hex.slice(1)
}

function daysFromNow(days: number): Date {
  const d = new Date()
  d.setDate(d.getDate() + days)
  return d
}
