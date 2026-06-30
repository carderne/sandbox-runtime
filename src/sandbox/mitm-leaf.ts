/**
 * Per-host leaf certificate minter for the in-process TLS-terminating proxy.
 *
 * Given a MitmCA (see mitm-ca.ts), mints a leaf certificate for a specific
 * hostname on first use and caches it for the lifetime of that CA instance.
 * The leaf is signed by the CA and carries SAN=DNS:<host> (or IP:<addr>),
 * so a client that trusts the CA will accept it for that host.
 */

import forge from 'node-forge'
import { isIP } from 'node:net'
import { createSecureContext, type SecureContext } from 'node:tls'
import { logForDebugging } from '../utils/debug.js'
import type { MitmCA } from './mitm-ca.js'

const { pki, md, random, util } = forge

export type LeafCert = {
  /** Leaf cert PEM followed by the CA cert PEM (full chain). */
  certPem: string
  /** Leaf private key PEM. */
  keyPem: string
}

/**
 * Mint (or return cached) an RSA-2048 leaf cert for `hostname`, signed by `ca`.
 * The cache lives on `ca.leafCerts`.
 */
export function mintLeafCert(ca: MitmCA, hostname: string): LeafCert {
  const cached = ca.leafCerts.get(hostname)
  if (cached) return cached

  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = randomSerial()
  const notBefore = daysFromNow(-1)
  cert.validity.notBefore = notBefore
  cert.validity.notAfter = clampValidity(ca.cert, notBefore)
  cert.setSubject([{ name: 'commonName', value: hostname }])
  cert.setIssuer(ca.cert.subject.attributes)
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      digitalSignature: true,
      keyEncipherment: true,
    },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [sanFor(hostname)] },
    { name: 'subjectKeyIdentifier' },
    // Python ≥3.13 enables ssl.VERIFY_X509_STRICT by default, which enforces
    // RFC 5280's "AKI MUST be present on non-self-signed certs". curl/Go/Node
    // don't enforce this, but requests/urllib3/httpx/google-auth all reject
    // a leaf without AKI under 3.13. See caSubjectKeyId() for why we can't
    // just pass the CA's stored SKI value through.
    { name: 'authorityKeyIdentifier', keyIdentifier: caSubjectKeyId(ca.cert) },
  ])
  cert.sign(ca.key, md.sha256.create())

  const leaf: LeafCert = {
    certPem: pki.certificateToPem(cert) + ca.certPem,
    keyPem: pki.privateKeyToPem(keys.privateKey),
  }
  ca.leafCerts.set(hostname, leaf)
  logForDebugging(`[mitm-leaf] minted RSA leaf for ${hostname}`)
  return leaf
}

/**
 * Mint-or-cache a Node TLS SecureContext for `hostname`. Intended as the
 * SNICallback target in the terminating proxy. The cache lives on
 * `ca.secureContexts`.
 */
export function secureContextFor(ca: MitmCA, hostname: string): SecureContext {
  const cached = ca.secureContexts.get(hostname)
  if (cached) return cached
  const { certPem, keyPem } = mintLeafCert(ca, hostname)
  const ctx = createSecureContext({ cert: certPem, key: keyPem })
  ca.secureContexts.set(hostname, ctx)
  return ctx
}

/**
 * Return the CA's Subject Key Identifier as raw bytes for use as the leaf's
 * authorityKeyIdentifier.keyIdentifier.
 *
 * node-forge stores a cert's subjectKeyIdentifier extension value as a *hex
 * string* (both for in-memory certs and certs parsed from PEM), but expects
 * AKI's keyIdentifier as *raw bytes* — passing the hex through verbatim
 * encodes the ASCII hex chars as the key id and the chain fails to verify.
 * If the CA has no SKI extension (e.g. a v1 user-supplied CA), derive the
 * RFC 5280 method-1 value from its public key.
 */
function caSubjectKeyId(caCert: forge.pki.Certificate): string {
  const ext = caCert.getExtension('subjectKeyIdentifier') as
    | { subjectKeyIdentifier?: string }
    | undefined
  return ext?.subjectKeyIdentifier
    ? util.hexToBytes(ext.subjectKeyIdentifier)
    : caCert.generateSubjectKeyIdentifier().getBytes()
}

function sanFor(hostname: string): {
  type: number
  value?: string
  ip?: string
} {
  // RFC 5280 GeneralName tags: 2 = dNSName, 7 = iPAddress.
  return isIP(hostname) !== 0
    ? { type: 7, ip: hostname }
    : { type: 2, value: hostname }
}

/**
 * Leaf validity capped at min(CA notAfter, notBefore+99d).
 *
 * 99d sits below every TLS cert validity ceiling we care about: the current
 * (2026-03) CA/B baseline of 200d, the next step-down to 100d in 2027-03, the
 * historical 398d public cap, and the macOS ~825d ceiling that trips
 * errSecCertificateIsNotStandardsCompliant on user-installed roots. Leaves are
 * re-minted per session, so we don't need the headroom.
 *
 * Anchored at notBefore — not now — because notBefore is backdated by 1 day,
 * so `now+Nd` would produce an (N+1)-day span and lose a day of margin.
 */
function clampValidity(caCert: forge.pki.Certificate, notBefore: Date): Date {
  const caEnd = caCert.validity.notAfter
  const max = new Date(notBefore)
  max.setDate(max.getDate() + 99)
  return caEnd < max ? new Date(caEnd) : max
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
