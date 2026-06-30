import { describe, test, expect, afterAll } from 'bun:test'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const certPath = join(FIXTURE_DIR, 'ca.crt')
const keyPath = join(FIXTURE_DIR, 'ca.key')
const certPem = readFileSync(certPath, 'utf8')
const keyPem = readFileSync(keyPath, 'utf8')

describe('mitm-ca: createMitmCA', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'srt-mitm-ca-'))
  const junkPath = join(scratch, 'junk.txt')
  writeFileSync(junkPath, 'not pem\n')

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  test('returns parsed cert+key from a real CA', () => {
    const ca = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(ca.certPath).toBe(certPath)
    expect(ca.keyPath).toBe(keyPath)
    expect(ca.certPem).toBe(certPem)
    expect(ca.keyPem).toBe(keyPem)
    expect(ca.certPem).toContain('-----BEGIN CERTIFICATE-----')
    // openssl req -nodes emits PKCS8 ("PRIVATE KEY"); the loader's regex also
    // accepts PKCS1 "RSA PRIVATE KEY" / "EC PRIVATE KEY".
    expect(ca.keyPem).toMatch(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/)
    expect(ca.cert.subject.getField('CN').value).toContain('srt-test-ca')
    expect(ca.key.n).toBeDefined() // RSA modulus present
  })

  test('is a pure factory: each call returns a new instance', () => {
    const a = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    const b = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(b).not.toBe(a)
    expect(b.certPem).toBe(a.certPem)
  })

  test('throws with field+path+code when cert path is missing', () => {
    const missing = join(scratch, 'nope.crt')
    expect(() =>
      createMitmCA({ caCertPath: missing, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: cannot read .*nope\.crt \(ENOENT\)/)
  })

  test('throws with field+path+code when key path is missing', () => {
    const missing = join(scratch, 'nope.key')
    expect(() =>
      createMitmCA({ caCertPath: certPath, caKeyPath: missing }),
    ).toThrow(/tlsTerminate\.caKeyPath: cannot read .*nope\.key \(ENOENT\)/)
  })

  test('throws when cert file is not PEM', () => {
    expect(() =>
      createMitmCA({ caCertPath: junkPath, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: .* is not a PEM CERTIFICATE/)
  })

  test('throws when key file is not PEM', () => {
    expect(() =>
      createMitmCA({ caCertPath: certPath, caKeyPath: junkPath }),
    ).toThrow(/tlsTerminate\.caKeyPath: .* is not a PEM PRIVATE KEY/)
  })

  test('throws when cert and key are swapped', () => {
    expect(() =>
      createMitmCA({ caCertPath: keyPath, caKeyPath: certPath }),
    ).toThrow(/is not a PEM CERTIFICATE/)
  })
})

describe('mitm-ca: ephemeral generation', () => {
  test('createMitmCA({}) generates a CA, writes PEMs to a temp dir', async () => {
    const ca = createMitmCA({})
    try {
      expect(ca.ephemeral).toBe(true)
      expect(ca.certPath).toContain('srt-ca-')
      expect(readFileSync(ca.certPath, 'utf8')).toBe(ca.certPem)
      expect(readFileSync(ca.keyPath, 'utf8')).toBe(ca.keyPem)
      expect(ca.certPem).toContain('-----BEGIN CERTIFICATE-----')
      expect(ca.cert.subject.getField('CN').value).toBe(
        'sandbox-runtime ephemeral CA',
      )
      expect(ca.key.n).toBeDefined()
      // Can mint a leaf against it.
      const leaf = mintLeafCert(ca, 'example.com')
      expect(leaf.certPem).toContain('-----BEGIN CERTIFICATE-----')
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('disposeMitmCA removes the temp dir for ephemeral, no-ops for user CA', async () => {
    const eph = createMitmCA({})
    const dir = dirname(eph.certPath)
    expect(existsSync(dir)).toBe(true)
    await disposeMitmCA(eph)
    expect(existsSync(dir)).toBe(false)

    const user = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(user.ephemeral).toBe(false)
    await disposeMitmCA(user) // must not delete the fixture
    expect(existsSync(certPath)).toBe(true)
  })

  test('writes a trust bundle: MITM CA first, then the host root store', async () => {
    // The child's trust env vars (SSL_CERT_FILE etc.) REPLACE the tool's
    // root store, so the bundle must contain the system roots too or hosts
    // exempted from termination (tlsTerminate.excludeDomains) could never
    // be verified by the in-sandbox client.
    const ca = createMitmCA({})
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      expect(bundle.startsWith(ca.certPem.trim())).toBe(true)
      const certCount = bundle.match(/-----BEGIN CERTIFICATE-----/g)!.length
      expect(certCount).toBeGreaterThan(1)
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('disposeMitmCA removes the trust-bundle dir of a user-supplied CA', async () => {
    const user = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    const bundleDir = dirname(user.trustBundlePath)
    expect(bundleDir).not.toBe(dirname(certPath))
    expect(existsSync(user.trustBundlePath)).toBe(true)
    await disposeMitmCA(user)
    expect(existsSync(bundleDir)).toBe(false)
    expect(existsSync(certPath)).toBe(true) // fixture untouched
  })

  test('throws when only one of caCertPath/caKeyPath is provided', () => {
    expect(() => createMitmCA({ caCertPath: certPath })).toThrow(
      /must be provided together/,
    )
    expect(() => createMitmCA({ caKeyPath: keyPath })).toThrow(
      /must be provided together/,
    )
  })
})

describe('mitm-ca: extraCaCertPaths', () => {
  // A site-local root (e.g. an internal mTLS CA) that excluded/passthrough
  // hosts present. Reuse the committed fixture CA as a structurally real PEM.
  const scratch = mkdtempSync(join(tmpdir(), 'srt-extra-ca-'))
  const extraRootPath = join(scratch, 'extra-root.pem')
  writeFileSync(extraRootPath, certPem)
  const notACert = join(scratch, 'not-a-cert.pem')
  writeFileSync(
    notACert,
    '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
  )
  // Combined cert+key PEM — a common layout for "the CA file". Only the
  // CERTIFICATE block may reach the (world-readable) trust bundle.
  const combined = join(scratch, 'combined.pem')
  writeFileSync(combined, certPem + keyPem)

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  test('appends the PEM to the trust bundle (ephemeral CA path)', async () => {
    const ca = createMitmCA({ extraCaCertPaths: [extraRootPath] })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      // MITM CA still first; the extra root rides along at the end.
      expect(bundle.startsWith(ca.certPem.trim())).toBe(true)
      expect(bundle).toContain(certPem.trim())
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('appends the PEM on the user-supplied CA path too (loadCA)', async () => {
    const ca = createMitmCA({
      caCertPath: certPath,
      caKeyPath: keyPath,
      extraCaCertPaths: [extraRootPath],
    })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      // The fixture CA is both the MITM CA and the "extra" root here, so it
      // must appear twice: once as the bundle head, once appended.
      const occurrences = bundle.split(certPem.trim()).length - 1
      expect(occurrences).toBe(2)
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('skips missing paths without throwing', async () => {
    const ca = createMitmCA({
      extraCaCertPaths: [join(scratch, 'nope.pem'), extraRootPath],
    })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      // The missing path is skipped; later entries are still appended.
      expect(bundle).toContain(certPem.trim())
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('skips files with no PEM CERTIFICATE block', async () => {
    const ca = createMitmCA({ extraCaCertPaths: [notACert] })
    try {
      expect(readFileSync(ca.trustBundlePath, 'utf8')).not.toContain(
        'PRIVATE KEY',
      )
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('copies only the CERTIFICATE blocks of a combined cert+key file', async () => {
    // The trust bundle is world-readable and handed to the sandboxed child:
    // a private key sitting next to the cert must never reach it.
    const ca = createMitmCA({ extraCaCertPaths: [combined] })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      expect(bundle).toContain(certPem.trim())
      expect(bundle).not.toContain('PRIVATE KEY')
    } finally {
      await disposeMitmCA(ca)
    }
  })
})
