import { afterAll, beforeAll, describe, it } from 'bun:test'
import * as fc from 'fast-check'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
} from '../../src/sandbox/sandbox-utils.js'
import {
  expandWindowsFsDenyPaths,
  wrapCommandWithSandboxWindows,
} from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * Property tests for the Windows path-normalisation pipeline and
 * the env scrub. These pin the case-fold and glob/literal-divergence
 * invariants generically (regression coverage for past bugs in this
 * layer). Pure-JS — runs on every CI leg.
 */

describe('property: stripExtendedPathPrefix', () => {
  it('UNC marker is case-fold-stable', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('UNC', 'Unc', 'unc', 'uNc', 'uNC', 'UnC'),
        fc
          .string({ minLength: 1, maxLength: 40 })
          .filter(s => !s.startsWith('\\')),
        (casing, tail) => {
          const ref = stripExtendedPathPrefix(`\\\\?\\UNC\\${tail}`)
          const got = stripExtendedPathPrefix(`\\\\?\\${casing}\\${tail}`)
          return got === ref && got === `\\\\${tail}`
        },
      ),
    )
  })

  it('non-UNC `\\\\?\\` strip is invariant in the residue', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('C', 'c', 'D', 'z'),
        fc.string({ minLength: 0, maxLength: 40 }),
        (drive, tail) => {
          const p = `\\\\?\\${drive}:\\${tail}`
          return stripExtendedPathPrefix(p) === `${drive}:\\${tail}`
        },
      ),
    )
  })
})

describe('property: containsGlobCharsWin', () => {
  it('true ⇔ contains `*` or `?`', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 60 }), s => {
        const want = s.includes('*') || s.includes('?')
        return containsGlobCharsWin(s) === want
      }),
    )
  })
})

describe('property: env scrub', () => {
  // Random casing of an ASCII identifier.
  const recase = (s: string, seed: number): string =>
    [...s]
      .map((ch, i) =>
        (seed >> i % 30) & 1 ? ch.toUpperCase() : ch.toLowerCase(),
      )
      .join('')

  it('unsetEnvVars scrubs every casing', () => {
    const ident = fc
      .string({ minLength: 1, maxLength: 12 })
      .map(s => s.replace(/[^A-Za-z0-9_]/g, '') || 'X')
      .map(s => (/^[A-Za-z_]/.test(s) ? s : 'X' + s))
    fc.assert(
      fc.property(
        fc.uniqueArray(ident, { minLength: 1, maxLength: 6 }),
        fc.integer(),
        (names, seed) => {
          const prevSrt = process.env.SRT_WIN_PATH
          process.env.SRT_WIN_PATH = process.execPath
          // Plant each name in a random casing.
          const planted: string[] = []
          for (const [i, n] of names.entries()) {
            const k = recase(n, seed + i)
            process.env[k] = 'x'
            planted.push(k)
          }
          try {
            const { env } = wrapCommandWithSandboxWindows({
              command: 'echo',
              group: { groupName: 'g' },
              unsetEnvVars: names,
            })
            const upper = new Set(names.map(n => n.toUpperCase()))
            return Object.keys(env).every(k => !upper.has(k.toUpperCase()))
          } finally {
            for (const k of planted) delete process.env[k]
            if (prevSrt === undefined) delete process.env.SRT_WIN_PATH
            else process.env.SRT_WIN_PATH = prevSrt
          }
        },
      ),
    )
  })
})

describe('property: expandWindowsFsDenyPaths', () => {
  let scratch: string
  const files: string[] = []

  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), 'srt-prop-'))
    for (let i = 0; i < 5; i++) {
      const f = join(scratch, `f${i}.txt`)
      writeFileSync(f, String(i))
      files.push(f)
    }
  })

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  it('idempotent: f(f(xs)) == f(xs)', () => {
    // Catches normalize-divergence between the literal and glob
    // branches generically — feeding the output back in must
    // round-trip.
    fc.assert(
      fc.property(fc.subarray(files, { minLength: 1 }), subset => {
        const once = expandWindowsFsDenyPaths(subset)
        const twice = expandWindowsFsDenyPaths(once)
        return (
          once.length === twice.length &&
          new Set(once).size === once.length &&
          once.every(p => twice.includes(p))
        )
      }),
    )
  })
})
