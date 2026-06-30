import { describe, test, expect } from 'bun:test'
import {
  isInjectHostCoveredByAllowedDomains,
  matchesDomainPattern,
} from '../../src/sandbox/domain-pattern.js'

describe('matchesDomainPattern', () => {
  test('exact match is case-insensitive', () => {
    expect(matchesDomainPattern('API.Example.com', 'api.example.com')).toBe(
      true,
    )
  })

  test('wildcard matches strict subdomains only', () => {
    expect(matchesDomainPattern('a.example.com', '*.example.com')).toBe(true)
    expect(matchesDomainPattern('a.b.example.com', '*.example.com')).toBe(true)
    expect(matchesDomainPattern('example.com', '*.example.com')).toBe(false)
    expect(matchesDomainPattern('notexample.com', '*.example.com')).toBe(false)
  })
})

// Generic "is this pattern fully covered by that pattern list" predicate.
// Used for injectHosts ⊆ allowedDomains and, since tlsTerminate
// excludeDomains, for "could this injectHost ever be injected".
describe('isInjectHostCoveredByAllowedDomains', () => {
  test('exact host covered by an exact entry or a wildcard', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', [
        'api.example.com',
      ]),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', ['*.example.com']),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', ['example.com']),
    ).toBe(false)
  })

  test('a wildcard is never covered by exact entries', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('*.example.com', [
        'api.example.com',
        'b.example.com',
      ]),
    ).toBe(false)
  })

  test('a wildcard is covered by an equal or ancestor wildcard only', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('*.api.example.com', [
        '*.example.com',
      ]),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('*.example.com', [
        '*.api.example.com',
      ]),
    ).toBe(false)
  })
})
