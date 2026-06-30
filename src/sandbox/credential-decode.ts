/**
 * Decoding support for encoded credential formats (`decode` on a
 * `credentials.files` entry). Currently JWT only.
 *
 * Pure helpers: the default extraction pattern for finding JWT candidates
 * in a file, and the verification predicate that confirms a candidate
 * actually is a JWT before it gets masked.
 */

/**
 * Default `extract` pattern for `decode: "jwt"` entries.
 *
 * A JWT's first segment is the base64url encoding of a JSON header that
 * starts `{"` (it always declares `alg`/`typ`), and base64url of `{"` is
 * `eyJ` — so every JWT starts with `eyJ`. Capture group 1 is the whole
 * three-segment token. The pattern over-matches (any eyJ-prefixed
 * base64url triple); {@link verifyJwt} filters the false positives.
 */
export const JWT_DEFAULT_EXTRACT_PATTERN =
  '(eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)'

/** Parse a base64url segment as JSON, or undefined if either step fails. */
function decodeSegment(segment: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))
  } catch {
    return undefined
  }
}

/**
 * True when `candidate` is structurally a JWT: three dot-separated
 * segments, the first two base64url-decoding to JSON, and the header
 * (segment 1) declaring an `alg` property.
 *
 * Used to filter extraction candidates before masking — a regex match
 * that fails this check (e.g. a random base64 blob the default pattern
 * over-matched) is left untouched rather than masked.
 */
export function verifyJwt(candidate: string): boolean {
  const parts = candidate.split('.')
  if (parts.length !== 3) return false
  const header = decodeSegment(parts[0]!)
  if (typeof header !== 'object' || header === null || !('alg' in header)) {
    return false
  }
  return decodeSegment(parts[1]!) !== undefined
}
