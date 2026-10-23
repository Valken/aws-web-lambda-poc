const DEFAULT_RETURN_TO = '/account';
// Keeps the sealed transaction cookie well under the browser's ~4KB cookie limit.
const MAX_RETURN_TO_LENGTH = 1024;

export function safeReturnTo(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > MAX_RETURN_TO_LENGTH) return DEFAULT_RETURN_TO;
  try {
    // The parser treats `\` as `/` here, so `/\evil.com` fails the origin check.
    const url = new URL(value, 'https://app.invalid');
    if (url.origin !== 'https://app.invalid') return DEFAULT_RETURN_TO;
    // Dot-segment resolution can turn `/..//evil.com` into `//evil.com`, which browsers treat as protocol-relative.
    if (url.pathname.startsWith('//')) return DEFAULT_RETURN_TO;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return DEFAULT_RETURN_TO;
  }
}
