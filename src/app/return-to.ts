const DEFAULT_RETURN_TO = '/account';

export function safeReturnTo(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/')) return DEFAULT_RETURN_TO;
  try {
    const url = new URL(value, 'https://app.invalid');
    if (url.origin !== 'https://app.invalid') return DEFAULT_RETURN_TO;
    // Dot-segment resolution can turn `/..//evil.com` into `//evil.com`, which browsers treat as protocol-relative.
    if (url.pathname.startsWith('//') || url.pathname.includes('\\')) return DEFAULT_RETURN_TO;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return DEFAULT_RETURN_TO;
  }
}
