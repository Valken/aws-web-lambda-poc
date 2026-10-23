import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { safeReturnTo } from '../src/app/return-to.js';

describe('safeReturnTo', () => {
  it('keeps same-origin paths with query and hash', () => {
    assert.equal(safeReturnTo('/account'), '/account');
    assert.equal(safeReturnTo('/orders/42?tab=items#top'), '/orders/42?tab=items#top');
    assert.equal(safeReturnTo('/a/../account'), '/account');
  });

  it('falls back to /account for missing or non-path values', () => {
    for (const value of [undefined, null, 42, ['/account'], '', 'account', 'https://evil.com', 'javascript:alert(1)']) {
      assert.equal(safeReturnTo(value), '/account', String(value));
    }
  });

  it('rejects protocol-relative and backslash redirects', () => {
    for (const value of ['//evil.com', '/\\evil.com', '/\\/evil.com', '///evil.com']) {
      assert.equal(safeReturnTo(value), '/account', value);
    }
  });

  it('rejects paths that normalize to a protocol-relative URL', () => {
    for (const value of ['/..//evil.com', '/a/..//evil.com', '/.//evil.com', '/%2e%2e//evil.com', '/%2E%2E//evil.com']) {
      assert.equal(safeReturnTo(value), '/account', value);
    }
  });
});
