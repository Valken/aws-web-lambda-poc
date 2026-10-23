import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CompactEncrypt, decodeProtectedHeader } from 'jose';
import { createHash } from 'node:crypto';
import {
  createSessionCookie,
  createTransactionCookie,
  pkceChallenge,
  randomUrlValue,
  readSessionCookie,
  readTransactionCookie,
  type OidcTransaction,
  type Session,
} from '../src/app/session.js';

const SECRET = 'test-session-secret';

const session: Session = {
  sub: 'user-123',
  email: 'person@example.com',
  name: 'Test Person',
  idToken: 'id.token.value',
  accessToken: 'access.token.value',
  expiresAt: 1_900_000_000_000,
};

const transaction: OidcTransaction = {
  state: 'state-value',
  nonce: 'nonce-value',
  verifier: 'verifier-value',
  returnTo: '/account',
};

// Flips one character in the given JWE segment (0 header, 2 IV, 3 ciphertext, 4 tag).
function tamper(cookie: string, segment: number): string {
  const parts = cookie.split('.');
  const value = parts[segment];
  const index = Math.floor(value.length / 2);
  parts[segment] = `${value.slice(0, index)}${value[index] === 'A' ? 'B' : 'A'}${value.slice(index + 1)}`;
  return parts.join('.');
}

describe('randomUrlValue', () => {
  it('returns 32 random bytes as unpadded base64url', () => {
    const value = randomUrlValue();
    assert.match(value, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(Buffer.from(value, 'base64url').length, 32);
  });

  it('does not repeat values', () => {
    const values = new Set(Array.from({ length: 100 }, randomUrlValue));
    assert.equal(values.size, 100);
  });
});

describe('pkceChallenge', () => {
  it('matches the RFC 7636 Appendix B S256 example', () => {
    assert.equal(pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});

describe('session cookie', () => {
  it('round-trips a session', async () => {
    const cookie = await createSessionCookie(session, SECRET);
    assert.deepEqual(await readSessionCookie(cookie, SECRET), session);
  });

  it('encrypts the payload with direct A256GCM', async () => {
    const cookie = await createSessionCookie(session, SECRET);
    assert.deepEqual(decodeProtectedHeader(cookie), { alg: 'dir', enc: 'A256GCM' });
    for (const value of [session.sub, session.email!, session.idToken, session.accessToken]) {
      assert.ok(!cookie.includes(value), `cookie leaks ${value}`);
      assert.ok(!cookie.includes(Buffer.from(value).toString('base64url')), `cookie leaks encoded ${value}`);
    }
  });

  it('uses a fresh IV for each cookie', async () => {
    const [first, second] = await Promise.all([createSessionCookie(session, SECRET), createSessionCookie(session, SECRET)]);
    assert.notEqual(first, second);
  });

  it('rejects a cookie sealed with a different secret', async () => {
    const cookie = await createSessionCookie(session, 'other-secret');
    assert.equal(await readSessionCookie(cookie, SECRET), undefined);
  });

  it('rejects a cookie with any tampered segment', async () => {
    const cookie = await createSessionCookie(session, SECRET);
    for (const segment of [0, 2, 3, 4]) {
      assert.equal(await readSessionCookie(tamper(cookie, segment), SECRET), undefined, `segment ${segment}`);
    }
  });

  it('returns undefined for missing or malformed values', async () => {
    for (const value of [undefined, '', 'not-a-jwe', 'a.b.c.d.e', 'a.b.c']) {
      assert.equal(await readSessionCookie(value, SECRET), undefined, String(value));
    }
  });

  it('returns undefined when a valid JWE does not contain JSON', async () => {
    const key = createHash('sha256').update(SECRET).digest();
    const cookie = await new CompactEncrypt(new TextEncoder().encode('not json'))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(key);
    assert.equal(await readSessionCookie(cookie, SECRET), undefined);
  });
});

describe('transaction cookie', () => {
  it('round-trips a transaction', async () => {
    const cookie = await createTransactionCookie(transaction, SECRET);
    assert.deepEqual(await readTransactionCookie(cookie, SECRET), transaction);
  });

  it('rejects a cookie sealed with a different secret', async () => {
    const cookie = await createTransactionCookie(transaction, 'other-secret');
    assert.equal(await readTransactionCookie(cookie, SECRET), undefined);
  });

  it('rejects a tampered cookie', async () => {
    const cookie = await createTransactionCookie(transaction, SECRET);
    assert.equal(await readTransactionCookie(tamper(cookie, 3), SECRET), undefined);
  });
});
