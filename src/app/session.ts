import { createHash, randomBytes } from 'node:crypto';
import { CompactEncrypt, compactDecrypt } from 'jose';

const COOKIE_NAME = 'web_session';
const TRANSACTION_COOKIE = 'oidc_transaction';

function key(secret: string): Uint8Array {
  return createHash('sha256').update(secret).digest();
}

async function seal(value: unknown, secret: string): Promise<string> {
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(value)))
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .encrypt(key(secret));
}

async function unseal<T>(value: string | undefined, secret: string): Promise<T | undefined> {
  if (!value) return undefined;
  try {
    const { plaintext } = await compactDecrypt(value, key(secret));
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    return undefined;
  }
}

export interface Session {
  sub: string;
  email?: string;
  name?: string;
  idToken: string;
  accessToken: string;
  expiresAt: number;
}

export interface OidcTransaction {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

export function randomUrlValue(): string {
  return randomBytes(32).toString('base64url');
}

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export async function createSessionCookie(session: Session, secret: string): Promise<string> {
  return seal(session, secret);
}

export async function readSessionCookie(value: string | undefined, secret: string): Promise<Session | undefined> {
  return unseal<Session>(value, secret);
}

export async function createTransactionCookie(transaction: OidcTransaction, secret: string): Promise<string> {
  return seal(transaction, secret);
}

export async function readTransactionCookie(value: string | undefined, secret: string): Promise<OidcTransaction | undefined> {
  return unseal<OidcTransaction>(value, secret);
}

export { COOKIE_NAME, TRANSACTION_COOKIE };
