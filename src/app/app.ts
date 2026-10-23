import express, { type Express, type Request, type Response } from 'express';
import { parse, serialize } from 'cookie';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { AppConfig } from './config.js';
import { safeReturnTo } from './return-to.js';
import {
  COOKIE_NAME,
  TRANSACTION_COOKIE,
  TRANSACTION_TTL_SECONDS,
  createSessionCookie,
  createTransactionCookie,
  pkceChallenge,
  randomUrlValue,
  readSessionCookie,
  readTransactionCookie,
  type Session,
} from './session.js';

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
};

function cookies(request: Request): Record<string, string | undefined> {
  return parse(request.headers.cookie ?? '');
}

function html(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{font:16px system-ui;max-width:720px;margin:4rem auto;padding:0 1rem}a,button{font:inherit}button{padding:.5rem 1rem}</style></head><body>${body}</body></html>`;
}

function escapeHtml(value: string): string {
  const replacements: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return value.replace(/[&<>"']/g, (character) => replacements[character] ?? character);
}

async function discovery(issuer: string): Promise<{ authorization_endpoint: string; token_endpoint: string; jwks_uri: string; end_session_endpoint?: string }> {
  const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
  let response: globalThis.Response;
  try {
    response = await fetch(discoveryUrl);
  } catch (error) {
    const cause = error instanceof Error && error.cause instanceof Error ? ` (${error.cause.message})` : '';
    throw new Error(`OIDC discovery request failed for ${discoveryUrl}${cause}`);
  }
  if (!response.ok) throw new Error(`OIDC discovery failed with ${response.status}`);
  return response.json() as Promise<{ authorization_endpoint: string; token_endpoint: string; jwks_uri: string; end_session_endpoint?: string }>;
}

function setCookie(response: Response, name: string, value: string, maxAge?: number): void {
  response.append('Set-Cookie', serialize(name, value, { ...cookieOptions, ...(maxAge === undefined ? {} : { maxAge }) }));
}

function publicUrl(request: Request, pathname: string): string {
  const protocol = request.get('x-forwarded-proto') ?? request.protocol;
  const host = request.get('x-forwarded-host') ?? request.get('host');
  if (!host) throw new Error('Request did not include a host');
  return `${protocol}://${host}${pathname}`;
}

function clearCookie(response: Response, name: string): void {
  response.append('Set-Cookie', serialize(name, '', { ...cookieOptions, maxAge: 0 }));
}

async function currentSession(request: Request, response: Response, sessionSecret: string): Promise<Session | undefined> {
  const session = await readSessionCookie(cookies(request)[COOKIE_NAME], sessionSecret);
  if (session && (!Number.isFinite(session.expiresAt) || session.expiresAt <= Date.now())) {
    clearCookie(response, COOKIE_NAME);
    return undefined;
  }
  return session;
}

export function createApp(config: AppConfig): Express {
  const app = express();
  app.use(express.urlencoded({ extended: false }));

  app.get('/', async (_request, response) => {
    const session = await currentSession(_request, response, config.sessionSecret);
    response.type('html').send(html('Lambda Web Functions POC', `<h1>Lambda Web Functions POC</h1><p>Node.js SSR behind CloudFront with Cognito OIDC.</p>${session ? `<p>Signed in as <strong>${escapeHtml(session.email ?? session.sub)}</strong>.</p><p><a href="/account">View account</a></p><form method="post" action="/logout"><button>Sign out</button></form>` : '<p><a href="/login">Sign in with Cognito</a></p>'}`));
  });

  app.get('/login', async (request, response, next) => {
    try {
      const oidc = await discovery(config.issuer);
      const transaction = {
        state: randomUrlValue(),
        nonce: randomUrlValue(),
        verifier: randomUrlValue(),
        returnTo: safeReturnTo(request.query.returnTo),
      };
      setCookie(response, TRANSACTION_COOKIE, await createTransactionCookie(transaction, config.sessionSecret), TRANSACTION_TTL_SECONDS);
      const url = new URL(oidc.authorization_endpoint);
      url.search = new URLSearchParams({
        response_type: 'code',
        client_id: config.clientId,
        redirect_uri: publicUrl(request, '/oauth2/callback'),
        scope: 'openid email profile api/read api/write',
        state: transaction.state,
        nonce: transaction.nonce,
        code_challenge: pkceChallenge(transaction.verifier),
        code_challenge_method: 'S256',
      }).toString();
      response.redirect(url.toString());
    } catch (error) {
      next(error);
    }
  });

  app.get('/oauth2/callback', async (request, response, next) => {
    try {
      const transaction = await readTransactionCookie(cookies(request)[TRANSACTION_COOKIE], config.sessionSecret);
      const code = typeof request.query.code === 'string' ? request.query.code : undefined;
      const state = typeof request.query.state === 'string' ? request.query.state : undefined;
      if (!transaction || !code || state !== transaction.state) {
        response.status(400).type('html').send(html('Authentication error', '<h1>Invalid authentication response</h1><p>Restart the sign-in flow.</p>'));
        return;
      }
      const oidc = await discovery(config.issuer);
      const tokenResponse = await fetch(oidc.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: config.clientId,
          ...(config.clientSecret ? { client_secret: config.clientSecret } : {}),
          redirect_uri: publicUrl(request, '/oauth2/callback'),
          code,
          code_verifier: transaction.verifier,
        }),
      });
      if (!tokenResponse.ok) throw new Error(`Token exchange failed with ${tokenResponse.status}`);
      const tokens = await tokenResponse.json() as { id_token?: string; access_token?: string; expires_in?: number };
      if (!tokens.id_token || !tokens.access_token) throw new Error('Token response did not contain required tokens');
      const expiresIn = tokens.expires_in ?? 3600;
      const jwks = createRemoteJWKSet(new URL(oidc.jwks_uri));
      const verified = await jwtVerify(tokens.id_token, jwks, { issuer: config.issuer, audience: config.clientId });
      if (verified.payload.nonce !== transaction.nonce || typeof verified.payload.sub !== 'string') throw new Error('OIDC nonce or subject validation failed');
      const session: Session = {
        sub: verified.payload.sub,
        email: typeof verified.payload.email === 'string' ? verified.payload.email : undefined,
        name: typeof verified.payload.name === 'string' ? verified.payload.name : undefined,
        idToken: tokens.id_token,
        accessToken: tokens.access_token,
        expiresAt: Date.now() + expiresIn * 1000,
      };
      setCookie(response, COOKIE_NAME, await createSessionCookie(session, config.sessionSecret), expiresIn);
      clearCookie(response, TRANSACTION_COOKIE);
      response.redirect(safeReturnTo(transaction.returnTo));
    } catch (error) {
      next(error);
    }
  });

  app.get('/account', async (request, response) => {
    const session = await currentSession(request, response, config.sessionSecret);
    if (!session) {
      response.redirect(`/login?returnTo=${encodeURIComponent(request.originalUrl)}`);
      return;
    }
    response.type('html').send(html('Your account', `<h1>Your account</h1><dl><dt>Subject</dt><dd>${escapeHtml(session.sub)}</dd><dt>Email</dt><dd>${escapeHtml(session.email ?? 'Not provided')}</dd><dt>Name</dt><dd>${escapeHtml(session.name ?? 'Not provided')}</dd></dl><p><a href="/">Home</a></p><form method="post" action="/logout"><button>Sign out</button></form>`));
  });

  app.post('/logout', async (request, response, next) => {
    try {
      clearCookie(response, COOKIE_NAME);
      const url = new URL(`${config.authDomain}/logout`);
      url.search = new URLSearchParams({
        client_id: config.clientId,
        logout_uri: publicUrl(request, ''),
      }).toString();
      response.redirect(url.toString());
    } catch (error) {
      next(error);
    }
  });

  app.get('/health', (_request, response) => response.json({ status: 'ok' }));

  app.use((error: unknown, _request: Request, response: Response, _next: unknown) => {
    console.error(JSON.stringify({ level: 'error', message: error instanceof Error ? error.message : 'request failed' }));
    response.status(500).type('html').send(html('Server error', '<h1>Something went wrong</h1><p>Check the server logs for details.</p>'));
  });

  return app;
}
