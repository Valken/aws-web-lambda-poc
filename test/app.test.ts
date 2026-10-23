import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, afterEach, before, beforeEach, describe, it, mock } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWTPayload } from 'jose';
import { createApp } from '../src/app/app.js';
import type { AppConfig } from '../src/app/config.js';
import {
  COOKIE_NAME,
  TRANSACTION_COOKIE,
  createSessionCookie,
  createTransactionCookie,
  pkceChallenge,
  readSessionCookie,
  readTransactionCookie,
  type OidcTransaction,
  type Session,
} from '../src/app/session.js';

const SECRET = 'test-session-secret';
const CLIENT_ID = 'test-client';
const CLIENT_SECRET = 'test-client-secret';
const AUTH_DOMAIN = 'https://auth.example.test';

interface TokenReply {
  status: number;
  body: unknown;
}

// Minimal stand-in for Cognito: discovery document, JWKS and a scriptable token endpoint.
class FakeProvider {
  issuer = '';
  tokenRequests: URLSearchParams[] = [];
  tokenReply: () => Promise<TokenReply> = async () => ({ status: 500, body: {} });
  private server?: Server;
  private privateKey?: CryptoKey;
  private jwks: unknown;

  async start(): Promise<void> {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    this.privateKey = privateKey;
    this.jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }] };
    this.server = createServer(async (request, response) => {
      const send = (status: number, body: unknown) => {
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(JSON.stringify(body));
      };
      if (request.url === '/.well-known/openid-configuration') {
        send(200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/oauth2/authorize`,
          token_endpoint: `${this.issuer}/oauth2/token`,
          jwks_uri: `${this.issuer}/jwks`,
        });
      } else if (request.url === '/jwks') {
        send(200, this.jwks);
      } else if (request.url === '/oauth2/token' && request.method === 'POST') {
        let body = '';
        for await (const chunk of request) body += chunk;
        this.tokenRequests.push(new URLSearchParams(body));
        const reply = await this.tokenReply();
        send(reply.status, reply.body);
      } else {
        send(404, {});
      }
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    this.issuer = `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
  }

  async idToken(claims: JWTPayload, options: { issuer?: string; audience?: string; expiresIn?: string; key?: CryptoKey } = {}): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(options.issuer ?? this.issuer)
      .setAudience(options.audience ?? CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime(options.expiresIn ?? '5m')
      .sign(options.key ?? this.privateKey!);
  }

  async stop(): Promise<void> {
    await new Promise((resolve) => this.server?.close(resolve));
  }
}

async function listen(config: AppConfig): Promise<{ base: string; close: () => Promise<void> }> {
  const server = createApp(config).listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

function setCookies(response: globalThis.Response): Map<string, { value: string; attributes: string }> {
  const result = new Map<string, { value: string; attributes: string }>();
  for (const header of response.headers.getSetCookie()) {
    const [pair, ...attributes] = header.split(';');
    const index = pair.indexOf('=');
    result.set(pair.slice(0, index), { value: decodeURIComponent(pair.slice(index + 1)), attributes: attributes.join(';').trim() });
  }
  return result;
}

function validSession(overrides: Partial<Session> = {}): Session {
  return {
    sub: 'user-123',
    email: 'person@example.com',
    name: 'Test Person',
    idToken: 'id-token',
    accessToken: 'access-token',
    expiresAt: Date.now() + 60_000,
    ...overrides,
  };
}

describe('web app routes', () => {
  const provider = new FakeProvider();
  let app: { base: string; close: () => Promise<void> };
  let consoleError: ReturnType<typeof mock.method>;

  before(async () => {
    await provider.start();
    app = await listen({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      issuer: provider.issuer,
      authDomain: AUTH_DOMAIN,
      sessionSecret: SECRET,
      host: '127.0.0.1',
      port: 0,
    });
  });

  after(async () => {
    await app.close();
    await provider.stop();
  });

  beforeEach(() => {
    provider.tokenRequests = [];
    consoleError = mock.method(console, 'error', () => {});
  });

  afterEach(() => mock.restoreAll());

  function request(path: string, init: { cookies?: Record<string, string>; method?: string; headers?: Record<string, string> } = {}) {
    const cookie = Object.entries(init.cookies ?? {}).map(([name, value]) => `${name}=${value}`).join('; ');
    return fetch(`${app.base}${path}`, {
      method: init.method ?? 'GET',
      redirect: 'manual',
      headers: { ...(cookie ? { cookie } : {}), ...init.headers },
    });
  }

  async function sessionCookie(session: Session): Promise<Record<string, string>> {
    return { [COOKIE_NAME]: await createSessionCookie(session, SECRET) };
  }

  async function startLogin(returnTo?: string): Promise<{ location: URL; cookie: string; transaction: OidcTransaction }> {
    const response = await request(`/login${returnTo === undefined ? '' : `?returnTo=${encodeURIComponent(returnTo)}`}`);
    assert.equal(response.status, 302);
    const cookie = setCookies(response).get(TRANSACTION_COOKIE)!.value;
    const transaction = await readTransactionCookie(cookie, SECRET);
    assert.ok(transaction);
    return { location: new URL(response.headers.get('location')!), cookie, transaction };
  }

  async function callback(login: { cookie: string; transaction: OidcTransaction }, query = `code=auth-code&state=${login.transaction.state}`) {
    return request(`/oauth2/callback?${query}`, { cookies: { [TRANSACTION_COOKIE]: login.cookie } });
  }

  function replyWithTokens(claims: (transaction: OidcTransaction) => Promise<TokenReply['body']>, transaction: OidcTransaction) {
    provider.tokenReply = async () => ({ status: 200, body: await claims(transaction) });
  }

  describe('GET /health', () => {
    it('reports ok', async () => {
      const response = await request('/health');
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { status: 'ok' });
    });
  });

  describe('GET /', () => {
    it('offers sign-in when there is no session', async () => {
      const body = await (await request('/')).text();
      assert.match(body, /href="\/login"/);
      assert.doesNotMatch(body, /Signed in as/);
    });

    it('shows the signed-in user with HTML escaped', async () => {
      const response = await request('/', { cookies: await sessionCookie(validSession({ email: '<script>alert(1)</script>' })) });
      const body = await response.text();
      assert.match(body, /Signed in as <strong>&lt;script&gt;alert\(1\)&lt;\/script&gt;<\/strong>/);
      assert.doesNotMatch(body, /<script>alert/);
    });

    it('falls back to the subject when there is no email', async () => {
      const body = await (await request('/', { cookies: await sessionCookie(validSession({ email: undefined })) })).text();
      assert.match(body, /Signed in as <strong>user-123<\/strong>/);
    });
  });

  describe('GET /account', () => {
    it('redirects to login with the current URL when signed out', async () => {
      const response = await request('/account?tab=profile');
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), '/login?returnTo=%2Faccount%3Ftab%3Dprofile');
    });

    it('treats a session cookie sealed with another secret as signed out', async () => {
      const response = await request('/account', { cookies: { [COOKIE_NAME]: await createSessionCookie(validSession(), 'other-secret') } });
      assert.equal(response.status, 302);
    });

    for (const [label, expiresAt] of [['expired', Date.now() - 1], ['non-numeric', Number.NaN]] as const) {
      it(`clears an ${label} session and redirects to login`, async () => {
        const response = await request('/account', { cookies: await sessionCookie(validSession({ expiresAt })) });
        assert.equal(response.status, 302);
        assert.match(response.headers.get('location')!, /^\/login\?returnTo=/);
        const cleared = setCookies(response).get(COOKIE_NAME);
        assert.equal(cleared?.value, '');
        assert.match(cleared!.attributes, /Max-Age=0/);
      });
    }

    it('shows account details with HTML escaped', async () => {
      const response = await request('/account', { cookies: await sessionCookie(validSession({ name: '"Bobby" & <b>' })) });
      assert.equal(response.status, 200);
      const body = await response.text();
      assert.match(body, /<dd>user-123<\/dd>/);
      assert.match(body, /<dd>person@example.com<\/dd>/);
      assert.match(body, /<dd>&quot;Bobby&quot; &amp; &lt;b&gt;<\/dd>/);
    });

    it('shows placeholders for missing profile fields', async () => {
      const body = await (await request('/account', { cookies: await sessionCookie(validSession({ email: undefined, name: undefined })) })).text();
      assert.equal(body.match(/<dd>Not provided<\/dd>/g)?.length, 2);
    });
  });

  describe('GET /login', () => {
    it('redirects to the authorization endpoint with PKCE and a sealed transaction', async () => {
      const { location, transaction } = await startLogin('/orders?id=1');
      assert.equal(`${location.origin}${location.pathname}`, `${provider.issuer}/oauth2/authorize`);
      assert.equal(location.searchParams.get('response_type'), 'code');
      assert.equal(location.searchParams.get('client_id'), CLIENT_ID);
      assert.equal(location.searchParams.get('redirect_uri'), `${app.base}/oauth2/callback`);
      assert.equal(location.searchParams.get('scope'), 'openid email profile api/read api/write');
      assert.equal(location.searchParams.get('state'), transaction.state);
      assert.equal(location.searchParams.get('nonce'), transaction.nonce);
      assert.equal(location.searchParams.get('code_challenge'), pkceChallenge(transaction.verifier));
      assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
      assert.equal(transaction.returnTo, '/orders?id=1');
    });

    it('sets an HttpOnly, SameSite=Lax transaction cookie that expires in 10 minutes', async () => {
      const response = await request('/login');
      const { attributes } = setCookies(response).get(TRANSACTION_COOKIE)!;
      assert.match(attributes, /Max-Age=600/);
      assert.match(attributes, /HttpOnly/);
      assert.match(attributes, /SameSite=Lax/);
      assert.match(attributes, /Path=\//);
    });

    it('uses forwarded protocol and host for the redirect URI', async () => {
      const response = await request('/login', { headers: { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'app.example.com' } });
      const location = new URL(response.headers.get('location')!);
      assert.equal(location.searchParams.get('redirect_uri'), 'https://app.example.com/oauth2/callback');
    });

    it('generates a fresh state, nonce and verifier per login', async () => {
      const [first, second] = await Promise.all([startLogin(), startLogin()]);
      assert.notEqual(first.transaction.state, second.transaction.state);
      assert.notEqual(first.transaction.nonce, second.transaction.nonce);
      assert.notEqual(first.transaction.verifier, second.transaction.verifier);
    });

    for (const returnTo of [undefined, '//evil.com', '/..//evil.com', 'https://evil.com']) {
      it(`stores /account as the return path for ${returnTo ?? 'a missing returnTo'}`, async () => {
        const { transaction } = await startLogin(returnTo);
        assert.equal(transaction.returnTo, '/account');
      });
    }
  });

  describe('GET /oauth2/callback', () => {
    it('exchanges the code, sets a session cookie and redirects to returnTo', async () => {
      const login = await startLogin('/orders?id=1');
      replyWithTokens(async (t) => ({
        id_token: await provider.idToken({ sub: 'user-123', email: 'person@example.com', name: 'Test Person', nonce: t.nonce }),
        access_token: 'access-token',
        expires_in: 300,
      }), login.transaction);

      const before = Date.now();
      const response = await callback(login);
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), '/orders?id=1');

      const [tokenRequest] = provider.tokenRequests;
      assert.equal(tokenRequest.get('grant_type'), 'authorization_code');
      assert.equal(tokenRequest.get('code'), 'auth-code');
      assert.equal(tokenRequest.get('code_verifier'), login.transaction.verifier);
      assert.equal(tokenRequest.get('client_id'), CLIENT_ID);
      assert.equal(tokenRequest.get('client_secret'), CLIENT_SECRET);
      assert.equal(tokenRequest.get('redirect_uri'), `${app.base}/oauth2/callback`);

      const cookies = setCookies(response);
      assert.match(cookies.get(TRANSACTION_COOKIE)!.attributes, /Max-Age=0/);
      const sessionCookieValue = cookies.get(COOKIE_NAME)!;
      assert.match(sessionCookieValue.attributes, /Max-Age=300/);
      assert.match(sessionCookieValue.attributes, /HttpOnly/);
      const session = await readSessionCookie(sessionCookieValue.value, SECRET);
      assert.equal(session?.sub, 'user-123');
      assert.equal(session?.email, 'person@example.com');
      assert.equal(session?.name, 'Test Person');
      assert.equal(session?.accessToken, 'access-token');
      assert.ok(session!.expiresAt >= before + 300_000 && session!.expiresAt <= Date.now() + 300_000);
    });

    it('defaults the session lifetime to one hour when expires_in is missing', async () => {
      const login = await startLogin();
      replyWithTokens(async (t) => ({ id_token: await provider.idToken({ sub: 'user-123', nonce: t.nonce }), access_token: 'access-token' }), login.transaction);
      const response = await callback(login);
      assert.equal(response.status, 302);
      assert.match(setCookies(response).get(COOKIE_NAME)!.attributes, /Max-Age=3600/);
    });

    it('re-validates a stored returnTo before redirecting', async () => {
      const transaction: OidcTransaction = { state: 'state', nonce: 'nonce', verifier: 'verifier', returnTo: '//evil.com' };
      const login = { cookie: await createTransactionCookie(transaction, SECRET), transaction };
      replyWithTokens(async (t) => ({ id_token: await provider.idToken({ sub: 'user-123', nonce: t.nonce }), access_token: 'access-token' }), transaction);
      const response = await callback(login);
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), '/account');
    });

    describe('rejects invalid callback requests with 400 before contacting the provider', () => {
      it('when the transaction cookie is missing', async () => {
        const response = await request('/oauth2/callback?code=auth-code&state=state');
        assert.equal(response.status, 400);
      });

      it('when the state does not match', async () => {
        const login = await startLogin();
        assert.equal((await callback(login, 'code=auth-code&state=wrong')).status, 400);
      });

      it('when the state is missing', async () => {
        const login = await startLogin();
        assert.equal((await callback(login, 'code=auth-code')).status, 400);
      });

      it('when the code is missing', async () => {
        const login = await startLogin();
        assert.equal((await callback(login, `state=${login.transaction.state}`)).status, 400);
      });

      it('when the code is repeated', async () => {
        const login = await startLogin();
        assert.equal((await callback(login, `code=a&code=b&state=${login.transaction.state}`)).status, 400);
      });

      afterEach(() => assert.equal(provider.tokenRequests.length, 0));
    });

    const failures: Array<[string, (t: OidcTransaction) => Promise<TokenReply>, RegExp]> = [
      ['the token endpoint returns an error', async () => ({ status: 400, body: { error: 'invalid_grant' } }), /Token exchange failed with 400/],
      ['the token response has no id_token', async () => ({ status: 200, body: { access_token: 'access-token' } }), /did not contain required tokens/],
      ['the token response has no access_token', async (t) => ({ status: 200, body: { id_token: await provider.idToken({ sub: 'u', nonce: t.nonce }) } }), /did not contain required tokens/],
      ['the nonce does not match', async () => ({ status: 200, body: { id_token: await provider.idToken({ sub: 'u', nonce: 'other' }), access_token: 'a' } }), /nonce or subject/],
      ['the id_token has no subject', async (t) => ({ status: 200, body: { id_token: await provider.idToken({ nonce: t.nonce }), access_token: 'a' } }), /nonce or subject/],
      ['the id_token audience is another client', async (t) => ({ status: 200, body: { id_token: await provider.idToken({ sub: 'u', nonce: t.nonce }, { audience: 'other-client' }), access_token: 'a' } }), /aud/],
      ['the id_token issuer is wrong', async (t) => ({ status: 200, body: { id_token: await provider.idToken({ sub: 'u', nonce: t.nonce }, { issuer: 'https://evil.example' }), access_token: 'a' } }), /iss/],
      ['the id_token has expired', async (t) => ({ status: 200, body: { id_token: await provider.idToken({ sub: 'u', nonce: t.nonce }, { expiresIn: '-1m' }), access_token: 'a' } }), /exp/],
      ['the id_token is signed by an unknown key', async (t) => {
        const { privateKey } = await generateKeyPair('RS256');
        return { status: 200, body: { id_token: await provider.idToken({ sub: 'u', nonce: t.nonce }, { key: privateKey }), access_token: 'a' } };
      }, /signature/],
    ];

    for (const [label, reply, logged] of failures) {
      it(`returns 500 without a session when ${label}`, async () => {
        const login = await startLogin();
        provider.tokenReply = () => reply(login.transaction);
        const response = await callback(login);
        assert.equal(response.status, 500);
        assert.match(await response.text(), /Something went wrong/);
        assert.equal(setCookies(response).has(COOKIE_NAME), false);
        assert.match(String(consoleError.mock.calls[0]?.arguments[0]), logged);
      });
    }
  });

  describe('POST /logout', () => {
    it('clears the session and redirects to Cognito logout', async () => {
      const response = await request('/logout', { method: 'POST', cookies: await sessionCookie(validSession()), headers: { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'app.example.com' } });
      assert.equal(response.status, 302);
      const location = new URL(response.headers.get('location')!);
      assert.equal(`${location.origin}${location.pathname}`, `${AUTH_DOMAIN}/logout`);
      assert.equal(location.searchParams.get('client_id'), CLIENT_ID);
      assert.equal(location.searchParams.get('logout_uri'), 'https://app.example.com');
      assert.match(setCookies(response).get(COOKIE_NAME)!.attributes, /Max-Age=0/);
    });
  });
});

describe('when OIDC discovery fails', () => {
  let app: { base: string; close: () => Promise<void> };
  let provider: Server;

  before(async () => {
    provider = createServer((_request, response) => {
      response.writeHead(503);
      response.end();
    });
    await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
    const issuer = `http://127.0.0.1:${(provider.address() as AddressInfo).port}`;
    app = await listen({ clientId: CLIENT_ID, issuer, authDomain: AUTH_DOMAIN, sessionSecret: SECRET, host: '127.0.0.1', port: 0 });
  });

  after(async () => {
    await app.close();
    await new Promise((resolve) => provider.close(resolve));
  });

  afterEach(() => mock.restoreAll());

  it('returns 500 from /login when the provider responds with an error', async () => {
    const consoleError = mock.method(console, 'error', () => {});
    const response = await fetch(`${app.base}/login`, { redirect: 'manual' });
    assert.equal(response.status, 500);
    assert.match(String(consoleError.mock.calls[0]?.arguments[0]), /OIDC discovery failed with 503/);
  });

  it('returns 500 from /login when the provider is unreachable', async () => {
    const unreachable = await listen({ clientId: CLIENT_ID, issuer: 'http://127.0.0.1:1', authDomain: AUTH_DOMAIN, sessionSecret: SECRET, host: '127.0.0.1', port: 0 });
    try {
      const consoleError = mock.method(console, 'error', () => {});
      const response = await fetch(`${unreachable.base}/login`, { redirect: 'manual' });
      assert.equal(response.status, 500);
      assert.match(String(consoleError.mock.calls[0]?.arguments[0]), /OIDC discovery request failed for http:\/\/127\.0\.0\.1:1/);
    } finally {
      await unreachable.close();
    }
  });
});
