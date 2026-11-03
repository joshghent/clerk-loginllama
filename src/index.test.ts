import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { beforeEach, test } from 'node:test';

const SIGNING_SECRET =
  'whsec_' + Buffer.from('example-secret').toString('base64');

const session = {
  object: 'session',
  id: 'sess_123',
  client_id: 'client_123',
  user_id: 'user_123',
  status: 'active',
  last_active_at: 1,
  expire_at: 2,
  abandon_at: 3,
  created_at: 1,
  updated_at: 1,
  latest_activity: {
    object: 'session_activity',
    id: 'sess_activity_123',
    ip_address: '203.0.113.42',
    browser_name: 'Chrome',
    browser_version: '141.0.0.0',
    is_mobile: false
  }
};

const user = {
  object: 'user',
  id: 'user_123',
  primary_email_address_id: 'idn_1',
  email_addresses: [
    {
      object: 'email_address',
      id: 'idn_1',
      email_address: 'ada@example.test',
      verification: null,
      linked_to: []
    }
  ],
  phone_numbers: [],
  web3_wallets: [],
  external_accounts: [],
  created_at: 1,
  updated_at: 1
};

// Stands in for both the Clerk Backend API and the LoginLlama API.
let score: number | 'down' = 0;
let calls: { url: string; body?: string }[] = [];
let source: string | null = null;
globalThis.fetch = async (input, init) => {
  const url = String(input instanceof Request ? input.url : input);
  calls.push({ url, body: init?.body ? String(init.body) : undefined });
  if (url === 'https://loginllama.app/api/v1/login/check') {
    source = new Headers(init?.headers).get('x-loginllama-source');
    if (score === 'down') throw new TypeError('fetch failed');
    return Response.json({
      data: { attributes: { risk_score: score, risk_codes: [] } }
    });
  }
  if (url.endsWith('/v1/sessions/sess_123')) return Response.json(session);
  if (url.endsWith('/v1/users/user_123')) return Response.json(user);
  if (url.endsWith('/v1/sessions/sess_123/revoke')) {
    return Response.json({ ...session, status: 'revoked' });
  }
  return new Response('{}', { status: 404 });
};

process.env.CLERK_API_URL = 'https://clerk.test';
// Imported after the stand-in, because Clerk binds fetch when it loads.
const { loginLlamaWebhook } = await import('./index.ts');
const handler = loginLlamaWebhook({
  apiKey: 'test-key',
  clerkSecretKey: 'sk_test_example',
  signingSecret: SIGNING_SECRET
});

function signedWebhook(type: string, signature?: string): Request {
  const body = JSON.stringify({ type, object: 'event', data: session });
  const id = 'msg_123';
  const timestamp = String(Math.floor(Date.now() / 1000));
  const key = Buffer.from(SIGNING_SECRET.slice('whsec_'.length), 'base64');
  const signed = createHmac('sha256', key)
    .update(`${id}.${timestamp}.${body}`)
    .digest('base64');

  return new Request('http://localhost/api/webhooks/clerk', {
    method: 'POST',
    headers: {
      'svix-id': id,
      'svix-timestamp': timestamp,
      'svix-signature': signature ?? `v1,${signed}`
    },
    body
  });
}

const checkBody = () =>
  JSON.parse(calls.find((c) => c.url.includes('loginllama.app'))!.body!);
const revoked = () => calls.some((c) => c.url.endsWith('/revoke'));

beforeEach(() => {
  score = 0;
  calls = [];
});

test('scores the session with the IP, browser and email Clerk recorded', async () => {
  score = 2;
  const response = await handler(signedWebhook('session.created'));

  assert.equal(response.status, 200);
  assert.deepEqual(checkBody(), {
    identity_key: 'user_123',
    email_address: 'ada@example.test',
    ip_address: '203.0.113.42',
    user_agent: 'Chrome 141.0.0.0',
    authentication_outcome: 'success'
  });
  assert.equal(revoked(), false);
});

test('revokes the session at the block threshold', async () => {
  score = 8;
  await handler(signedWebhook('session.created'));
  assert.equal(revoked(), true);
});

test('keeps the session when LoginLlama is unreachable', async () => {
  score = 'down';
  const response = await handler(signedWebhook('session.created'));
  assert.equal(response.status, 200);
  assert.equal(revoked(), false);
});

test('ignores other event types', async () => {
  await handler(signedWebhook('user.created'));
  assert.deepEqual(calls, []);
});

test('rejects a webhook with a bad signature', async () => {
  const response = await handler(
    signedWebhook('session.created', 'v1,bm9wZQ==')
  );
  assert.equal(response.status, 400);
  assert.deepEqual(calls, []);
});

test('refuses to start without an API key', () => {
  const saved = process.env.LOGINLLAMA_API_KEY;
  delete process.env.LOGINLLAMA_API_KEY;
  try {
    assert.throws(() => loginLlamaWebhook(), /LOGINLLAMA_API_KEY/);
  } finally {
    if (saved) process.env.LOGINLLAMA_API_KEY = saved;
  }
});

test('tells LoginLlama which integration sent the check', async () => {
  await handler(signedWebhook('session.created'));
  assert.equal(source, 'clerk-loginllama');
});
