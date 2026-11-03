import { createClerkClient } from '@clerk/backend';
import { verifyWebhook } from '@clerk/backend/webhooks';

export type LoginLlamaWebhookOptions = {
  /** Defaults to `process.env.LOGINLLAMA_API_KEY`. */
  apiKey?: string;
  /** Defaults to `process.env.CLERK_SECRET_KEY`. */
  clerkSecretKey?: string;
  /** Defaults to `process.env.CLERK_WEBHOOK_SIGNING_SECRET`. */
  signingSecret?: string;
  /**
   * Revoke the session at this score or above (0 to 10). LoginLlama calls
   * anything over 5 risky; 8 revokes only the clearest cases while you watch
   * real scores in the dashboard.
   */
  blockAt?: number;
};

type LoginCheck = { risk_score: number; risk_codes: string[] };

const CHECK_URL = 'https://loginllama.app/api/v1/login/check';

/**
 * A webhook handler for Clerk's `session.created` event. It scores the new
 * session and revokes it when the score reaches `blockAt`. Takes a standard
 * `Request`, so it mounts in Next.js, Hono, Remix or anything with fetch.
 */
export const loginLlamaWebhook = ({
  apiKey = process.env.LOGINLLAMA_API_KEY,
  clerkSecretKey = process.env.CLERK_SECRET_KEY,
  signingSecret = process.env.CLERK_WEBHOOK_SIGNING_SECRET,
  blockAt = 8
}: LoginLlamaWebhookOptions = {}) => {
  if (!apiKey) {
    throw new Error(
      'clerk-loginllama: set LOGINLLAMA_API_KEY or pass { apiKey }. Get a free key at https://loginllama.app/signup'
    );
  }
  if (!clerkSecretKey) {
    throw new Error(
      'clerk-loginllama: set CLERK_SECRET_KEY or pass { clerkSecretKey }.'
    );
  }

  const clerk = createClerkClient({
    secretKey: clerkSecretKey,
    apiUrl: process.env.CLERK_API_URL
  });

  // Fails open: an outage, on our side or yours, must never lock people out.
  async function check(body: object): Promise<LoginCheck | null> {
    const response = await fetch(CHECK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/vnd.api+json',
        'X-API-KEY': apiKey!,
        'X-LOGINLLAMA-SOURCE': 'clerk-loginllama'
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(2000)
    }).catch(() => null);

    if (!response?.ok) return null;
    return (await response.json()).data.attributes;
  }

  return async (request: Request): Promise<Response> => {
    const event = await verifyWebhook(request, { signingSecret }).catch(
      () => null
    );
    if (!event) return new Response('invalid signature', { status: 400 });
    if (event.type !== 'session.created') return new Response('ignored');

    // The event carries the session, but Clerk fills in where it came from
    // (IP, browser) on the session it serves from the API.
    const [session, user] = await Promise.all([
      clerk.sessions.getSession(event.data.id),
      clerk.users.getUser(event.data.user_id)
    ]);
    const activity = session.latestActivity;

    const result = await check({
      identity_key: session.userId,
      email_address: user.primaryEmailAddress?.emailAddress,
      ip_address: activity?.ipAddress,
      user_agent: [activity?.browserName, activity?.browserVersion]
        .filter(Boolean)
        .join(' '),
      authentication_outcome: 'success'
    });

    if (result && result.risk_score >= blockAt) {
      await clerk.sessions.revokeSession(session.id);
      return new Response('revoked');
    }
    return new Response('ok');
  };
};
