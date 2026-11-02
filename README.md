# clerk-loginllama

Scores every [Clerk](https://clerk.com) sign-in for risk and revokes the risky
sessions within seconds.

Clerk checks the password. It does not ask whether the login looks right. A
correct password from a Tor exit node, a country the user has never been to, or
a bot that has just tried four thousand other accounts still gets a session.
This package asks [LoginLlama](https://loginllama.app) about every new session
and ends the ones that score high.

```bash
npm install clerk-loginllama
```

Next.js App Router, `app/api/webhooks/clerk/route.ts`:

```ts
import { loginLlamaWebhook } from 'clerk-loginllama';

export const POST = loginLlamaWebhook();
```

Hono, or anything else that hands you a `Request`:

```ts
const handler = loginLlamaWebhook();
app.post('/webhooks/clerk', (c) => handler(c.req.raw));
```

Then in the Clerk dashboard, under **Webhooks**, add an endpoint at that URL and
subscribe it to `session.created`.

Set these in your environment:

| Variable | Where to get it |
| --- | --- |
| `LOGINLLAMA_API_KEY` | [loginllama.app/signup](https://loginllama.app/signup). The first 1,000 checks are free. |
| `CLERK_SECRET_KEY` | Clerk dashboard, **API keys** |
| `CLERK_WEBHOOK_SIGNING_SECRET` | The webhook endpoint you just made |

## What it does

When Clerk creates a session it calls the webhook. The handler checks the
signature, reads the IP address and browser Clerk recorded for the session, and
sends them to LoginLlama with the user's ID and primary email. It gets back a
score from 0 to 10 and reason codes such as `known_tor_exit_node`,
`known_vpn`, `impossible_travel_detected`, `new_login_location` and
`known_bot`. At 8 or above it revokes the session, which signs the user out on
their next request.

Every sign-in shows up in the
[dashboard](https://loginllama.app/account/dashboard) with its score and
reasons, and LoginLlama can email the user when it sees a login from somewhere
new.

If LoginLlama is down or takes longer than two seconds, the session stays. A
fraud check should never lock your users out.

The webhook runs after Clerk has made the session, so a risky user has it for
the second or two the webhook takes. Use it with Clerk's own bot protection
rather than in place of it.

## Options

```ts
loginLlamaWebhook({
  apiKey: process.env.LOGINLLAMA_API_KEY, // the default
  clerkSecretKey: process.env.CLERK_SECRET_KEY, // the default
  signingSecret: process.env.CLERK_WEBHOOK_SIGNING_SECRET, // the default
  blockAt: 8 // revoke at this score or above
});
```

Start at 8 and lower it once you have watched real scores for a week.
LoginLlama marks anything above 5 as risky.

## Requirements

`@clerk/backend` 3 or newer, Node 22.18 or newer.

## Links

- [LoginLlama for Clerk](https://loginllama.app/for-clerk)
- [LoginLlama docs](https://loginllama.app/docs)
- [Free IP reputation checker](https://loginllama.app/tools/ip-reputation-checker)

## Licence

MIT
