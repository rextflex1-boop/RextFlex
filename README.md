# Magic Screen Control backend (Cloudflare Worker)

One file: `src/worker.js`. No dependencies. Runs on Cloudflare Workers (free plan is enough).
Firestore is used through its REST API with a service account. The Firebase Blaze plan is not needed.

## What it does

Public pages (anyone with the link):

| URL | What |
|---|---|
| `/u/<username>` | Profile link. Opens the app (`magicscreencontrol://u/<name>`), or the Play Store page |
| `/g/<inviteCode>` | Group invite link. Shows the group name, opens the app to join |
| `/s/<token>` | Shared chat. Read only, a snapshot of the last 100 messages at share time |
| `/.well-known/assetlinks.json` | Android App Links (the app opens these links directly) |

Login needed (send the Firebase ID token as `Authorization: Bearer <idToken>`):

| API | Body | What |
|---|---|---|
| `GET /api/health` | — | Shows which part works (service account, Firestore, Firebase API key). No secrets are shown. Open it in a browser when something fails |
| `GET /api/groups/preview?code=...` | — | Group name, description, member count, and whether you are already in it (used by the join screen) |
| `POST /api/shares` | `{"kind":"chat"\|"group","sourceId":"...","days":7}` | Creates a read-only shared chat. You must be in the chat or group. Returns `url` |
| `POST /api/shares/<token>/revoke` | — | Owner stops the link |
| `POST /api/groups/join` | `{"code":"..."}` | Adds you to the group. Checks the invite code on the server |
| `POST /api/groups/invites/revoke` | `{"code":"..."}` | Admin or creator revokes an invite link |
| `POST /api/account/delete` | — | Deletes my messages, groups, profile, username and login |
| `POST /api/notify` | `{"kind":"chat|group|call","id":"...","messageId":"..."}` | Sends a push to the other people's phones. The server checks the sender, members, blocks and mutes |
| `POST /api/upload` | `{"image":"<base64 jpeg>","expirationSeconds":3600}` | Uploads a photo to ImgBB. The ImgBB key stays on the server |

## Security

- Login is checked with Google (`accounts:lookup`) on every API call.
- Every permission check (chat member, group member, share owner) is done in the worker. The service account bypasses Firestore rules, so the worker must do the checks.
- Share pages escape all text, and only `https://` photos are shown. Audio data is never copied into a share.
- Share snapshots keep usernames only, not user ids.
- Daily limits per user: 50 shares and 300 uploads (stored in `quotas`, which clients cannot read).
- Share tokens are 192 random bits.
- Secrets (service account JSON, ImgBB key) are Cloudflare secrets, never in code or in the app.

## Setup

You need: a Cloudflare account (free), Node.js (on a PC, or Termux on the phone), the Firebase service account JSON, and an ImgBB key.

### 1. Get the two secrets

- **Firebase service account:** Firebase Console > Project settings > Service accounts > Generate new private key. Keep the JSON private.
- **ImgBB key:** create a NEW key at api.imgbb.com. The old key is inside the current app, so treat it as leaked.

### 2. Deploy with the command line (PC or Termux)

```bash
npm install
npx wrangler login                                  # opens a browser, log in to Cloudflare
npx wrangler secret put FIREBASE_SERVICE_ACCOUNT_JSON   # paste the whole JSON file
npx wrangler secret put IMGBB_API_KEY                   # paste the new ImgBB key
npx wrangler deploy
```

`wrangler deploy` prints the address, for example `https://magicscreen-links.<your-subdomain>.workers.dev`.

### 3. Or deploy from the Cloudflare dashboard (no command line)

1. dash.cloudflare.com > Workers & Pages > Create > Worker > name it `magicscreen-links` > Deploy.
2. Click Edit code, delete the sample code, paste all of `src/worker.js`, click Deploy.
3. Settings > Variables and Secrets: add the values from `wrangler.toml` as variables (`FIREBASE_PROJECT_ID`, `FIREBASE_WEB_API_KEY`, `ANDROID_PACKAGE`, `ANDROID_CERT_SHA256`, `PLAY_STORE_URL`), and add two **Secret** values: `FIREBASE_SERVICE_ACCOUNT_JSON` and `IMGBB_API_KEY`.
4. Deploy again. The address is shown on the Worker page.

### 4. Check it works

- Open `https://<your-address>/` — should show the landing text.
- Open `https://<your-address>/u/alice` — should show the profile page.
- Open `https://<your-address>/.well-known/assetlinks.json` — should show the package name.

### 5. Custom domain (optional, later)

Needs a domain whose DNS is on Cloudflare. Workers & Pages > your worker > Settings > Domains & Routes > Add > Custom domain. Then put that address in `PUBLIC_BASE_URL`.

## Tests

```bash
npm test
```

Runs 46 tests with a fake Firestore, fake Google login and fake ImgBB. The service-account JWT is really signed and verified.

## Known limits

- Rate limiting per IP: add a Cloudflare rule (dashboard > Security > WAF > Rate limiting rules) for `/api/*`, for example 30 requests per minute per IP. Not in the code.
- If `/api/*` returns 500 with "accounts lookup 403": the web API key is restricted. In Google Cloud Console > Credentials, set that key's application restriction to "None" and its API restriction to "Identity Toolkit API".
- Old quota documents are not deleted automatically (one small document per user per day).
- Shares are snapshots: messages sent after the share are not included.

## Security (v29)

- Rate limits per user per minute: preview 30, join 10, upload 20, share 10, revoke 20, account delete 3.
- Daily limits: shares 50, uploads 300.
- Invite links can be revoked, and can have an expiry time.
- Cron job every 6 hours removes expired shared chats and quota counters older than 2 days.
- Cloudflare rate limit rule (dashboard > Security > WAF > Rate limiting rules) for `/api/*` is still recommended on top of these checks.
- Push notifications: FCM HTTP v1 from this server (service account). Tokens are stored under users/{uid}/devices. Invalid tokens are removed automatically.

## Notification check (this build)

- `/api/health` `messaging` now asks FCM to validate a message without sending it. `ok` means FCM is enabled and this server may send. An `error 403` means the Firebase Cloud Messaging API is off or not allowed for the project.
- `POST /api/notify` returns `sent`, `failed` and the first reasons in `errors`, and logs the same line to Cloudflare Logs.
