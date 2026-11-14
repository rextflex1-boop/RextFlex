/**
 * Magic Screen Control backend (Cloudflare Worker). One file, no dependencies.
 *
 * Public pages (anyone with the link):
 *   GET  /                          landing
 *   GET  /u/:username               profile link (opens the app)
 *   GET  /g/:inviteCode             group invite link (opens the app)
 *   GET  /s/:shareToken             shared chat, read only, snapshot
 *   GET  /.well-known/assetlinks.json   Android App Links
 *
 * Login needed (Firebase ID token in "Authorization: Bearer <token>"):
 *   POST /api/shares                    share a chat or group as a read-only snapshot
 *   POST /api/shares/:token/revoke      owner stops a share link
 *   POST /api/groups/join               join a group with its invite code
 *   POST /api/upload                    photo upload (the ImgBB key stays on the server)
 *
 * Security: the ID token is checked with Google (accounts:lookup). Firestore is read and
 * written with a service account, so every permission check is done in this file.
 * The service account and the ImgBB key are secrets (never in code or in the app).
 */

const MAX_BODY_BYTES = 4 * 1024 * 1024;
const SNAPSHOT_MAX_MESSAGES = 100;
const SHARE_DEFAULT_DAYS = 7;
const SHARE_MAX_DAYS = 30;
const DAILY_LIMIT_SHARES = 50;
const DAILY_LIMIT_UPLOADS = 300;

const RE_USERNAME = /^[a-z0-9_.]{3,30}$/;
const RE_ID = /^[A-Za-z0-9_-]{4,64}$/;
const RE_TOKEN = /^[A-Za-z0-9_-]{32,64}$/;
const RE_BEARER = /^Bearer ([A-Za-z0-9._-]{20,4096})$/;
const RE_BASE64 = /^[A-Za-z0-9+/=]+$/;

const FS_API = "https://firestore.googleapis.com/v1/";
const CSS = "body{margin:0;background:#eef2f7;color:#111827;font:16px/1.5 system-ui,-apple-system,sans-serif}" +
  "main{max-width:520px;margin:0 auto;padding:32px 16px}" +
  ".card{background:#fff;border-radius:24px;padding:28px 22px;text-align:center;box-shadow:0 10px 30px rgba(15,23,42,.08)}" +
  ".avatar{width:112px;height:112px;border-radius:50%;object-fit:cover;margin:0 auto 14px;display:block}" +
  ".initial{background:#3b82f6;color:#fff;font-size:44px;font-weight:700;line-height:112px;text-align:center}" +
  "h1{font-size:24px;margin:6px 0 2px;word-break:break-word}" +
  ".handle{color:#6b7280;font-size:15px}.bio{color:#374151;margin:16px 0 0;white-space:pre-wrap;word-break:break-word}" +
  ".btn{display:block;background:#3b82f6;color:#fff;padding:14px 18px;border-radius:14px;text-decoration:none;font-weight:600;margin:22px 0 8px}" +
  ".muted{color:#6b7280;font-size:14px}" +
  ".msg{background:#fff;border-radius:16px;padding:10px 12px;margin:8px 0;box-shadow:0 4px 14px rgba(15,23,42,.06)}" +
  ".who{font-weight:600;color:#2563eb;font-size:14px}.time{color:#6b7280;font-size:12px;margin-left:6px}" +
  ".text{white-space:pre-wrap;word-break:break-word;margin-top:4px}img{max-width:100%;border-radius:12px;margin-top:6px}a{color:#2563eb}";

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** A server setup problem (secret, API key, Firestore). The message says what to fix; it never shows a secret. */
class SetupError extends HttpError {
  constructor(message) {
    super(503, message);
  }
}

// ---------- responses ----------

function securityHeaders() {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "strict-transport-security": "max-age=31536000",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; img-src https:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  };
}

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...securityHeaders() },
  });
}

function html(status, title, bodyHtml) {
  const doc =
    `<!doctype html><html lang="hi"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="robots" content="noindex,nofollow"><title>${esc(title)}</title>` +
    `<style>${CSS}</style></head><body><main>${bodyHtml}</main></body></html>`;
  return new Response(doc, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...securityHeaders() },
  });
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
  );
}

function notFoundPage(message) {
  return html(404, "Link nahi mila", `<h1>Link nahi mila</h1><p class="muted">${esc(message)}</p>`);
}

function storeLink(env) {
  return env.PLAY_STORE_URL
    ? `<p class="muted"><a href="${esc(env.PLAY_STORE_URL)}" rel="noopener noreferrer">App nahi hai? Yahan se install karo</a></p>`
    : "";
}

// ---------- encoding helpers ----------

function b64urlFromBytes(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlFromString(str) {
  return b64urlFromBytes(new TextEncoder().encode(str));
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomToken() {
  const bytes = new Uint8Array(24); // 24 bytes = 32 base64url characters
  crypto.getRandomValues(bytes);
  return b64urlFromBytes(bytes);
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return "";
  }
}

const isId = (v) => typeof v === "string" && RE_ID.test(v);

// ---------- Google service account (Firestore access) ----------

const DATASTORE_SCOPE = "https://www.googleapis.com/auth/datastore";
const MESSAGING_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const cachedTokens = new Map(); // scope -> { token, exp }, lives as long as this worker instance

async function googleAccessToken(env, scope = DATASTORE_SCOPE) {
  const now = Math.floor(Date.now() / 1000);
  const cached = cachedTokens.get(scope);
  if (cached && cached.exp - 60 > now) return cached.token;

  let sa;
  try {
    sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON || "");
  } catch {
    throw new SetupError("FIREBASE_SERVICE_ACCOUNT_JSON secret galat hai (JSON parse nahi hua). Poori JSON file dobara paste karo.");
  }
  if (!sa.client_email || !sa.private_key) {
    throw new SetupError("FIREBASE_SERVICE_ACCOUNT_JSON mein client_email ya private_key nahi hai.");
  }
  const header = b64urlFromString(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64urlFromString(
    JSON.stringify({
      iss: sa.client_email,
      scope,
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
    })
  );
  let key;
  try {
    key = await crypto.subtle.importKey(
      "pkcs8",
      pemToDer(sa.private_key),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } catch {
    throw new SetupError("private_key import nahi hua. Service account JSON file dobara download karke paste karo.");
  }
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(`${header}.${claims}`)
  );
  const assertion = `${header}.${claims}.${b64urlFromBytes(new Uint8Array(sig))}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
  });
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    throw new SetupError(`Service account login fail (${info.error || res.status}). ${String(info.error_description || "").slice(0, 200)}`);
  }
  const data = await res.json();
  const fresh = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  cachedTokens.set(scope, fresh);
  return fresh.token;
}

// ---------- Firestore REST (typed values) ----------

const dbPath = (env) => `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
const docName = (env, path) => `${dbPath(env)}/${path}`;

function fromFsValue(v) {
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return Number(v.doubleValue);
  if ("booleanValue" in v) return v.booleanValue;
  if ("timestampValue" in v) return Date.parse(v.timestampValue);
  if ("nullValue" in v) return null;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fromFsValue);
  if ("mapValue" in v) return fromFsFields(v.mapValue.fields || {});
  return undefined;
}

function fromFsFields(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields)) out[k] = fromFsValue(v);
  return out;
}

function toFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "string") return { stringValue: v };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFsValue) } };
  if (typeof v === "object") return { mapValue: { fields: toFsFields(v) } };
  throw new Error("unsupported value type");
}

function toFsFields(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) if (v !== undefined) fields[k] = toFsValue(v);
  return fields;
}

async function authedFetch(env, url, init = {}) {
  const token = await googleAccessToken(env);
  return fetch(url, {
    ...init,
    headers: { ...(init.headers || {}), authorization: `Bearer ${token}`, "content-type": "application/json" },
  });
}

async function firestoreError(res, action) {
  const info = await res.json().catch(() => ({}));
  return new SetupError(`Firestore ${action} fail (${res.status}). ${String(info.error?.message || "").slice(0, 200)}`);
}

async function fsGet(env, path) {
  const res = await authedFetch(env, `${FS_API}${dbPath(env)}/${path}`, { method: "GET" });
  if (res.status === 404) return null;
  if (!res.ok) throw await firestoreError(res, "get");
  const doc = await res.json();
  return fromFsFields(doc.fields || {});
}

async function fsGetMany(env, paths) {
  const found = new Map();
  if (paths.length === 0) return found;
  const res = await authedFetch(env, `${FS_API}${dbPath(env)}:batchGet`, {
    method: "POST",
    body: JSON.stringify({ documents: paths.map((p) => docName(env, p)) }),
  });
  if (!res.ok) throw await firestoreError(res, "batchGet");
  for (const row of await res.json()) {
    if (row.found) found.set(row.found.name.split("/documents/")[1], fromFsFields(row.found.fields || {}));
  }
  return found;
}

async function fsQuery(env, parentPath, collectionId, { orderBy, direction, limit }) {
  const structuredQuery = { from: [{ collectionId }], limit };
  if (orderBy) structuredQuery.orderBy = [{ field: { fieldPath: orderBy }, direction: direction || "ASCENDING" }];
  const res = await authedFetch(env, `${FS_API}${dbPath(env)}/${parentPath}:runQuery`, {
    method: "POST",
    body: JSON.stringify({ structuredQuery }),
  });
  if (!res.ok) throw await firestoreError(res, "query");
  const rows = await res.json();
  return rows
    .filter((r) => r.document)
    .map((r) => ({ id: r.document.name.split("/").pop(), ...fromFsFields(r.document.fields || {}) }));
}

async function fsCommit(env, writes) {
  const res = await authedFetch(env, `${FS_API}${dbPath(env)}:commit`, {
    method: "POST",
    body: JSON.stringify({ writes }),
  });
  if (!res.ok) throw await firestoreError(res, "commit");
}

// ---------- Firebase login check ----------

async function verifyIdToken(env, idToken) {
  if (!env.FIREBASE_WEB_API_KEY) throw new SetupError("FIREBASE_WEB_API_KEY variable set nahi hai.");
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken }),
    }
  );
  if (res.status === 400) return null; // token is wrong or expired
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    throw new SetupError(`FIREBASE_WEB_API_KEY reject hua (${res.status}: ${String(info.error?.message || "").slice(0, 160)}). Google Cloud > Credentials mein key ki restriction check karo.`);
  }
  const data = await res.json();
  const user = data.users && data.users[0];
  if (!user || user.disabled || !isId(user.localId)) return null;
  return user.localId;
}

async function requireUid(request, env) {
  const m = RE_BEARER.exec(request.headers.get("authorization") || "");
  if (!m) throw new HttpError(401, "Login karo pehle");
  const uid = await verifyIdToken(env, m[1]);
  if (!uid) throw new HttpError(401, "Login expire ho gaya, dobara login karo");
  return uid;
}

// ---------- limits ----------

async function bumpQuota(env, uid, bucket, limit) {
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const id = `${uid}_${bucket}_${day}`;
  const current = (await fsGet(env, `quotas/${id}`)) || { count: 0 };
  if (current.count >= limit) throw new HttpError(429, "Aaj ki limit khatam ho gayi, kal phir try karo");
  await fsCommit(env, [
    { update: { name: docName(env, `quotas/${id}`), fields: toFsFields({ count: current.count + 1, uid, bucket, day }) } },
  ]);
}

function clampDays(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return SHARE_DEFAULT_DAYS;
  return Math.min(Math.max(Math.floor(n), 1), SHARE_MAX_DAYS);
}

async function readJson(request) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > MAX_BODY_BYTES) throw new HttpError(413, "Data bahut bada hai");
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) throw new HttpError(413, "Data bahut bada hai");
  try {
    return JSON.parse(text || "{}");
  } catch {
    throw new HttpError(400, "JSON galat hai");
  }
}

// ---------- health check (open /api/health in a browser) ----------

const CLOUD_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

/** Says exactly what Firestore answers for this project. Shown in /api/health, with no secrets. */
async function firestoreHealth(env) {
  // 1. Which databases exist in this project?
  const cloudToken = await googleAccessToken(env, CLOUD_SCOPE);
  const list = await fetch(`${FS_API}projects/${env.FIREBASE_PROJECT_ID}/databases`, {
    headers: { authorization: `Bearer ${cloudToken}` },
  });
  const listInfo = await list.json().catch(() => ({}));
  if (!list.ok) {
    return `databases list error ${list.status}: ${String(listInfo.error?.message || "").slice(0, 200)}`;
  }
  const names = (listInfo.databases || []).map((d) => `${d.name.split("/").pop()} (${d.type || "?"})`);
  if (!names.some((n) => n.startsWith("(default)"))) {
    return `Project "${env.FIREBASE_PROJECT_ID}" mein (default) Firestore database nahi hai. Is project mein mile: ${names.join(", ") || "koi nahi"}. Firebase Console mein ISI project ko kholo aur Firestore Database banao.`;
  }
  // 2. Can the server read a document?
  const res = await fetch(`${FS_API}${dbPath(env)}/quotas/health-check`, {
    headers: { authorization: `Bearer ${await googleAccessToken(env)}` },
  });
  if (res.ok) return "ok";
  const info = await res.json().catch(() => ({}));
  const msg = String(info.error?.message || "");
  // A missing document is fine: the database answered
  // A missing document is fine (the database answered). Only "does not exist" means the database is missing.
  if (res.status === 404 && !/does not exist/i.test(msg)) return "ok";
  return `error ${res.status}: ${msg.slice(0, 200)}`;
}

/** Asks FCM to validate a message WITHOUT sending it. Shows whether the API is enabled and this server may use it. */
async function fcmApiHealth(env) {
  const access = await googleAccessToken(env, MESSAGING_SCOPE);
  const res = await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/messages:send`, {
    method: "POST",
    headers: { authorization: `Bearer ${access}`, "content-type": "application/json" },
    body: JSON.stringify({ validate_only: true, message: { token: "health-check-token-not-real", data: { ping: "1" } } }),
  });
  // FCM answered and refused only the fake token: the API is on and this server may send
  if (res.status === 400) return "ok";
  const info = await res.json().catch(() => ({}));
  return `error ${res.status}: ${String(info.error?.message || "").slice(0, 200)}`;
}

async function healthCheck(env) {
  const out = {
    serviceAccount: "ok",
    firestore: "ok",
    webApiKey: "ok",
    messaging: "ok",
    imgbbKey: env.IMGBB_API_KEY ? "ok" : "missing (photo upload kaam nahi karega)",
  };
  let token = null;
  try {
    token = await googleAccessToken(env);
  } catch (e) {
    out.serviceAccount = e.message;
  }
  if (token) {
    try {
      out.firestore = await firestoreHealth(env);
    } catch (e) {
      out.firestore = e.message;
    }
  } else {
    out.firestore = "skipped (service account fail)";
  }
  try {
    const res = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY || "")}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ idToken: "health-check-dummy-token-000000" }),
      }
    );
    if (res.status !== 400) {
      const info = await res.json().catch(() => ({}));
      out.webApiKey = `error ${res.status}: ${String(info.error?.message || "").slice(0, 200)}`;
    }
  } catch (e) {
    out.webApiKey = e.message;
  }
  try {
    out.messaging = await fcmApiHealth(env);
  } catch (e) {
    out.messaging = e.message;
  }
  out.ready = out.serviceAccount === "ok" && out.firestore === "ok" && out.webApiKey === "ok" && out.messaging === "ok";
  return out;
}

// ---------- public pages ----------

function landingPage() {
  return html(200, "Magic Screen Control", `<h1>Magic Screen Control</h1><p class="muted">Ye server app ke links aur uploads ke liye hai.</p>`);
}

function assetLinks(env) {
  const fingerprints = (env.ANDROID_CERT_SHA256 || "").split(",").map((s) => s.trim()).filter(Boolean);
  const body = [
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: env.ANDROID_PACKAGE || "com.magicscreencontrol.app",
        sha256_cert_fingerprints: fingerprints,
      },
    },
  ];
  return new Response(JSON.stringify(body), {
    headers: { ...securityHeaders(), "content-type": "application/json", "cache-control": "public, max-age=3600" },
  });
}

function avatarHtml(photoUrl, name) {
  if (photoUrl) return `<img class="avatar" src="${esc(photoUrl)}" alt="">`;
  const letter = String(name || "?").trim().charAt(0).toUpperCase() || "?";
  return `<div class="avatar initial">${esc(letter)}</div>`;
}

async function profilePage(username, env) {
  if (!RE_USERNAME.test(username)) return notFoundPage("Ye profile link galat hai.");
  const mapping = await fsGet(env, `usernames/${username}`);
  const profile = mapping && isId(mapping.uid) ? await fsGet(env, `users/${mapping.uid}`) : null;
  if (!profile) return notFoundPage("Ye profile nahi mila.");
  const name = typeof profile.displayName === "string" && profile.displayName ? profile.displayName : username;
  const photo = typeof profile.photoURL === "string" && profile.photoURL.startsWith("https://") ? profile.photoURL : "";
  const bio = typeof profile.bio === "string" ? profile.bio.slice(0, 500) : "";
  return html(
    200,
    `@${username} · Magic Screen Control`,
    `<div class="card">
       ${avatarHtml(photo, name)}
       <h1>${esc(name)}</h1>
       <div class="handle">@${esc(username)}</div>
       ${bio ? `<p class="bio">${esc(bio)}</p>` : ""}
       <a class="btn" href="magicscreencontrol://u/${esc(username)}">App mein profile kholo</a>
       ${storeLink(env)}
     </div>`
  );
}

async function groupInvitePage(code, env) {
  if (!isId(code)) return notFoundPage("Ye invite link galat hai.");
  const invite = await fsGet(env, `groupInvites/${code}`);
  if (!invite || !isId(invite.groupId)) return notFoundPage("Ye invite link ab kaam nahi karta.");
  if (invite.revoked || (invite.expiresAt && invite.expiresAt < Date.now())) return notFoundPage("Ye invite link ab kaam nahi karta.");
  const group = await fsGet(env, `groups/${invite.groupId}`);
  if (!group) return notFoundPage("Ye group ab maujood nahi hai.");
  const name = group.name || "Group";
  const count = (group.members || []).length;
  const description = typeof group.description === "string" ? group.description.slice(0, 500) : "";
  return html(
    200,
    `${name} · invite`,
    `<div class="card">
       ${avatarHtml("", name)}
       <h1>${esc(name)}</h1>
       <div class="handle">Private group · ${count} members</div>
       ${description ? `<p class="bio">${esc(description)}</p>` : ""}
       <a class="btn" href="magicscreencontrol://join/${esc(code)}">Join group</a>
       <p class="muted">Join karne ke liye app kholo. App nahi hai to pehle install karo.</p>
       ${storeLink(env)}
     </div>`
  );
}

function renderMessage(m) {
  const when = m.createdAt
    ? new Date(m.createdAt).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", dateStyle: "short", timeStyle: "short" })
    : "";
  let content = "";
  if (m.type === "photo" && m.imageUrl) content += `<img src="${esc(m.imageUrl)}" alt="photo" loading="lazy">`;
  if (m.type === "voice") content += `<div class="muted">🎤 Voice message (app mein sunein)</div>`;
  if (m.type === "location" && typeof m.latitude === "number" && typeof m.longitude === "number") {
    content += `<div><a href="https://maps.google.com/?q=${m.latitude},${m.longitude}" rel="noopener noreferrer">📍 Location dekho</a></div>`;
  }
  if (m.text) content += `<div class="text">${esc(m.text)}</div>`;
  return `<div class="msg"><span class="who">@${esc(m.senderUsername || "user")}</span><span class="time">${esc(when)}</span>${content}</div>`;
}

async function sharedPage(token, env) {
  if (!RE_TOKEN.test(token)) return notFoundPage("Ye link galat hai.");
  const share = await fsGet(env, `sharedChats/${token}`);
  if (!share) return notFoundPage("Ye link nahi mila.");
  if (share.revoked) return notFoundPage("Ye link band kar diya gaya hai.");
  if (!share.expiresAt || share.expiresAt < Date.now()) return notFoundPage("Ye link khatam ho chuka hai.");
  const rows = await fsQuery(env, `sharedChats/${token}`, "messages", {
    orderBy: "seq",
    direction: "ASCENDING",
    limit: SNAPSHOT_MAX_MESSAGES,
  });
  const body = rows.map(renderMessage).join("") || `<p class="muted">Is chat mein koi message nahi hai.</p>`;
  const until = new Date(share.expiresAt).toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata" });
  return html(
    200,
    `${share.title || "Shared chat"} · shared chat`,
    `<h1>${esc(share.title || "Shared chat")}</h1>
     <p class="muted">Ye chat sirf padhne ke liye hai. Yahan se message nahi bhej sakte.</p>
     ${body}
     <p class="muted">Ye link ${esc(until)} tak chalega.</p>`
  );
}

async function groupPreview(request, env, url) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "preview", 30);
  const code = url.searchParams.get("code") || "";
  if (!isId(code)) throw new HttpError(400, "Invite code galat hai");
  const invite = await fsGet(env, `groupInvites/${code}`);
  if (!invite || !isId(invite.groupId)) throw new HttpError(404, "Invite code galat hai ya expire ho gaya");
  assertInviteUsable(invite);
  const group = await fsGet(env, `groups/${invite.groupId}`);
  if (!group) throw new HttpError(404, "Group nahi mila");
  const members = group.members || [];
  return json(200, {
    groupId: invite.groupId,
    name: group.name || "Group",
    description: typeof group.description === "string" ? group.description.slice(0, 500) : "",
    memberCount: members.length,
    alreadyMember: members.includes(uid),
  });
}

// ---------- limits, search and bulk delete ----------

function dayKey(date) {
  return date.toISOString().slice(0, 10).replace(/-/g, "");
}

/** Per-user limit for one minute. Stops a script that hits one endpoint over and over. */
async function rateLimit(env, uid, name, perMinute) {
  const now = new Date();
  const minute = now.toISOString().slice(0, 16).replace(/[-:T]/g, "");
  const id = `${uid}_${name}_${minute}`;
  const current = (await fsGet(env, `quotas/${id}`)) || { count: 0 };
  if (current.count >= perMinute) {
    throw new HttpError(429, "Bahut jaldi-jaldi request ho rahi hai. 1 minute baad phir try karo.");
  }
  await fsCommit(env, [
    { update: { name: docName(env, `quotas/${id}`), fields: toFsFields({ count: current.count + 1, uid, bucket: name, day: dayKey(now) }) } },
  ]);
}

/** Finds documents. parentPath null = top-level collection. Each row has path (full name) and id. */
async function fsFind(env, parentPath, collectionId, filters = [], limit = 1000, allDescendants = false) {
  const structuredQuery = { from: [{ collectionId, allDescendants }], limit };
  const parts = filters.map((f) => ({
    fieldFilter: { field: { fieldPath: f.field }, op: f.op, value: toFsValue(f.value) },
  }));
  if (parts.length === 1) structuredQuery.where = parts[0];
  if (parts.length > 1) structuredQuery.where = { compositeFilter: { op: "AND", filters: parts } };
  const url = parentPath
    ? `${FS_API}${dbPath(env)}/${parentPath}:runQuery`
    : `${FS_API}${dbPath(env)}:runQuery`;
  const res = await authedFetch(env, url, { method: "POST", body: JSON.stringify({ structuredQuery }) });
  if (!res.ok) throw await firestoreError(res, "query");
  const rows = await res.json();
  return rows
    .filter((r) => r.document)
    .map((r) => ({ ...fromFsFields(r.document.fields || {}), path: r.document.name, id: r.document.name.split("/").pop() }));
}

/** Deletes documents by their full path, 400 per commit. */
async function fsDeleteAll(env, paths) {
  const list = paths.filter(Boolean);
  for (let i = 0; i < list.length; i += 400) {
    await fsCommit(env, list.slice(i, i + 400).map((p) => ({ delete: p })));
  }
}

/** Removes one value from array fields of a document (for example, leaving a group). */
async function fsRemoveFromArrays(env, path, fieldNames, value) {
  await fsCommit(env, [{
    transform: {
      document: path,
      fieldTransforms: fieldNames.map((f) => ({ fieldPath: f, removeAllFromArray: { values: [{ stringValue: value }] } })),
    },
  }]);
}

/** Invite links can be revoked, and can have an expiry time. */
function assertInviteUsable(invite) {
  if (invite.revoked) throw new HttpError(404, "Ye invite link band kar diya gaya hai");
  if (invite.expiresAt && invite.expiresAt < Date.now()) throw new HttpError(404, "Ye invite link khatam ho chuka hai");
}

async function revokeInvite(request, env) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "revoke", 20);
  const body = await readJson(request);
  const code = typeof body.code === "string" ? body.code : "";
  if (!isId(code)) throw new HttpError(400, "Invite code galat hai");
  const invite = await fsGet(env, `groupInvites/${code}`);
  if (!invite || !isId(invite.groupId)) throw new HttpError(404, "Invite nahi mila");
  const group = await fsGet(env, `groups/${invite.groupId}`);
  const admins = group && Array.isArray(group.admins) ? group.admins : [];
  const allowed = group && (group.createdBy === uid || admins.includes(uid));
  if (!allowed) throw new HttpError(403, "Sirf group admin link band kar sakta hai");
  await fsCommit(env, [
    {
      update: { name: docName(env, `groupInvites/${code}`), fields: { revoked: { booleanValue: true } } },
      updateMask: { fieldPaths: ["revoked"] },
    },
  ]);
  return json(200, { ok: true });
}

/** Removes everything that belongs to a user. Messages in shared chats stay, but only with the sender's name. */
async function deleteUserData(env, uid) {
  const chats = await fsFind(env, null, "chats", [{ field: "participants", op: "ARRAY_CONTAINS", value: uid }]);
  for (const chat of chats) {
    const mine = await fsFind(env, `chats/${chat.id}`, "messages", [{ field: "senderUid", op: "EQUAL", value: uid }]);
    await fsDeleteAll(env, mine.map((m) => m.path));
  }
  const groups = await fsFind(env, null, "groups", [{ field: "members", op: "ARRAY_CONTAINS", value: uid }]);
  for (const g of groups) {
    const mine = await fsFind(env, `groups/${g.id}`, "messages", [{ field: "senderUid", op: "EQUAL", value: uid }]);
    await fsDeleteAll(env, mine.map((m) => m.path));
    const fields = ["members"];
    if (Array.isArray(g.admins) && g.admins.includes(uid)) fields.push("admins");
    await fsRemoveFromArrays(env, g.path, fields, uid);
  }
  const profile = await fsGet(env, `users/${uid}`);
  for (const sub of ["chatPrefs", "callLogs", "starred", "savedNotes", "devices"]) {
    const rows = await fsFind(env, `users/${uid}`, sub, []);
    await fsDeleteAll(env, rows.map((r) => r.path));
  }
  const mine = [];
  for (const [collection, field] of [["blocks", "blockerUid"], ["follows", "followerUid"], ["stories", "uid"], ["groupInvites", "createdBy"]]) {
    const rows = await fsFind(env, null, collection, [{ field, op: "EQUAL", value: uid }]);
    mine.push(...rows.map((r) => r.path));
  }
  if (profile && typeof profile.username === "string" && RE_USERNAME.test(profile.username)) {
    const claim = await fsGet(env, `usernames/${profile.username}`);
    if (claim && claim.uid === uid) mine.push(docName(env, `usernames/${profile.username}`));
  }
  mine.push(docName(env, `users/${uid}`));
  await fsDeleteAll(env, mine);
}

/** Deletes the login itself. Uses the user's own token, so only the owner can do it. */
async function deleteAuthAccount(env, idToken) {
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY || "")}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken }),
    }
  );
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    throw new SetupError(`Login account delete nahi hua (${res.status}: ${String(info.error?.message || "").slice(0, 160)}). Phir se try karo.`);
  }
}

async function deleteAccount(request, env) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "account-delete", 3);
  const token = RE_BEARER.exec(request.headers.get("authorization") || "")[1];
  await deleteUserData(env, uid);
  await deleteAuthAccount(env, token);
  return json(200, { ok: true });
}

/** Cron job: removes expired shared chats and old quota counters. Runs every 6 hours. */
async function cleanupExpired(env) {
  const now = new Date();
  const shares = await fsFind(env, null, "sharedChats", [{ field: "expiresAt", op: "LESS_THAN", value: now }]);
  for (const s of shares) {
    const msgs = await fsFind(env, `sharedChats/${s.id}`, "messages", []);
    await fsDeleteAll(env, [...msgs.map((m) => m.path), s.path]);
  }
  const expired = await fsFind(env, null, "messages", [{ field: "expiresAt", op: "LESS_THAN", value: now.getTime() }], 1000, true);
  await fsDeleteAll(env, expired.map((m) => m.path));
  const cutoff = dayKey(new Date(now.getTime() - 2 * 86400000));
  const quotas = await fsFind(env, null, "quotas", [{ field: "day", op: "LESS_THAN", value: cutoff }]);
  await fsDeleteAll(env, quotas.map((q) => q.path));
  return { sharesRemoved: shares.length, quotasRemoved: quotas.length, messagesRemoved: expired.length };
}

export { cleanupExpired };

// ---------- push notifications (FCM HTTP v1, sent by this server) ----------

/** One push to one device. Returns "ok", "gone" (token no longer valid) or "fail". */
async function sendPush(env, token, data, urgent) {
  const access = await googleAccessToken(env, MESSAGING_SCOPE);
  const res = await fetch(`https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/messages:send`, {
    method: "POST",
    headers: { authorization: `Bearer ${access}`, "content-type": "application/json" },
    body: JSON.stringify({ message: { token, data, android: { priority: urgent ? "HIGH" : "NORMAL", ttl: "60s" } } }),
  });
  if (res.ok) return { result: "ok" };
  const info = await res.json().catch(() => ({}));
  const errorCode = info.error?.details?.[0]?.errorCode || "";
  if (res.status === 404 || errorCode === "UNREGISTERED") return { result: "gone" };
  return {
    result: "fail",
    error: `${res.status} ${info.error?.status || ""}: ${String(info.error?.message || "").slice(0, 160)}`,
  };
}

/**
 * The app calls this right after it saves a message or starts a call.
 * The server checks the sender in the database, so a push can only be sent for a real message or call.
 */
async function notifyPush(request, env) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "notify", 60);
  const body = await readJson(request);
  const kind = body.kind;
  const id = isId(body.id) ? body.id : "";
  const messageId = isId(body.messageId) ? body.messageId : "";
  let receivers = [];
  let payload;
  let urgent = false;

  if (kind === "chat") {
    if (!id || !messageId) throw new HttpError(400, "id aur messageId chahiye");
    const chat = await fsGet(env, `chats/${id}`);
    if (!chat || !(chat.participants || []).includes(uid)) throw new HttpError(403, "Ye chat aapki nahi hai");
    const msg = await fsGet(env, `chats/${id}/messages/${messageId}`);
    if (!msg || msg.senderUid !== uid) throw new HttpError(403, "Ye message aapka nahi hai");
    receivers = chat.participants.filter((p) => p !== uid);
    const sender = await fsGet(env, `users/${uid}`);
    urgent = true;
    payload = { type: "message", chatKey: id, lockKey: `u_${uid}`, chatId: id, messageId };
  } else if (kind === "group") {
    if (!id || !messageId) throw new HttpError(400, "id aur messageId chahiye");
    const group = await fsGet(env, `groups/${id}`);
    if (!group || !(group.members || []).includes(uid)) throw new HttpError(403, "Ye group aapka nahi hai");
    const msg = await fsGet(env, `groups/${id}/messages/${messageId}`);
    if (!msg || msg.senderUid !== uid) throw new HttpError(403, "Ye message aapka nahi hai");
    receivers = group.members.filter((p) => p !== uid);
    urgent = true;
    payload = {
      type: "message",
      chatKey: `g_${id}`,
      lockKey: `g_${id}`,
      groupId: id,
      messageId,
    };
  } else if (kind === "call") {
    if (!id) throw new HttpError(400, "call id chahiye");
    const call = await fsGet(env, `calls/${id}`);
    if (!call || call.callerId !== uid || !isId(call.receiverId)) throw new HttpError(403, "Ye call aapki nahi hai");
    receivers = [call.receiverId];
    urgent = true;
    payload = {
      type: "incoming_call",
      callerUsername: String(call.callerUsername || "user").slice(0, 40),
      callType: String(call.type || "audio"),
    };
  } else if (kind === "groupcall") {
    if (!id) throw new HttpError(400, "group call id chahiye");
    const call = await fsGet(env, `groupCalls/${id}`);
    if (!call || call.starterUid !== uid || call.status !== "active") throw new HttpError(403, "Ye group call aapki nahi hai");
    if (Date.now() - (call.createdAtMs || 0) > 60000) throw new HttpError(403, "Ye group call purani ho chuki hai");
    receivers = (call.members || []).filter((p) => p !== uid);
    urgent = true;
    const kindLabel = call.type === "video" ? "Video call" : call.type === "screenshare" ? "Screen share call" : "Audio call";
    payload = {
      type: "group_call",
      title: `${String(call.groupName || "Group").slice(0, 60)} · @${String(call.starterUsername || "user").slice(0, 40)}`,
      body: `${kindLabel} shuru hui. Join karo.`,
      chatKey: `gc_${id}`,
    };
  } else {
    throw new HttpError(400, "kind 'chat', 'group', 'call' ya 'groupcall' hona chahiye");
  }

  // Nobody gets a push when either side blocked the other, or when they muted this chat.
  const now = Date.now();
  const allowed = [];
  for (const r of receivers.filter(isId)) {
    if (await fsGet(env, `blocks/${r}_${uid}`)) continue;
    if (await fsGet(env, `blocks/${uid}_${r}`)) continue;
    if (kind === "chat" || kind === "group") {
      const prefKey = kind === "chat" ? id : `g_${id}`;
      const pref = await fsGet(env, `users/${r}/chatPrefs/${prefKey}`);
      if (pref && pref.muted && (!pref.mutedUntil || now < pref.mutedUntil)) continue;
    }
    allowed.push(r);
  }

  let sent = 0;
  const failures = [];
  for (const r of allowed) {
    const devices = await fsFind(env, `users/${r}`, "devices", []);
    for (const dev of devices) {
      if (!dev.token) continue;
      const outcome = await sendPush(env, dev.token, payload, urgent);
      if (outcome.result === "ok") sent++;
      if (outcome.result === "gone") await fsDeleteAll(env, [dev.path]);
      if (outcome.result === "fail") failures.push(outcome.error);
    }
  }
  const summary = { sent, failed: failures.length, errors: failures.slice(0, 3) };
  console.log(JSON.stringify({ notify: kind, ...summary }));
  return json(200, summary);
}

// ---------- API ----------

function snapshotRow(m, seq, senders) {
  const sender = m.senderUid ? senders.get(`users/${m.senderUid}`) : null;
  const username = (sender && sender.username) || m.senderUsername || "user";
  return {
    seq,
    type: m.type === "photo" || m.type === "voice" || m.type === "location" ? m.type : "text",
    text: typeof m.text === "string" ? m.text.slice(0, 4000) : "",
    imageUrl: typeof m.imageUrl === "string" && m.imageUrl.startsWith("https://") ? m.imageUrl.slice(0, 500) : "",
    latitude: typeof m.latitude === "number" ? m.latitude : null,
    longitude: typeof m.longitude === "number" ? m.longitude : null,
    senderUsername: String(username).slice(0, 40),
    createdAt: new Date(m.createdAt || Date.now()),
  };
}

async function createShare(request, env, url) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "share-min", 10);
  await bumpQuota(env, uid, "shares", DAILY_LIMIT_SHARES);
  const body = await readJson(request);
  const sourceId = typeof body.sourceId === "string" ? body.sourceId : "";
  if (!isId(sourceId)) throw new HttpError(400, "ID galat hai");
  const days = clampDays(body.days);

  let sourcePath;
  let title;
  if (body.kind === "chat") {
    const chat = await fsGet(env, `chats/${sourceId}`);
    const participants = (chat && chat.participants) || [];
    if (!participants.includes(uid)) throw new HttpError(403, "Ye chat aapki nahi hai");
    const people = await fsGetMany(env, participants.filter(isId).map((p) => `users/${p}`));
    title = participants.map((p) => `@${((people.get(`users/${p}`) || {}).username) || "user"}`).join(" & ");
    sourcePath = `chats/${sourceId}`;
  } else if (body.kind === "group") {
    const group = await fsGet(env, `groups/${sourceId}`);
    if (!group || !(group.members || []).includes(uid)) throw new HttpError(403, "Ye group aapka nahi hai");
    title = group.name || "Group";
    sourcePath = `groups/${sourceId}`;
  } else {
    throw new HttpError(400, "kind 'chat' ya 'group' hona chahiye");
  }

  const now = Date.now();
  const latest = await fsQuery(env, sourcePath, "messages", {
    orderBy: "createdAt",
    direction: "DESCENDING",
    limit: SNAPSHOT_MAX_MESSAGES,
  });
  const live = latest.filter((m) => !(m.expiresAt && m.expiresAt < now)).reverse(); // oldest first

  const senderIds = [...new Set(live.map((m) => m.senderUid).filter(isId))];
  const senders = await fsGetMany(env, senderIds.map((s) => `users/${s}`));

  const token = randomToken();
  const expiresAt = new Date(now + days * 86400000);
  const writes = [
    {
      update: {
        name: docName(env, `sharedChats/${token}`),
        fields: toFsFields({
          kind: body.kind,
          sourceId,
          ownerUid: uid,
          title,
          createdAt: new Date(now),
          expiresAt,
          revoked: false,
          messageCount: live.length,
        }),
      },
    },
  ];
  live.forEach((m, i) => {
    writes.push({
      update: {
        name: docName(env, `sharedChats/${token}/messages/${String(i).padStart(4, "0")}`),
        fields: toFsFields(snapshotRow(m, i, senders)),
      },
    });
  });
  await fsCommit(env, writes);

  const base = (env.PUBLIC_BASE_URL || url.origin).replace(/\/+$/, "");
  return json(201, { token, url: `${base}/s/${token}`, expiresAt: expiresAt.getTime(), messageCount: live.length });
}

async function revokeShare(request, env, token) {
  const uid = await requireUid(request, env);
  if (!RE_TOKEN.test(token)) throw new HttpError(404, "Link nahi mila");
  const share = await fsGet(env, `sharedChats/${token}`);
  if (!share) throw new HttpError(404, "Link nahi mila");
  if (share.ownerUid !== uid) throw new HttpError(403, "Ye link aapne nahi banaya");
  await fsCommit(env, [
    {
      update: { name: docName(env, `sharedChats/${token}`), fields: { revoked: { booleanValue: true } } },
      updateMask: { fieldPaths: ["revoked"] },
    },
  ]);
  return json(200, { ok: true });
}

async function joinGroup(request, env) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "join", 10);
  const body = await readJson(request);
  const code = typeof body.code === "string" ? body.code : "";
  if (!isId(code)) throw new HttpError(400, "Invite code galat hai");

  const invite = await fsGet(env, `groupInvites/${code}`);
  if (!invite || !isId(invite.groupId)) throw new HttpError(404, "Invite code galat hai ya expire ho gaya");
  assertInviteUsable(invite);
  const group = await fsGet(env, `groups/${invite.groupId}`);
  if (!group) throw new HttpError(404, "Group nahi mila");

  const name = group.name || "Group";
  if ((group.members || []).includes(uid)) {
    return json(200, { groupId: invite.groupId, name, alreadyMember: true });
  }
  await fsCommit(env, [
    {
      transform: {
        document: docName(env, `groups/${invite.groupId}`),
        fieldTransforms: [{ fieldPath: "members", appendMissingElements: { values: [{ stringValue: uid }] } }],
      },
    },
  ]);
  return json(200, { groupId: invite.groupId, name, alreadyMember: false });
}

async function uploadPhoto(request, env) {
  const uid = await requireUid(request, env);
  await rateLimit(env, uid, "upload-min", 20);
  if (!env.IMGBB_API_KEY) throw new HttpError(500, "Server setup adhura hai");
  await bumpQuota(env, uid, "uploads", DAILY_LIMIT_UPLOADS);
  const body = await readJson(request);

  const image = typeof body.image === "string" ? body.image : "";
  if (image.length < 100 || image.length > 3000000 || !RE_BASE64.test(image)) {
    throw new HttpError(400, "Photo galat hai");
  }
  let expiration = null;
  if (body.expirationSeconds !== undefined && body.expirationSeconds !== null) {
    const exp = body.expirationSeconds;
    if (!Number.isInteger(exp) || exp < 60 || exp > 15552000) throw new HttpError(400, "Expiry galat hai");
    expiration = exp;
  }

  const form = new FormData();
  form.append("image", image);
  if (expiration) form.append("expiration", String(expiration));
  const res = await fetch(`https://api.imgbb.com/1/upload?key=${encodeURIComponent(env.IMGBB_API_KEY)}`, {
    method: "POST",
    body: form,
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data || !data.success) throw new HttpError(502, "Photo upload nahi ho paayi");
  return json(200, {
    url: data.data.url,
    thumbUrl: (data.data.thumb && data.data.thumb.url) || data.data.url,
  });
}

// ---------- router ----------

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : "/";
  let m;

  if (request.method === "GET") {
    if (path === "/") return landingPage();
    if (path === "/.well-known/assetlinks.json") return assetLinks(env);
    if (path === "/api/health") return json(200, await healthCheck(env));
    if ((m = /^\/u\/([^/]+)$/.exec(path))) return profilePage(safeDecode(m[1]), env);
    if ((m = /^\/g\/([^/]+)$/.exec(path))) return groupInvitePage(safeDecode(m[1]), env);
    if ((m = /^\/s\/([^/]+)$/.exec(path))) return sharedPage(safeDecode(m[1]), env);
    if (path === "/api/groups/preview") return groupPreview(request, env, url);
    return notFoundPage("Ye link nahi mila.");
  }

  if (request.method === "POST") {
    if (path === "/api/shares") return createShare(request, env, url);
    if ((m = /^\/api\/shares\/([^/]+)\/revoke$/.exec(path))) return revokeShare(request, env, safeDecode(m[1]));
    if (path === "/api/groups/join") return joinGroup(request, env);
    if (path === "/api/groups/invites/revoke") return revokeInvite(request, env);
    if (path === "/api/account/delete") return deleteAccount(request, env);
    if (path === "/api/notify") return notifyPush(request, env);
    if (path === "/api/upload") return uploadPhoto(request, env);
    return json(404, { error: "API nahi mila" });
  }

  return json(405, { error: "Ye method allowed nahi hai" });
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));
  },

  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (err) {
      if (err instanceof HttpError) return json(err.status, { error: err.message });
      console.error("unhandled error:", err && err.message);
      return json(500, { error: "Server mein kuch galat hua" });
    }
  },
};
