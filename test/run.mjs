// Local tests: a fake Firestore, fake Google login and a fake ImgBB stand in for the real services.
// The service-account JWT is really signed and verified, so the signing code is tested too.
import { webcrypto } from "node:crypto";
import assert from "node:assert/strict";
import worker, { cleanupExpired } from "../src/worker.js";

const { subtle } = webcrypto;
const PROJECT = "magicscreen-control";
const DB = `projects/${PROJECT}/databases/(default)/documents/`;
const BASE = "/v1/" + DB.slice(0, -1); // "/v1/projects/.../documents"
const SA_EMAIL = "svc@magicscreen-control.iam.gserviceaccount.com";
const ALICE_TOKEN = "alice-idtoken-0000000000000000000";
const BOB_TOKEN = "bob-idtoken-00000000000000000000";
const CAROL_TOKEN = "carol-idtoken-000000000000000000";
const ALICE = "aliceUid00000000000000001";
const BOB = "bobUid000000000000000002";
const CAROL = "carolUid00000000000000003";
const IMGBB_KEY = "imgbb-test-key";
const WEB_KEY = "web-test-key";

// ---- fake service account key pair (real RSA) ----
const kp = await subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"]
);
const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey));
const pem =
  "-----BEGIN PRIVATE KEY-----\n" +
  Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n") +
  "\n-----END PRIVATE KEY-----\n";

const env = {
  FIREBASE_PROJECT_ID: PROJECT,
  FIREBASE_WEB_API_KEY: WEB_KEY,
  FIREBASE_SERVICE_ACCOUNT_JSON: JSON.stringify({ client_email: SA_EMAIL, private_key: pem }),
  IMGBB_API_KEY: IMGBB_KEY,
  PUBLIC_BASE_URL: "https://links.test.example",
  ANDROID_PACKAGE: "com.magicscreencontrol.app",
  ANDROID_CERT_SHA256: "AE:89:BE:8B:C1:6D:58:81:74:6D:B7:76:23:79:B6:4A:AE:66:CA:CD:2B:2E:36:8C:39:17:56:7A:39:FB:F8:9D",
  PLAY_STORE_URL: "https://play.google.com/store/apps/details?id=com.magicscreencontrol.app",
};

// ---- fake Firestore: values kept in Firestore REST format ----
const store = new Map();
function encValue(v) {
  if (v === null) return { nullValue: null };
  if (typeof v === "string") return { stringValue: v };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(encValue) } };
  return { mapValue: { fields: encFields(v) } };
}
function encFields(o) {
  const f = {};
  for (const [k, v] of Object.entries(o)) f[k] = encValue(v);
  return f;
}
function decValue(v) {
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("timestampValue" in v) return Date.parse(v.timestampValue);
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(decValue);
  if ("mapValue" in v) return decFields(v.mapValue.fields || {});
  return null;
}
function decFields(f) {
  const o = {};
  for (const [k, v] of Object.entries(f)) o[k] = decValue(v);
  return o;
}
const put = (path, obj) => store.set(path, encFields(obj));
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---- fake outside services ----
const jsonRes = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const firestoreAuthSeen = [];

async function oauthFake(init) {
  const body = new URLSearchParams(init.body);
  const [h, c, s] = body.get("assertion").split(".");
  const ok = await subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    kp.publicKey,
    Buffer.from(s, "base64url"),
    new TextEncoder().encode(`${h}.${c}`)
  );
  if (!ok) return jsonRes(400, { error: "bad signature" });
  const claims = JSON.parse(Buffer.from(c, "base64url").toString("utf8"));
  if (claims.iss !== SA_EMAIL || !["https://www.googleapis.com/auth/datastore", "https://www.googleapis.com/auth/firebase.messaging", "https://www.googleapis.com/auth/cloud-platform"].includes(claims.scope)) {
    return jsonRes(400, { error: "bad claims" });
  }
  return jsonRes(200, { access_token: "TOKEN-OK", expires_in: 3600 });
}

const deletedAuth = new Set();
function lookupFake(url, init) {
  if (url.searchParams.get("key") !== WEB_KEY) return jsonRes(403, { error: "key" });
  const { idToken } = JSON.parse(init.body);
  if (url.pathname.endsWith(":delete")) {
    if (idToken === CAROL_TOKEN) {
      deletedAuth.add(CAROL);
      return jsonRes(200, {});
    }
    return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
  }
  if (idToken === ALICE_TOKEN) return jsonRes(200, { users: [{ localId: ALICE }] });
  if (idToken === BOB_TOKEN) return jsonRes(200, { users: [{ localId: BOB }] });
  if (idToken === CAROL_TOKEN && !deletedAuth.has(CAROL)) return jsonRes(200, { users: [{ localId: CAROL }] });
  return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
}

const pushed = [];
let fakeDatabases = [{ name: "projects/magicscreen-control/databases/(default)", type: "FIRESTORE_NATIVE" }];
let fcmBroken = false;
function fcmFake(init) {
  const body = JSON.parse(init.body);
  const message = body.message;
  if (body.validate_only) {
    if (fcmBroken) return jsonRes(403, { error: { status: "PERMISSION_DENIED", message: "Firebase Cloud Messaging API has not been used in project magicscreen-control before or it is disabled." } });
    return jsonRes(400, { error: { status: "INVALID_ARGUMENT", message: "The registration token is not a valid FCM registration token" } });
  }
  if (message.token === "tok-perm") return jsonRes(403, { error: { status: "PERMISSION_DENIED", message: "Permission denied on resource" } });
  if (message.token === "tok-dead") {
    return jsonRes(404, { error: { status: "NOT_FOUND", details: [{ errorCode: "UNREGISTERED" }] } });
  }
  pushed.push({ token: message.token, data: message.data, priority: message.android.priority });
  return jsonRes(200, { name: "projects/x/messages/1" });
}

function imgbbFake(url, init) {
  if (url.searchParams.get("key") !== IMGBB_KEY) return jsonRes(403, {});
  assert.ok(init.body instanceof FormData, "imgbb gets form data");
  assert.ok(init.body.get("image").length > 100, "image sent");
  return jsonRes(200, {
    success: true,
    data: { url: "https://i.ibb.co/abc/photo.jpg", thumb: { url: "https://i.ibb.co/abc/thumb.jpg" } },
  });
}

function commitFake(writes) {
  for (const w of writes) {
    if (w.delete) {
      store.delete(w.delete.slice(DB.length));
      continue;
    }
    if (w.update) {
      const path = w.update.name.slice(DB.length);
      if (w.updateMask) {
        const cur = store.get(path);
        if (!cur) return jsonRes(404, { error: "masked update on missing doc" });
        for (const f of w.updateMask.fieldPaths) cur[f] = w.update.fields[f];
      } else {
        store.set(path, w.update.fields);
      }
    } else if (w.transform) {
      const path = w.transform.document.slice(DB.length);
      const cur = store.get(path);
      if (!cur) return jsonRes(404, { error: "transform on missing doc" });
      for (const ft of w.transform.fieldTransforms) {
        if (ft.removeAllFromArray) {
          const drop = ft.removeAllFromArray.values.map((v) => v.stringValue);
          if (cur[ft.fieldPath]) cur[ft.fieldPath].arrayValue.values = cur[ft.fieldPath].arrayValue.values.filter((v) => !drop.includes(v.stringValue));
          continue;
        }
        if (!cur[ft.fieldPath]) cur[ft.fieldPath] = { arrayValue: { values: [] } };
        const arr = cur[ft.fieldPath].arrayValue.values;
        for (const v of ft.appendMissingElements.values) {
          if (!arr.some((x) => x.stringValue === v.stringValue)) arr.push(v);
        }
      }
    }
  }
  return jsonRes(200, { writeResults: writes.map(() => ({})) });
}

function matches(fields, f) {
  if (f.compositeFilter) return f.compositeFilter.filters.every((x) => matches(fields, x));
  const ff = f.fieldFilter;
  const path = ff.field.fieldPath;
  const val = fields[path] ? decValue(fields[path]) : undefined;
  const want = decValue(ff.value);
  if (ff.op === "EQUAL") return val === want;
  if (ff.op === "ARRAY_CONTAINS") return Array.isArray(val) && val.includes(want);
  if (ff.op === "LESS_THAN") return val !== undefined && val < want;
  return false;
}

function queryFake(url, sq) {
  const isRoot = url.pathname === BASE + ":runQuery";
  const parent = isRoot ? "" : decodeURIComponent(url.pathname.slice(BASE.length + 1, -":runQuery".length));
  const coll = sq.from[0].collectionId;
  const prefix = isRoot ? `${coll}/` : `${parent}/${coll}/`;
  let rows = [];
  const allDescendants = !!sq.from[0].allDescendants;
  for (const [path, fields] of store) {
    if (allDescendants) {
      const segs = path.split("/");
      if (segs.length % 2 === 0 && segs[segs.length - 2] === coll) rows.push({ document: { name: DB + path, fields }, readTime: "t" });
      continue;
    }
    if (path.startsWith(prefix) && !path.slice(prefix.length).includes("/")) {
      rows.push({ document: { name: DB + path, fields }, readTime: "t" });
    }
  }
  if (sq.where) rows = rows.filter((r) => matches(r.document.fields, sq.where));
  if (sq.orderBy) {
    const f = sq.orderBy[0].field.fieldPath;
    const dir = sq.orderBy[0].direction === "DESCENDING" ? -1 : 1;
    const val = (row) => decValue(row.document.fields[f] || { nullValue: null });
    rows.sort((a, b) => dir * compare(val(a), val(b)));
  }
  if (sq.limit) rows = rows.slice(0, sq.limit);
  return jsonRes(200, rows);
}

function firestoreFake(url, method, init) {
  if (!url.pathname.startsWith(BASE)) return jsonRes(404, {});
  if (method === "GET") {
    const path = decodeURIComponent(url.pathname.slice(BASE.length + 1));
    if (!store.has(path)) return jsonRes(404, { error: { status: "NOT_FOUND" } });
    return jsonRes(200, { name: DB + path, fields: store.get(path) });
  }
  if (url.pathname.endsWith(":commit")) return commitFake(JSON.parse(init.body).writes);
  if (url.pathname.endsWith(":batchGet")) {
    const { documents } = JSON.parse(init.body);
    return jsonRes(
      200,
      documents.map((name) => {
        const p = name.slice(DB.length);
        return store.has(p) ? { found: { name, fields: store.get(p) } } : { missing: name };
      })
    );
  }
  if (url.pathname.endsWith(":runQuery")) return queryFake(url, JSON.parse(init.body).structuredQuery);
  return jsonRes(404, {});
}

globalThis.fetch = async (input, init = {}) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  const method = (init.method || "GET").toUpperCase();
  if (url.hostname === "oauth2.googleapis.com") return oauthFake(init);
  if (url.hostname === "identitytoolkit.googleapis.com") return lookupFake(url, init);
  if (url.hostname === "api.imgbb.com") return imgbbFake(url, init);
  if (url.hostname === "firestore.googleapis.com" && url.pathname.endsWith("/databases")) {
    return jsonRes(200, { databases: fakeDatabases });
  }
  if (url.hostname === "firestore.googleapis.com") {
    firestoreAuthSeen.push(new Headers(init.headers).get("authorization"));
    return firestoreFake(url, method, init);
  }
  if (url.hostname === "fcm.googleapis.com") return fcmFake(init);
  throw new Error("unexpected outbound call: " + url.href);
};

// ---- seed data ----
const T0 = Date.now() - 3600_000;
put(`users/${ALICE}`, { username: "alice", displayName: "Alice", bio: "Hi <b>there</b>", photoURL: "https://i.ibb.co/a/alice.jpg" });
put("usernames/alice", { uid: ALICE });
put(`users/${BOB}`, { username: "bob", displayName: "Bob" });
put("usernames/bob", { uid: BOB });
put("chats/chat_ab", { participants: [ALICE, BOB] });
put("chats/chat_private", { participants: [ALICE] });
put("chats/chat_ab/messages/m1", { senderUid: ALICE, type: "text", text: "<script>alert(1)</script> hi", createdAt: new Date(T0 + 1000) });
put("chats/chat_ab/messages/m2", { senderUid: BOB, type: "photo", imageUrl: "https://i.ibb.co/x/p.jpg", text: "", senderUsername: "bobOld", createdAt: new Date(T0 + 2000) });
put("chats/chat_ab/messages/m3", { senderUid: BOB, type: "voice", audioBase64: "QUFBQUFBQUFBQUFB", createdAt: new Date(T0 + 3000) });
put("chats/chat_ab/messages/m4", { senderUid: ALICE, type: "location", latitude: 28.6, longitude: 77.2, createdAt: new Date(T0 + 4000) });
put("chats/chat_ab/messages/mExpired", { senderUid: ALICE, type: "text", text: "gone soon", createdAt: new Date(T0 + 500), expiresAt: new Date(Date.now() - 1000) });
put("groups/grp1", { name: "Study <Group>", members: [ALICE], createdBy: ALICE, admins: [] });
put("groups/grp2", { name: "Private", members: [ALICE] });
put("groupInvites/INVITE123", { groupId: "grp1", createdBy: ALICE });

// ---- helpers ----
function req(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  let payload;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = typeof body === "string" ? body : JSON.stringify(body);
  }
  return worker.fetch(new Request("https://links.test.example" + path, { method, headers, body: payload }), env);
}
const aliceChatShare = (extra = {}) =>
  req("POST", "/api/shares", { token: ALICE_TOKEN, body: { kind: "chat", sourceId: "chat_ab", ...extra } });

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
let shareToken = "";

// ---- public pages ----
test("landing page loads", async () => {
  const r = await req("GET", "/");
  assert.equal(r.status, 200);
  assert.match(await r.text(), /Magic Screen Control/);
});

test("profile link opens the app and offers the store link", async () => {
  const r = await req("GET", "/u/alice");
  assert.equal(r.status, 200);
  const body = await r.text();
  assert.ok(body.includes("magicscreencontrol://u/alice"));
  assert.ok(body.includes("play.google.com"));
});

test("bad profile names are 404", async () => {
  for (const p of ["/u/ALICE", "/u/x", "/u/a%3Cscript%3E", "/u/%E0%A4%A", "/u/a%20b"]) {
    const r = await req("GET", p);
    assert.equal(r.status, 404, p);
  }
});

test("assetlinks lists the app package and its certificate fingerprint", async () => {
  const r = await req("GET", "/.well-known/assetlinks.json");
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data[0].target.package_name, "com.magicscreencontrol.app");
  assert.deepEqual(data[0].target.sha256_cert_fingerprints, [env.ANDROID_CERT_SHA256]);
});

test("pages send security headers", async () => {
  const r = await req("GET", "/u/alice");
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  assert.match(r.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal(r.headers.get("referrer-policy"), "no-referrer");
});

test("group invite page shows the escaped group name", async () => {
  const r = await req("GET", "/g/INVITE123");
  const body = await r.text();
  assert.equal(r.status, 200);
  assert.ok(body.includes("Study &lt;Group&gt;"));
  assert.ok(body.includes("magicscreencontrol://join/INVITE123"));
  assert.equal((await req("GET", "/g/NOPE0000")).status, 404);
});

// ---- login checks ----
test("share API needs a valid login", async () => {
  assert.equal((await req("POST", "/api/shares", { body: { kind: "chat", sourceId: "chat_ab" } })).status, 401);
  assert.equal((await req("POST", "/api/shares", { token: "bad-but-long-enough-token-0000", body: {} })).status, 401);
  assert.equal((await req("POST", "/api/shares", { token: "x", body: {} })).status, 401);
});

test("service account requests use the signed-in server token", async () => {
  assert.ok(firestoreAuthSeen.length > 0);
  assert.ok(firestoreAuthSeen.every((a) => a === "Bearer TOKEN-OK"));
});

// ---- chat share (snapshot) ----
test("owner creates a chat share as a snapshot with no uids and no audio data", async () => {
  const r = await aliceChatShare({ days: 2 });
  assert.equal(r.status, 201, await r.clone().text());
  const data = await r.json();
  shareToken = data.token;
  assert.equal(data.token.length, 32);
  assert.ok(data.url.startsWith("https://links.test.example/s/"));
  assert.equal(data.messageCount, 4, "expired message is left out");
  const doc = store.get(`sharedChats/${shareToken}`);
  assert.equal(decValue(doc.ownerUid), ALICE);
  assert.equal(decValue(doc.title), "@alice & @bob");
  for (let i = 0; i < 4; i++) {
    const row = store.get(`sharedChats/${shareToken}/messages/000${i}`);
    assert.ok(row, "snapshot row " + i);
    assert.equal(row.senderUid, undefined, "no uid in snapshot");
    assert.equal(row.audioBase64, undefined, "no audio data in snapshot");
  }
  assert.equal(decValue(store.get(`sharedChats/${shareToken}/messages/0002`).type), "voice");
});

test("share expiry is clamped to 1..30 days", async () => {
  const data = await (await aliceChatShare({ days: 999 })).json();
  const days = (data.expiresAt - Date.now()) / 86400000;
  assert.ok(days > 29.9 && days <= 30.01, "days=" + days);
});

test("bad share input is rejected", async () => {
  assert.equal((await req("POST", "/api/shares", { token: ALICE_TOKEN, body: { kind: "video", sourceId: "chat_ab" } })).status, 400);
  assert.equal((await req("POST", "/api/shares", { token: ALICE_TOKEN, body: { kind: "chat", sourceId: "a/b" } })).status, 400);
  assert.equal((await req("POST", "/api/shares", { token: ALICE_TOKEN, body: "{bad json" })).status, 400);
});

test("a user cannot share a chat they are not in", async () => {
  const r = await req("POST", "/api/shares", { token: BOB_TOKEN, body: { kind: "chat", sourceId: "chat_private" } });
  assert.equal(r.status, 403);
});

test("group share works for members and is refused to outsiders", async () => {
  const ok = await req("POST", "/api/shares", { token: ALICE_TOKEN, body: { kind: "group", sourceId: "grp2" } });
  assert.equal(ok.status, 201);
  const bad = await req("POST", "/api/shares", { token: BOB_TOKEN, body: { kind: "group", sourceId: "grp2" } });
  assert.equal(bad.status, 403);
});

test("shared page is read only, escapes text, and shows no uids or audio", async () => {
  const r = await req("GET", `/s/${shareToken}`);
  assert.equal(r.status, 200);
  const body = await r.text();
  assert.ok(body.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "text is escaped");
  assert.ok(!body.includes("<script>alert"), "no raw script tag");
  assert.ok(body.includes('<img src="https://i.ibb.co/x/p.jpg"'), "photo shown");
  assert.ok(body.includes("Voice message"), "voice placeholder");
  assert.ok(body.includes("maps.google.com/?q=28.6,77.2"), "location link");
  assert.ok(body.includes("@bob"), "current username shown");
  assert.ok(!body.includes("bobOld"), "old stored name not used");
  assert.ok(!body.includes(ALICE) && !body.includes(BOB), "no uid leaked");
  assert.ok(!body.includes("QUFB"), "no audio data leaked");
  assert.ok(!body.includes("gone soon"), "expired message not shown");
  assert.ok(body.includes("sirf padhne"), "read-only notice shown");
});

test("unknown or malformed share tokens are 404", async () => {
  assert.equal((await req("GET", "/s/" + "A".repeat(32))).status, 404);
  assert.equal((await req("GET", "/s/short")).status, 404);
});

test("only the owner can revoke, and a revoked link stops working", async () => {
  const created = await (await aliceChatShare()).json();
  assert.equal((await req("POST", `/api/shares/${created.token}/revoke`, { token: BOB_TOKEN })).status, 403);
  assert.equal((await req("GET", `/s/${created.token}`)).status, 200);
  assert.equal((await req("POST", `/api/shares/${created.token}/revoke`, { token: ALICE_TOKEN })).status, 200);
  const gone = await req("GET", `/s/${created.token}`);
  assert.equal(gone.status, 404);
  assert.match(await gone.text(), /band kar diya/);
});

test("expired share shows the expired page", async () => {
  const created = await (await aliceChatShare()).json();
  store.get(`sharedChats/${created.token}`).expiresAt = encValue(new Date(Date.now() - 1000));
  const r = await req("GET", `/s/${created.token}`);
  assert.equal(r.status, 404);
  assert.match(await r.text(), /khatam/);
});

test("profile page shows name, handle, bio and photo", async () => {
  const r = await req("GET", "/u/alice");
  const body = await r.text();
  assert.equal(r.status, 200);
  assert.ok(body.includes("Alice"), "display name");
  assert.ok(body.includes("@alice"), "handle");
  assert.ok(body.includes("Hi &lt;b&gt;there&lt;/b&gt;"), "bio is escaped");
  assert.ok(body.includes('<img class="avatar" src="https://i.ibb.co/a/alice.jpg"'), "photo");
  assert.ok(body.includes("magicscreencontrol://u/alice"), "opens the app");
});

test("profile page without a photo shows the first letter", async () => {
  const body = await (await req("GET", "/u/bob")).text();
  assert.ok(body.includes('<div class="avatar initial">B</div>'));
});

test("profile link for an unknown username is 404", async () => {
  assert.equal((await req("GET", "/u/ghostuser")).status, 404);
});

test("group preview needs login and returns the group info", async () => {
  assert.equal((await req("GET", "/api/groups/preview?code=INVITE123")).status, 401);
  const r = await req("GET", "/api/groups/preview?code=INVITE123", { token: BOB_TOKEN });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.name, "Study <Group>");
  assert.equal(data.memberCount, 1);
  assert.equal(data.alreadyMember, false);
  const alice = await (await req("GET", "/api/groups/preview?code=INVITE123", { token: ALICE_TOKEN })).json();
  assert.equal(alice.alreadyMember, true);
});

test("group page shows the member count", async () => {
  const body = await (await req("GET", "/g/INVITE123")).text();
  assert.ok(body.includes("Private group · 1 members"));
});

test("health check reports each part and is ready", async () => {
  const r = await req("GET", "/api/health");
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.serviceAccount, "ok");
  assert.equal(data.firestore, "ok");
  assert.equal(data.webApiKey, "ok");
  assert.equal(data.messaging, "ok");
  assert.equal(data.ready, true);
});

// ---- group join ----
test("join needs login, validates the code, and adds the member once", async () => {
  assert.equal((await req("POST", "/api/groups/join", { body: { code: "INVITE123" } })).status, 401);
  assert.equal((await req("POST", "/api/groups/join", { token: BOB_TOKEN, body: { code: "x" } })).status, 400);
  const r = await req("POST", "/api/groups/join", { token: BOB_TOKEN, body: { code: "INVITE123" } });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).alreadyMember, false);
  assert.ok(decValue(store.get("groups/grp1").members).includes(BOB));
  const again = await req("POST", "/api/groups/join", { token: BOB_TOKEN, body: { code: "INVITE123" } });
  assert.equal((await again.json()).alreadyMember, true);
  assert.equal(decValue(store.get("groups/grp1").members).filter((x) => x === BOB).length, 1);
});

test("join with an unknown code is 404", async () => {
  const r = await req("POST", "/api/groups/join", { token: BOB_TOKEN, body: { code: "NOPE0000" } });
  assert.equal(r.status, 404);
});

// ---- photo upload ----
test("upload needs login and keeps the ImgBB key on the server", async () => {
  assert.equal((await req("POST", "/api/upload", { body: { image: "QUFB".repeat(60) } })).status, 401);
  const r = await req("POST", "/api/upload", { token: BOB_TOKEN, body: { image: "QUFB".repeat(60) } });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.url, "https://i.ibb.co/abc/photo.jpg");
  assert.equal(data.thumbUrl, "https://i.ibb.co/abc/thumb.jpg");
});

test("upload rejects bad data and bad expiry", async () => {
  assert.equal((await req("POST", "/api/upload", { token: BOB_TOKEN, body: { image: "!".repeat(150) } })).status, 400);
  assert.equal((await req("POST", "/api/upload", { token: BOB_TOKEN, body: { image: "QUFB".repeat(60), expirationSeconds: 10 } })).status, 400);
  const ok = await req("POST", "/api/upload", { token: BOB_TOKEN, body: { image: "QUFB".repeat(60), expirationSeconds: 3600 } });
  assert.equal(ok.status, 200);
});

// ---- routing ----
test("wrong method and unknown API paths", async () => {
  assert.equal((await req("PUT", "/")).status, 405);
  assert.equal((await req("POST", "/api/nothing", { token: ALICE_TOKEN, body: {} })).status, 404);
});

test("only a group admin can revoke an invite, and a revoked link stops working", async () => {
  const bobTry = await req("POST", "/api/groups/invites/revoke", { token: BOB_TOKEN, body: { code: "INVITE123" } });
  assert.equal(bobTry.status, 403);
  const ok = await req("POST", "/api/groups/invites/revoke", { token: ALICE_TOKEN, body: { code: "INVITE123" } });
  assert.equal(ok.status, 200);
  assert.equal((await req("GET", "/g/INVITE123")).status, 404);
  const preview = await req("GET", "/api/groups/preview?code=INVITE123", { token: BOB_TOKEN });
  assert.equal(preview.status, 404);
  assert.match((await preview.json()).error, /band/);
});

test("too many requests in one minute get 429", async () => {
  const minute = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  put(`quotas/${BOB}_preview_${minute}`, { count: 30, uid: BOB, bucket: "preview", day });
  assert.equal((await req("GET", "/api/groups/preview?code=INVITE123", { token: BOB_TOKEN })).status, 429);
});

test("account delete removes my data and my login on the server", async () => {
  put(`users/${CAROL}`, { username: "carol", displayName: "Carol" });
  put("usernames/carol", { uid: CAROL });
  put("chats/chat_ca", { participants: [CAROL, ALICE] });
  put("chats/chat_ca/messages/m1", { senderUid: CAROL, type: "text", text: "carol msg", createdAt: new Date() });
  put("chats/chat_ca/messages/m2", { senderUid: ALICE, type: "text", text: "alice msg", createdAt: new Date() });
  put(`users/${CAROL}/starred/s1`, { note: "x" });
  put(`users/${CAROL}/devices/c1`, { token: "tok-carol" });
  put("groups/grp1", { name: "Study <Group>", members: [ALICE, BOB, CAROL], createdBy: ALICE, admins: [] });
  const r = await req("POST", "/api/account/delete", { token: CAROL_TOKEN, body: {} });
  assert.equal(r.status, 200, await r.clone().text());
  assert.ok(!store.has(`users/${CAROL}`), "profile removed");
  assert.ok(!store.has("usernames/carol"), "username removed");
  assert.ok(!store.has("chats/chat_ca/messages/m1"), "my message removed");
  assert.ok(store.has("chats/chat_ca/messages/m2"), "other people's messages stay");
  assert.ok(!store.has(`users/${CAROL}/starred/s1`), "my saved items removed");
  assert.ok(!store.has(`users/${CAROL}/devices/c1`), "my device tokens removed");
  assert.ok(!decValue(store.get("groups/grp1").members).includes(CAROL), "left the group");
  assert.equal((await req("POST", "/api/shares", { token: CAROL_TOKEN, body: { kind: "chat", sourceId: "chat_ca" } })).status, 401);
});

test("cleanup removes expired shares and old quota counters, keeps recent ones", async () => {
  assert.equal(typeof worker.scheduled, "function");
  put("sharedChats/OLDSHARE0000000000000000000000000", { kind: "chat", ownerUid: ALICE, title: "old", expiresAt: new Date(Date.now() - 86400000), revoked: false, messageCount: 1 });
  put("sharedChats/OLDSHARE0000000000000000000000000/messages/0000", { seq: 0, type: "text", text: "old", senderUsername: "x", createdAt: new Date() });
  put("quotas/oldquota_shares_20200101", { count: 3, uid: ALICE, bucket: "shares", day: "20200101" });
  await cleanupExpired(env);
  assert.ok(!store.has("sharedChats/OLDSHARE0000000000000000000000000"), "expired share removed");
  assert.ok(!store.has("sharedChats/OLDSHARE0000000000000000000000000/messages/0000"), "its messages removed");
  assert.ok(!store.has("quotas/oldquota_shares_20200101"), "old quota removed");
  assert.ok(store.has(`sharedChats/${shareToken}`), "recent share kept");
});

test("push: a new chat message goes to the other person's phone", async () => {
  put(`users/${BOB}/devices/d1`, { token: "tok-bob-1" });
  put("chats/chat_ab/messages/mNew", { senderUid: ALICE, type: "text", text: "hello bob", createdAt: new Date() });
  pushed.length = 0;
  const r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "chat", id: "chat_ab", messageId: "mNew" } });
  assert.equal(r.status, 200, await r.clone().text());
  assert.equal((await r.json()).sent, 1);
  const msg = pushed.find((p) => p.token === "tok-bob-1");
  assert.ok(msg, "bob got a push");
  assert.equal(msg.data.title, undefined, "no title in the push");
  assert.equal(msg.data.body, undefined, "no text in the push");
  assert.ok(!JSON.stringify(msg.data).includes("hello bob"), "the message text never leaves the server in a push");
  assert.equal(msg.data.chatKey, "chat_ab");
  assert.equal(msg.data.messageId, "mNew");
  assert.equal(msg.data.chatId, "chat_ab");
  assert.equal(msg.priority, "HIGH");
});

test("push: you can only announce your own message", async () => {
  const r = await req("POST", "/api/notify", { token: BOB_TOKEN, body: { kind: "chat", id: "chat_ab", messageId: "mNew" } });
  assert.equal(r.status, 403);
});

test("push: muted chats and blocked people get no push", async () => {
  put(`users/${BOB}/chatPrefs/chat_ab`, { muted: true, mutedUntil: 0 });
  let r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "chat", id: "chat_ab", messageId: "mNew" } });
  assert.equal((await r.json()).sent, 0, "muted");
  store.delete(`users/${BOB}/chatPrefs/chat_ab`);
  put(`blocks/${BOB}_${ALICE}`, { blockerUid: BOB, blockedUid: ALICE });
  r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "chat", id: "chat_ab", messageId: "mNew" } });
  assert.equal((await r.json()).sent, 0, "blocked");
  store.delete(`blocks/${BOB}_${ALICE}`);
});

test("push: a group message goes to the other members", async () => {
  put("groups/grp1/messages/gmsg1", { senderUid: ALICE, senderUsername: "alice", type: "text", text: "hi group", createdAt: new Date() });
  pushed.length = 0;
  const r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "group", id: "grp1", messageId: "gmsg1" } });
  assert.equal(r.status, 200);
  const msg = pushed.find((p) => p.token === "tok-bob-1");
  assert.ok(msg, "bob got a group push");
  assert.equal(msg.data.title, undefined, "no title in the group push");
  assert.equal(msg.data.body, undefined, "no text in the group push");
  assert.equal(msg.data.groupId, "grp1");
  assert.equal(msg.data.messageId, "gmsg1");
  assert.equal(msg.data.chatKey, "g_grp1");
});

test("push: an incoming call rings the receiver with high priority", async () => {
  put("calls/call_push_1", { callerId: ALICE, receiverId: BOB, callerUsername: "alice", type: "audio", status: "calling" });
  pushed.length = 0;
  const r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "call", id: "call_push_1" } });
  assert.equal(r.status, 200);
  const msg = pushed.find((p) => p.token === "tok-bob-1");
  assert.ok(msg, "bob's phone rings");
  assert.equal(msg.data.type, "incoming_call");
  assert.equal(msg.priority, "HIGH");
});

test("push: a token that is no longer valid is removed", async () => {
  put(`users/${BOB}/devices/dead`, { token: "tok-dead" });
  await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "chat", id: "chat_ab", messageId: "mNew" } });
  assert.ok(!store.has(`users/${BOB}/devices/dead`));
  assert.ok(store.has(`users/${BOB}/devices/d1`), "live token kept");
});

test("push: a group call start rings every other member", async () => {
  put("groupCalls/gc_grp1", { starterUid: ALICE, starterUsername: "alice", groupName: "Study <Group>", type: "audio", status: "active", members: [ALICE, BOB], createdAtMs: Date.now() });
  pushed.length = 0;
  const r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "groupcall", id: "gc_grp1" } });
  assert.equal(r.status, 200, await r.clone().text());
  const msg = pushed.find((p) => p.token === "tok-bob-1");
  assert.ok(msg, "bob gets the group call push");
  assert.equal(msg.data.type, "group_call");
  assert.equal(msg.data.chatKey, "gc_gc_grp1");
  assert.match(msg.data.title, /Study <Group>/);
  assert.equal(msg.priority, "HIGH");
});

test("push: an old group call does not ring anyone", async () => {
  put("groupCalls/gc_old1", { starterUid: ALICE, starterUsername: "alice", groupName: "Study <Group>", type: "audio", status: "active", members: [ALICE, BOB], createdAtMs: Date.now() - 600000 });
  const r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "groupcall", id: "gc_old1" } });
  assert.equal(r.status, 403);
});

test("cleanup removes expired disappearing messages in chats and groups, keeps the rest", async () => {
  put("chats/chat_ab/messages/exp1", { senderUid: ALICE, type: "text", text: "gone soon", expiresAt: Date.now() - 1000, createdAt: new Date() });
  put("groups/grp1/messages/gexp1", { senderUid: ALICE, senderUsername: "alice", type: "text", text: "gone soon", expiresAt: Date.now() - 1000, createdAt: new Date() });
  const result = await cleanupExpired(env);
  assert.equal(result.messagesRemoved >= 2, true);
  assert.ok(!store.has("chats/chat_ab/messages/exp1"), "expired chat message removed");
  assert.ok(!store.has("groups/grp1/messages/gexp1"), "expired group message removed");
  assert.ok(store.has("chats/chat_ab/messages/mNew"), "message without a timer kept");
});

test("health check says when the (default) database is missing from this project", async () => {
  fakeDatabases = [{ name: "projects/magicscreen-control/databases/other", type: "FIRESTORE_NATIVE" }];
  const r = await req("GET", "/api/health");
  const data = await r.json();
  fakeDatabases = [{ name: "projects/magicscreen-control/databases/(default)", type: "FIRESTORE_NATIVE" }];
  assert.match(data.firestore, /nahi hai/);
  assert.match(data.firestore, /other/);
  assert.equal(data.ready, false);
});

test("push: a failed send is reported with the reason, not hidden", async () => {
  put(`users/${BOB}/devices/perm`, { token: "tok-perm" });
  const r = await req("POST", "/api/notify", { token: ALICE_TOKEN, body: { kind: "chat", id: "chat_ab", messageId: "mNew" } });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.ok(data.failed >= 1, "failure counted");
  assert.match(data.errors[0], /403/, "the reason is returned");
  store.delete(`users/${BOB}/devices/perm`);
});

test("health: messaging says when FCM is disabled for the project", async () => {
  fcmBroken = true;
  const data = await (await req("GET", "/api/health")).json();
  fcmBroken = false;
  assert.match(data.messaging, /^error 403/);
  assert.equal(data.ready, false);
});

test("health: a missing document is fine, a missing database is reported", async () => {
  // the test fake answers any unknown document with 404 NOT_FOUND (no message), which the real service also does
  const ok = await (await req("GET", "/api/health")).json();
  assert.equal(ok.firestore, "ok");
  assert.equal(ok.ready, true);
});

// ---- daily limit (last, because it fills Alice's quota) ----
test("daily share limit stops abuse with 429", async () => {
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  put(`quotas/${ALICE}_shares_${day}`, { count: 50, uid: ALICE, bucket: "shares", day });
  assert.equal((await aliceChatShare()).status, 429);
});

// ---- runner ----
let failed = 0;
for (const t of tests) {
  try {
    await t.fn();
    console.log("PASS", t.name);
  } catch (err) {
    failed++;
    console.log("FAIL", t.name, "\n     ", err.message);
  }
}
console.log(failed ? `\n${failed} of ${tests.length} failed` : `\nall ${tests.length} tests passed`);
process.exit(failed ? 1 : 0);
