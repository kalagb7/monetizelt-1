"use strict";

/* ============================= IMPORTS & SECRETS ============================= */

const { defineSecret } = require("firebase-functions/params");
const { setGlobalOptions } = require("firebase-functions/v2");
const { onRequest } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { onMessagePublished } = require("firebase-functions/v2/pubsub");

const admin = require("firebase-admin");
const crypto = require("crypto");
const path = require("path");

// Secrets
const sendgridApiKey = defineSecret("SENDGRID_API_KEY");
const paypalClientId = defineSecret("PAYPAL_CLIENT_ID");
const paypalClientSecret = defineSecret("PAYPAL_CLIENT_SECRET");
const stripeSecretKey = defineSecret("STRIPE_SECRET_KEY");
const stripeWebhookSecret = defineSecret("STRIPE_WEBHOOK_SECRET");
const appBaseUrl = defineSecret("APP_BASE_URL");

// Optional (ops/admin alerts). If not configured, system still logs to Firestore.
const adminAlertEmail = defineSecret("ADMIN_ALERT_EMAIL");

/* ============================= GLOBAL CONFIG ============================= */

setGlobalOptions({
    region: "us-central1",
    memory: "256MiB",
});

admin.initializeApp({
    storageBucket: "monetizelt-1.firebasestorage.app",
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

let stripe = null;

/* ============================= BUSINESS CONSTANTS ============================= */

const PLATFORM_RATE = 0.12;
const STRIPE_FEE_RATE_FALLBACK = 0.029;
const STRIPE_FEE_FIXED_FALLBACK = 0.3;

// ✅ Weekly payouts only, with $10 minimum
const MIN_PAYOUT_AMOUNT = 10;

// Upload constraints
const VIDEO_SERIES_MAX_EPISODES = 10;
const MUSIC_ALBUM_MAX_TRACKS = 35;

// Upload: chunked backend uploads
// We never buffer the whole file. Each request carries one chunk only.
const UPLOAD_CHUNK_SIZE_BYTES = 16 * 1024 * 1024; // 16MB
const UPLOAD_SESSION_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const TMP_UPLOAD_PREFIX = "tmpUploads";

// Cover & asset constraints
const COVER_MAX_BYTES = 5 * 1024 * 1024;

// ✅ New max sizes: 3GB for video, 1GB for music
const VIDEO_MAX_BYTES = 3 * 1024 * 1024 * 1024;
const MUSIC_MAX_BYTES = 1 * 1024 * 1024 * 1024;

// ✅ Product create/cancel coordination
const PRODUCT_CREATE_REQUESTS_COLLECTION = "productCreateRequests";

const PRODUCT_STATUS = {
    DRAFT: "draft",
    ACTIVE: "active",
    TAKEN_DOWN: "taken_down",
    ARCHIVED: "archived",
    DELETED: "deleted",

    // Deprecated (kept only for backward compatibility with existing docs)
    UNDER_REVIEW: "under_review",
    REJECTED: "rejected",
};

const PRODUCT_COLLECTION_ACTIVE = "products";
const PRODUCT_COLLECTION_ARCHIVED = "archivedProducts";

// Payout constraints
const PAYPAL_PAYOUT_MAX_ITEMS_PER_BATCH = 100;
const PAYPAL_PAYOUT_INTER_BATCH_DELAY_MS = 2200; // a few seconds between batches (safety)

/* ============================= EMAIL CONFIG (LIVE) ============================= */
/**
 * ✅ Per your request:
 * - Sender: hello@monetizelt.com
 * - Help: contact@monetizelt.com (reply-to + footer)
 * - No noreply
 */
const EMAIL_FROM = { email: "hello@monetizelt.com", name: "Monetizelt" };
const EMAIL_REPLY_TO = { email: "contact@monetizelt.com", name: "Monetizelt Support" };

const LIST_UNSUBSCRIBE_MAILTO = "mailto:unsubscribe@monetizelt.com?subject=unsubscribe";
const LIST_UNSUBSCRIBE_URL_FALLBACK = "/unsubscribe.html";

/* ============================= CORS ============================= */

const ALLOWED_ORIGINS = new Set([
    "https://monetizelt.com",
    "https://www.monetizelt.com",
    "https://monetizelt-1.web.app",
    "https://monetizelt-1.firebaseapp.com",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]);

function isAllowedOrigin(origin) {
    if (!origin) return false;
    if (ALLOWED_ORIGINS.has(origin)) return true;
    try {
        const u = new URL(origin);
        return u.hostname.endsWith(".web.app") || u.hostname.endsWith(".firebaseapp.com");
    } catch {
        return false;
    }
}

function corsMiddleware(req, res, handler) {
    const origin = req.headers.origin;
    const allowed = origin && isAllowedOrigin(origin);

    if (allowed) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Credentials", "true");
    } else {
        res.setHeader("Access-Control-Allow-Origin", "*");
    }

    res.setHeader("Vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method");

    const reqAllowHeaders = req.headers["access-control-request-headers"];
    res.setHeader(
        "Access-Control-Allow-Headers",
        reqAllowHeaders || "Content-Type, Authorization, Stripe-Signature, X-Device-Fingerprint"
    );

    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Max-Age", "3600");

    if (req.method === "OPTIONS") {
        res.status(204).send("");
        return;
    }

    handler(req, res).catch((e) => {
        console.error("corsMiddleware handler error:", e);
        if (!res.headersSent) {
            res.status(500).json({ success: false, error: "Internal server error", code: "internal" });
        }
    });
}

/* ============================= GENERAL HELPERS ============================= */

function isEmail(s) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").toLowerCase());
}

function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

function nowServerTimestamp() {
    return admin.firestore.FieldValue.serverTimestamp();
}

function generateTokenHex(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function sha256Hex(s) {
    return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function extractDeviceInfo(userAgent) {
    const ua = String(userAgent || "");

    function detectBrowser(u) {
        if (/edg\//i.test(u)) return "Edge";
        if (/chrome\//i.test(u) && !/edg\//i.test(u)) return "Chrome";
        if (/safari\//i.test(u) && /version\//i.test(u) && !/chrome\//i.test(u)) return "Safari";
        if (/firefox\//i.test(u)) return "Firefox";
        return "Unknown";
    }
    function detectOS(u) {
        if (/windows nt/i.test(u)) return "Windows";
        if (/android/i.test(u)) return "Android";
        if (/iphone|ipad|ipod/i.test(u)) return "iOS";
        if (/mac os x/i.test(u)) return "macOS";
        if (/linux/i.test(u)) return "Linux";
        return "Unknown";
    }

    const browser = detectBrowser(ua);
    const os = detectOS(ua);

    return {
        browser,
        os,
        device: /mobile/i.test(ua) ? "Mobile" : "Desktop",
        userAgent: ua,
    };
}

function createHttpError(status, code, message, meta = {}) {
    const err = new Error(message);
    err.httpStatus = status;
    err.code = code;
    err.meta = meta;
    return err;
}

function getEnvSecret(name) {
    const v = process.env[name];
    return v && String(v).trim() ? String(v).trim() : null;
}

/**
 * We are LIVE and must always use the custom domain for public links.
 * NEVER return .web.app / .firebaseapp.com as a public origin.
 */
function sanitizePublicOrigin(candidate) {
    const s = String(candidate || "").trim().replace(/\/+$/, "");
    if (!s) return null;
    try {
        const u = new URL(s);
        const host = String(u.hostname || "").toLowerCase();

        // Must be https in production links
        if (u.protocol !== "https:") return null;

        // Never allow firebase hosting domains for public links
        if (host.endsWith(".web.app") || host.endsWith(".firebaseapp.com")) return null;

        return u.origin;
    } catch {
        return null;
    }
}

/**
 * Public site origin:
 * - Always use Monetizelt custom domain in live.
 * - If APP_BASE_URL is set AND is NOT a firebase hosting domain, we allow it.
 */
function getPublicSiteOrigin() {
    const hard = "https://monetizelt.com";

    const env = sanitizePublicOrigin(getEnvSecret("APP_BASE_URL"));
    if (env) return env;

    try {
        const v = sanitizePublicOrigin(appBaseUrl.value());
        if (v) return v;
    } catch {
        // ignore
    }

    return hard;
}

function safeExtFromName(originalName) {
    const ext = String(path.extname(String(originalName || "")) || "").toLowerCase();
    if (!ext) return "";
    if (!/^\.[a-z0-9]{1,8}$/i.test(ext)) return "";
    return ext;
}

function inferKind(category, subtype) {
    if (category === "video") return subtype === "series" ? "episode" : "file";
    if (category === "music") return subtype === "album" ? "track" : "file";
    return "file";
}

function isUnknownDeviceInfo(di) {
    const d = di || {};
    return (d.browser || "Unknown") === "Unknown" && (d.os || "Unknown") === "Unknown";
}

// Access code generation: short, user-friendly, no confusing chars
function generateAccessCode(length = 10) {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I,O,1,0
    let out = "";
    const buf = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) out += alphabet[buf[i] % alphabet.length];
    return out;
}

function normalizeAccessCode(s) {
    return String(s || "").trim().toUpperCase().replace(/\s+/g, "");
}

function getDeviceFingerprintFromReq(req) {
    // Prefer header, fallback to body/query
    const h = req.get?.("X-Device-Fingerprint") || req.headers?.["x-device-fingerprint"];
    return String(h || req.body?.deviceFingerprint || req.query?.deviceFingerprint || req.query?.fp || "").trim();
}

function normalizeClientRequestId(v) {
    const s = String(v || "").trim();
    if (!s) return "";
    // Keep it safe for logging/storage
    if (s.length > 160) return s.slice(0, 160);
    return s;
}

function deterministicIdFromClientRequest(prefix, uid, clientRequestId, len = 28) {
    const key = `${prefix}|${uid}|${clientRequestId}`;
    const h = sha256Hex(key);
    return `${prefix}_${h.slice(0, len)}`;
}

function requestDocIdFor(uid, clientRequestId) {
    return sha256Hex(`req|${uid}|${clientRequestId}`).slice(0, 32);
}

/* ============================= OPS / INCIDENT MECHANISM (PROJECT-WIDE) ============================= */

/**
 * Strong logging layer:
 * - Always writes systemErrors
 * - Also writes/upserts incidents to opsIncidents (dedup by hash)
 * - If SENDGRID + ADMIN_ALERT_EMAIL env secrets are present for this function, sends alert (throttled)
 */

function incidentKeyForError(functionName, error) {
    const code = String(error?.code || "internal");
    const status = String(error?.httpStatus || "");
    const msg = String(error?.message || String(error) || "unknown");
    const sig = `${functionName}|${code}|${status}|${msg}`.slice(0, 800);
    return sha256Hex(sig).slice(0, 32);
}

async function upsertOpsIncident(functionName, error, extra = {}) {
    const key = incidentKeyForError(functionName, error);
    const ref = db.collection("opsIncidents").doc(key);

    const payload = {
        key,
        function: functionName,
        code: error?.code || null,
        httpStatus: error?.httpStatus || null,
        message: error?.message || String(error),
        meta: error?.meta || null,
        lastSeenAt: nowServerTimestamp(),
        status: "open",
        extra: extra || {},
    };

    // Transaction: create if missing, else increment count + update lastSeen
    await db.runTransaction(async (tx) => {
        const s = await tx.get(ref);
        if (!s.exists) {
            tx.set(ref, { ...payload, firstSeenAt: nowServerTimestamp(), count: 1, alert: { lastSentAt: null } });
            return;
        }
        tx.set(
            ref,
            {
                ...payload,
                count: admin.firestore.FieldValue.increment(1),
            },
            { merge: true }
        );
    });

    return { key };
}

async function maybeAlertAdmin(functionName, error, extra = {}) {
    const sgKey = getEnvSecret("SENDGRID_API_KEY");
    const adminTo = getEnvSecret("ADMIN_ALERT_EMAIL");
    if (!sgKey || !adminTo || !isEmail(adminTo)) return { alerted: false, reason: "missing_env_secrets" };

    const key = incidentKeyForError(functionName, error);
    const incidentRef = db.collection("opsIncidents").doc(key);

    // Throttle: at most 1 alert per incident per 30 minutes
    const throttleMs = 30 * 60 * 1000;

    let shouldSend = false;
    let incidentData = null;

    await db.runTransaction(async (tx) => {
        const s = await tx.get(incidentRef);
        incidentData = s.exists ? s.data() : null;
        const last = incidentData?.alert?.lastSentAt?.toDate?.() || null;
        const now = Date.now();

        if (!last || now - last.getTime() > throttleMs) {
            shouldSend = true;
            tx.set(incidentRef, { alert: { lastSentAt: nowServerTimestamp() } }, { merge: true });
        }
    });

    if (!shouldSend) return { alerted: false, reason: "throttled" };

    try {
        const sgMail = require("@sendgrid/mail");
        sgMail.setApiKey(sgKey);

        const subject = `[Monetizelt] Incident: ${functionName} (${error?.code || "internal"})`;
        const body = `
Function: ${functionName}
Code: ${error?.code || "internal"}
HTTP: ${error?.httpStatus || ""}
Message: ${error?.message || String(error)}

Meta: ${JSON.stringify(error?.meta || null)}
Extra: ${JSON.stringify(extra || null)}
`;

        await sgMail.send({
            to: adminTo,
            from: EMAIL_FROM,
            replyTo: EMAIL_REPLY_TO,
            subject,
            text: body,
            categories: ["ops_incident"],
        });

        return { alerted: true };
    } catch (e) {
        console.error("maybeAlertAdmin failed:", e?.message);
        return { alerted: false, reason: "send_failed" };
    }
}

async function logSystemError(functionName, error, extra = {}) {
    try {
        await db.collection("systemErrors").add({
            function: functionName,
            error: error?.message || String(error),
            code: error?.code || null,
            httpStatus: error?.httpStatus || null,
            meta: error?.meta || null,
            stack: error?.stack || null,
            extra,
            timestamp: nowServerTimestamp(),
        });
    } catch (e) {
        console.error("Failed to write systemErrors:", e);
    }

    try {
        await upsertOpsIncident(functionName, error, extra);
    } catch (e) {
        console.error("Failed to upsert ops incident:", e?.message);
    }

    // Best-effort admin alert (only if env secrets exist for this function)
    try {
        await maybeAlertAdmin(functionName, error, extra);
    } catch {
        // ignore
    }
}

async function requireAuth(req) {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
        throw createHttpError(401, "unauthenticated", "Missing Authorization Bearer token.");
    }
    const idToken = authHeader.slice("Bearer ".length);
    try {
        return await admin.auth().verifyIdToken(idToken);
    } catch (e) {
        throw createHttpError(401, "unauthenticated", "Invalid or expired token.", { original: e?.message });
    }
}

/**
 * ✅ Updated: blocks banned accounts AND temporarily frozen accounts.
 * Freezes auto-expire after freezeUntil. If freeze expired, we auto-unfreeze best-effort.
 */
async function ensureUserNotBanned(uid) {
    const userRef = db.collection("users").doc(uid);
    const userDoc = await userRef.get();

    if (!userDoc.exists) return userDoc;

    const u = userDoc.data() || {};

    if (u.isBanned) {
        throw createHttpError(403, "permission_denied", "Account is banned.");
    }

    const status = String(u.accountStatus || "active").toLowerCase();
    if (status === "frozen") {
        const untilTs = u.freezeUntil || null;
        const until = untilTs?.toDate?.() || (untilTs ? new Date(untilTs) : null);

        if (until && until.getTime() <= Date.now()) {
            // Auto-unfreeze if expired (fail-safe)
            try {
                await userRef.set(
                    {
                        accountStatus: "active",
                        freezeUntil: admin.firestore.FieldValue.delete(),
                        freeze: admin.firestore.FieldValue.delete(),
                        updatedAt: nowServerTimestamp(),
                    },
                    { merge: true }
                );
            } catch (e) {
                console.error("Auto-unfreeze failed:", e?.message);
            }

            // Best-effort re-enable Auth
            try {
                await admin.auth().updateUser(uid, { disabled: false });
            } catch {
                // ignore
            }

            return await userRef.get();
        }

        throw createHttpError(403, "account_frozen", "Account is temporarily frozen.", {
            freezeUntil: until ? until.toISOString() : null,
        });
    }

    return userDoc;
}

/* ============================= SELLER PUBLIC INFO HELPERS ============================= */

const SELLER_ACCOUNT_TYPE = {
    INDIVIDUAL: "individual",
    BUSINESS: "business",
};

function normalizeAccountType(v) {
    const s = String(v || "").toLowerCase().trim();
    if (s === "business" || s === "company" || s === "pro") return SELLER_ACCOUNT_TYPE.BUSINESS;
    return SELLER_ACCOUNT_TYPE.INDIVIDUAL;
}

function pickFirstNonEmpty(...vals) {
    for (const v of vals) {
        const s = String(v || "").trim();
        if (s) return s;
    }
    return "";
}

/**
 * Builds the shape expected by product.html /getSellerInfo
 */
function buildSellerPublicInfo(userData, sellerId) {
    const u = userData || {};
    const sp = u.sellerProfile || {};
    const si = u.sellerIdentity || {};

    const accountType = normalizeAccountType(pickFirstNonEmpty(u.accountType, sp.accountType, si.accountType));

    const fullName = pickFirstNonEmpty(sp.fullName, si.fullName, u.fullName, u.displayName, "Seller");
    const businessName = pickFirstNonEmpty(sp.businessName, si.businessName, u.businessName);

    const email = pickFirstNonEmpty(sp.contactEmail, u.contactEmail, u.supportEmail, u.email);

    return {
        sellerId: String(sellerId || ""),
        accountType,
        fullName,
        businessName,
        email: email || "",
        photoUrl: pickFirstNonEmpty(sp.photoUrl, u.photoUrl),
        contactLinks: sp.contactLinks && typeof sp.contactLinks === "object" ? sp.contactLinks : {},
    };
}

/* ============================= EMAIL TEMPLATES (WHITE + BLUE 007bff) ============================= */

function emailShell({ title, bodyHtml, preheader = "" }) {
    const year = new Date().getFullYear();

    // White background, blue borders (#007bff), Poppins
    const colors = {
        bg: "#ffffff",
        card: "#ffffff",
        border: "#007bff",
        text: "#212529",
        muted: "#6c757d",
        primary: "#007bff",
        success: "#28a745",
        danger: "#dc3545",
        warn: "#fd7e14",
        softBlueBg: "#f2f8ff",
    };

    const logoUrl =
        "https://firebasestorage.googleapis.com/v0/b/monetizelt-1.firebasestorage.app/o/Monetizelt.jpg?alt=media&token=c942c3a7-0a4b-42f7-82bc-5cfde360e06e";

    const preheaderHtml = `
      <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;mso-hide:all;">
        ${String(preheader || "").slice(0, 140)}
      </div>
    `;

    return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0;padding:0;background:${colors.bg};border-collapse:collapse;">
  <tr>
    <td align="center" style="margin:0;padding:0;background:${colors.bg};">

      ${preheaderHtml}

      <!-- font: best-effort (some clients ignore) -->
      <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700;800&display=swap');
        </style>
      </div>

      <!-- Outer container (centered everywhere, incl. iOS) -->
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
             style="width:100%;max-width:600px;margin:0 auto;border-collapse:collapse;">
        <tr>
          <td style="padding:18px;">

            <!-- Logo circulaire centré -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
              <tr>
                <td align="center" style="padding:0 0 20px 0;">
                  <img src="${logoUrl}" alt="Monetizelt"
                       width="60" height="60"
                       style="display:block;width:60px;height:60px;border-radius:50%;object-fit:cover;border:3px solid ${colors.border};margin:0 auto;">
                </td>
              </tr>
            </table>

            <!-- Card -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                   style="background:${colors.card};border:2px solid ${colors.border};border-radius:16px;border-collapse:separate;overflow:hidden;">
              <tr>
                <td style="padding:16px 18px;background:${colors.softBlueBg};border-bottom:2px solid ${colors.border};">
                  <div style="font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;font-size:16px;font-weight:800;color:${colors.primary};margin:0;text-align:center;">
                    ${title}
                  </div>
                </td>
              </tr>

              <tr>
                <td style="padding:18px;">
                  <div style="font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;font-size:14px;line-height:1.55;color:${colors.text};">
                    ${bodyHtml}
                  </div>
                </td>
              </tr>
            </table>

          </td>
        </tr>
      </table>

    </td>
  </tr>
</table>`;
}

function emailButton({ href, label, tone = "primary" }) {
    const tones = {
        primary: { bg: "#007bff", text: "#ffffff", border: "#007bff" },
        success: { bg: "#28a745", text: "#ffffff", border: "#28a745" },
        danger: { bg: "#dc3545", text: "#ffffff", border: "#dc3545" },
        neutral: { bg: "#ffffff", text: "#007bff", border: "#007bff" },
    };
    const t = tones[tone] || tones.primary;

    return `
    <div style="text-align:center;margin:14px 0 8px 0;">
      <a href="${href}"
         style="display:inline-block;background:${t.bg};color:${t.text};padding:11px 16px;border-radius:12px;font-size:12px;text-decoration:none;font-weight:800;font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;border:2px solid ${t.border};">
        ${label}
      </a>
    </div>
  `;
}

function kvTable(rows) {
    const safeRows = Array.isArray(rows) ? rows : [];
    const border = "#007bff";
    const text = "#212529";
    const muted = "#6c757d";

    const tr = safeRows
        .map(
            ([k, v]) => `
      <tr>
        <td style="padding:10px 10px;border-bottom:1px solid ${border};color:${muted};font-size:12px;white-space:nowrap;font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;">${k}</td>
        <td style="padding:10px 10px;border-bottom:1px solid ${border};color:${text};font-size:13px;font-weight:700;font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;">${v}</td>
      </tr>
    `
        )
        .join("");

    return `
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;border:2px solid ${border};border-radius:12px;overflow:hidden;">
      <tbody>
        ${tr}
      </tbody>
    </table>
  `;
}

function htmlToText(html) {
    const s = String(html || "");
    return s
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/p>/gi, "\n\n")
        .replace(/<\/li>/gi, "\n")
        .replace(/<li>/gi, " - ")
        .replace(/<[^>]+>/g, "")
        .replace(/&nbsp;/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/[ \t]+\n/g, "\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}

async function sendEmail(type, { to, subject, title, bodyHtml, preheader = "", uid = null, productId = null, meta = {} }) {
    const sgMail = require("@sendgrid/mail");
    sgMail.setApiKey(sendgridApiKey.value());

    const base = getPublicSiteOrigin();
    const unsubscribeUrl = `${base}${LIST_UNSUBSCRIBE_URL_FALLBACK}`;

    const html = emailShell({ title, bodyHtml, preheader });
    const text = `${title}\n\n${htmlToText(bodyHtml)}\n\n---\nMonetizelt\nUnsubscribe: ${unsubscribeUrl}\n`;

    await sgMail.send({
        to,
        from: EMAIL_FROM,
        replyTo: EMAIL_REPLY_TO,
        subject,
        html,
        text,
        categories: [String(type || "transactional").slice(0, 50)],
        customArgs: {
            ...(uid ? { uid: String(uid) } : {}),
            ...(productId ? { productId: String(productId) } : {}),
            type: String(type || ""),
        },
        headers: {
            "List-Unsubscribe": `<${LIST_UNSUBSCRIBE_MAILTO}>, <${unsubscribeUrl}>`,
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
        trackingSettings: {
            clickTracking: { enable: false, enableText: false },
            openTracking: { enable: false },
            subscriptionTracking: { enable: false },
        },
    });

    await db.collection("emailSentLogs").add({
        type,
        uid,
        productId,
        to,
        subject,
        meta,
        createdAt: nowServerTimestamp(),
    });
}

/* ============================= STATS HELPERS ============================= */

async function statsInitIfMissing(uid) {
    const ref = db.collection("userStats").doc(uid);
    const doc = await ref.get();
    if (!doc.exists) {
        await ref.set({
            generatedLinksCount: 0,
            viewsCount: 0,
            ordersCount: 0,
            processedCount: 0,
            lifetimeNetIncome: 0,

            productsCreatedCount: 0, // becomes ACTIVE at least once
            productsActiveCount: 0,
            productsArchivedCount: 0,
            productsDeletedCount: 0,

            lastUpdated: nowServerTimestamp(),
        });
    }
}

async function statsInc(uid, patch) {
    await statsInitIfMissing(uid);
    const ref = db.collection("userStats").doc(uid);

    const update = { lastUpdated: nowServerTimestamp() };
    for (const [k, v] of Object.entries(patch)) {
        update[k] = admin.firestore.FieldValue.increment(Number(v));
    }
    await ref.set(update, { merge: true });
}

/* ============================= PAYOUTS (WEEKLY FRIDAY ONLY) ============================= */

function nextFridayNoonUtc(from = new Date()) {
    const d = new Date(from.getTime());
    const day = d.getUTCDay();
    const daysUntilFriday = (5 - day + 7) % 7 || 7;
    d.setUTCDate(d.getUTCDate() + daysUntilFriday);
    d.setUTCHours(12, 0, 0, 0);
    return d;
}

function fridayKeyFromDate(d) {
    // YYYY-MM-DD in UTC
    const y = d.getUTCFullYear();
    const m = String(d.getUTCMonth() + 1).padStart(2, "0");
    const day = String(d.getUTCDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
}

function weeklyScheduleLabel() {
    return "Weekly (Friday)";
}

function createPaypalPayoutsClient() {
    let paypalPayouts;
    try {
        paypalPayouts = require("@paypal/payouts-sdk");
    } catch (e) {
        throw createHttpError(500, "failed_precondition", "Missing dependency @paypal/payouts-sdk.", {
            hint: "Run: npm i @paypal/payouts-sdk",
            original: e?.message,
        });
    }

    const isEmulator = !!process.env.FUNCTIONS_EMULATOR;
    const environment = isEmulator
        ? new paypalPayouts.core.SandboxEnvironment(paypalClientId.value(), paypalClientSecret.value())
        : new paypalPayouts.core.LiveEnvironment(paypalClientId.value(), paypalClientSecret.value());

    const client = new paypalPayouts.core.PayPalHttpClient(environment);
    return { paypalPayouts, client };
}

/**
 * ✅ IMPORTANT CHANGE (per your request):
 * PayPal is used only as a payout rail. We do NOT subtract "PayPal fees" from the seller.
 * The seller receives exactly their balance amount (gross == net).
 */
function computeNetPayoutAmountUSD(grossAmount) {
    const amount = Number(grossAmount);
    return { payoutFee: 0, netAmount: amount };
}

function payoutGroupKeyFromPaypalEmail(paypalEmail) {
    const s = String(paypalEmail || "").trim().toLowerCase();
    const c = s[0] || "#";
    if (c >= "a" && c <= "z") return c.toUpperCase();
    return "#";
}

/**
 * Mark payout candidates on Thursday (preparation step).
 * This does NOT pay. It just stores snapshot info for Friday.
 */
async function prepareWeeklyPayoutCandidates({ trigger = "schedule" } = {}) {
    const FN = "prepareWeeklyPayoutCandidates";
    const now = new Date();
    const upcomingFriday = nextFridayNoonUtc(now);
    const fridayKey = fridayKeyFromDate(upcomingFriday);

    console.log(`[${FN}] trigger=${trigger} now=${now.toISOString()} upcomingFriday=${upcomingFriday.toISOString()} key=${fridayKey}`);

    let lastDoc = null;
    let prepared = 0;
    let scanned = 0;

    const bw = db.bulkWriter();

    while (true) {
        let q = db.collection("users").orderBy(admin.firestore.FieldPath.documentId()).limit(500);
        if (lastDoc) q = q.startAfter(lastDoc);

        const snap = await q.get();
        if (snap.empty) break;

        for (const docSnap of snap.docs) {
            lastDoc = docSnap;
            scanned++;

            const uid = docSnap.id;
            const u = docSnap.data() || {};

            if (u.isBanned) continue;
            if (String(u.accountStatus || "active").toLowerCase() === "frozen") continue;

            const balance = Number(u.balance || 0);
            const paypalEmail = String(u.paypalEmail || "").trim();

            if (!Number.isFinite(balance) || balance < MIN_PAYOUT_AMOUNT) continue;
            if (!isEmail(paypalEmail)) continue;

            // If already prepared for this Friday, skip
            const existing = u.payoutCandidate || null;
            if (existing && existing.fridayKey === fridayKey && existing.status && existing.status !== "cleared") continue;

            bw.set(
                db.collection("users").doc(uid),
                {
                    payoutCandidate: {
                        fridayKey,
                        amountGross: balance,
                        paypalEmail,
                        schedule: "weekly_friday",
                        status: "prepared",
                        preparedAt: nowServerTimestamp(),
                        trigger,
                    },
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            prepared++;
        }
    }

    await bw.close();

    console.log(`[${FN}] scanned=${scanned} prepared=${prepared}`);
    return { scanned, prepared, fridayKey };
}

/**
 * Create and send PayPal payouts in batches (<= 500).
 * Protections:
 * - Per-week run lock doc
 * - Per-user per-week dedup docs (create-only)
 * - Balance is decremented ONLY for successful PayPal items (in reconciliation)
 */
async function processWeeklyFridayPayouts({ trigger = "schedule", messageId = null } = {}) {
    const FN = "processWeeklyFridayPayouts";
    const now = new Date();

    const fridayNoon = new Date(now.getTime());
    fridayNoon.setUTCHours(12, 0, 0, 0);
    const todayIsFriday = now.getUTCDay() === 5;
    const targetFriday = todayIsFriday ? fridayNoon : nextFridayNoonUtc(now);
    const fridayKey = fridayKeyFromDate(targetFriday);

    const base = getPublicSiteOrigin();
    const dashboardUrl = `${base}/dashboard.html`;
    const payAddressUrl = `${base}/pay-address.html`;
    const settingsUrl = `${base}/settings.html`;

    console.log(`[${FN}] trigger=${trigger} messageId=${messageId || ""} now=${now.toISOString()} key=${fridayKey}`);

    // Global lock per fridayKey
    const runLockRef = db.collection("payoutRunLocks").doc(fridayKey);
    const gotRunLock = await db.runTransaction(async (tx) => {
        const s = await tx.get(runLockRef);
        if (s.exists) return false;
        tx.set(runLockRef, { fridayKey, createdAt: nowServerTimestamp(), trigger, messageId: messageId || null });
        return true;
    });
    if (!gotRunLock) {
        console.log(`[${FN}] Another instance already holds lock for ${fridayKey}. Exiting.`);
        return { success: false, locked: true, fridayKey };
    }

    let processedUsers = 0;
    let sentItems = 0;
    let skippedCount = 0;
    let deferredCount = 0;

    try {
        const candidateDocs = [];

        // 1) Prepared candidates
        {
            let last = null;
            while (candidateDocs.length < 5000) {
                let q = db
                    .collection("users")
                    .where("payoutCandidate.fridayKey", "==", fridayKey)
                    .where("payoutCandidate.status", "==", "prepared")
                    .limit(500);
                if (last) q = q.startAfter(last);
                const snap = await q.get();
                if (snap.empty) break;
                for (const d of snap.docs) candidateDocs.push(d);
                last = snap.docs[snap.docs.length - 1];
                if (snap.size < 500) break;
            }
        }

        // 2) Fallback if none prepared
        if (candidateDocs.length === 0) {
            console.log(`[${FN}] No prepared candidates found for ${fridayKey}. Fallback scanning first 1000 users for eligibility.`);
            let last = null;
            let scanned = 0;
            while (candidateDocs.length < 1000) {
                let q = db.collection("users").orderBy(admin.firestore.FieldPath.documentId()).limit(500);
                if (last) q = q.startAfter(last);
                const snap = await q.get();
                if (snap.empty) break;
                scanned += snap.size;
                last = snap.docs[snap.docs.length - 1];

                for (const d of snap.docs) {
                    const u = d.data() || {};
                    const balance = Number(u.balance || 0);
                    const paypalEmail = String(u.paypalEmail || "").trim();
                    if (u.isBanned) continue;
                    if (String(u.accountStatus || "active").toLowerCase() === "frozen") continue;
                    if (!Number.isFinite(balance) || balance < MIN_PAYOUT_AMOUNT) continue;
                    if (!isEmail(paypalEmail)) continue;
                    candidateDocs.push(d);
                }
                if (scanned >= 1000) break;
            }
        }

        // ✅ Filter + sort:
        // - group by first letter of PayPal email (A-Z) for predictable batching
        // - inside group, pay larger balances first
        candidateDocs.sort((a, b) => {
            const pa = String(a.data()?.paypalEmail || "").trim();
            const pb = String(b.data()?.paypalEmail || "").trim();
            const ga = payoutGroupKeyFromPaypalEmail(pa);
            const gb = payoutGroupKeyFromPaypalEmail(pb);
            if (ga !== gb) return ga.localeCompare(gb);
            return Number(b.data()?.balance || 0) - Number(a.data()?.balance || 0);
        });

        let batchIndex = 0;

        for (let offset = 0; offset < candidateDocs.length; offset += PAYPAL_PAYOUT_MAX_ITEMS_PER_BATCH) {
            const slice = candidateDocs.slice(offset, offset + PAYPAL_PAYOUT_MAX_ITEMS_PER_BATCH);
            if (slice.length === 0) break;

            batchIndex++;
            const batchDocId = `${fridayKey}_batch_${String(batchIndex).padStart(3, "0")}`;
            const batchRef = db.collection("payoutBatches").doc(batchDocId);

            // Build payout items with per-user dedup (create-only).
            // ✅ Fix: we keep a direct mapping (no re-read/misalignment).
            const bw = db.bulkWriter();
            const creates = [];

            for (const docSnap of slice) {
                const uid = docSnap.id;
                const u = docSnap.data() || {};
                const balance = Number(u.balance || 0);
                const paypalEmail = String(u.paypalEmail || "").trim();

                if (u.isBanned || String(u.accountStatus || "active").toLowerCase() === "frozen") {
                    skippedCount++;
                    continue;
                }

                if (!Number.isFinite(balance) || balance < MIN_PAYOUT_AMOUNT) {
                    skippedCount++;
                    continue;
                }

                if (!isEmail(paypalEmail)) {
                    skippedCount++;

                    bw.set(
                        db.collection("users").doc(uid),
                        {
                            payoutCandidate: { fridayKey, status: "missing_paypal_email", lastCheckedAt: nowServerTimestamp() },
                            updatedAt: nowServerTimestamp(),
                        },
                        { merge: true }
                    );

                    // ✅ Email seller: action required (button only, no raw link)
                    try {
                        const userSnap = await db.collection("users").doc(uid).get();
                        const to = userSnap.data()?.email;
                        if (to && isEmail(to)) {
                            await sendEmail("paypal_action_required", {
                                to,
                                subject: "Action required: add or update your PayPal email",
                                title: "Action required",
                                preheader: "We couldn't process your payout because your PayPal email is missing or invalid.",
                                bodyHtml: `
                                  <p>We couldn’t process your payout because your PayPal email is missing or invalid.</p>
                                  ${kvTable([
                                    ["What to do", `<span style="font-weight:800;color:#007bff;">Update your payout email</span>`],
                                    ["Where", `<span style="font-weight:700;">Dashboard</span>`],
                                    ["Schedule", `<span style="font-weight:700;">${weeklyScheduleLabel()}</span>`],
                                ])}
                                  ${emailButton({ href: dashboardUrl, label: "Open dashboard to update PayPal email", tone: "primary" })}
                                  <p style="color:#6c757d;font-size:10px;margin-top:10px;">
                                    After you update it, we’ll automatically retry on the next scheduled payout.
                                  </p>
                                `,
                                uid,
                            });
                        }
                    } catch (e) {
                        console.error(`[${FN}] paypal_action_required email failed uid=${uid}:`, e?.message);
                    }

                    continue;
                }

                const { payoutFee, netAmount } = computeNetPayoutAmountUSD(balance);
                if (!Number.isFinite(netAmount) || netAmount <= 0) {
                    skippedCount++;
                    continue;
                }

                const dedupId = `${fridayKey}_${uid}`;
                const dedupRef = db.collection("payoutDedup").doc(dedupId);
                const senderItemId = dedupId;

                const item = {
                    recipient_type: "EMAIL",
                    amount: { value: Number(netAmount).toFixed(2), currency: "USD" },
                    receiver: paypalEmail,
                    note: "Monetizelt scheduled payout (weekly Friday)",
                    sender_item_id: senderItemId,
                };

                const meta = {
                    uid,
                    paypalEmail,
                    grossAmount: balance,
                    payoutFeeEst: payoutFee,
                    netAmount: Number(netAmount.toFixed(2)),
                    dedupId,
                    senderItemId,
                    item,
                };

                const p = bw.create(dedupRef, {
                    fridayKey,
                    uid,
                    grossAmount: balance,
                    netAmount: Number(netAmount.toFixed(2)),
                    payoutFeeEst: Number(payoutFee || 0),
                    paypalEmail,
                    status: "preparing",
                    createdAt: nowServerTimestamp(),
                    trigger,
                    batchDocId,
                    senderItemId,
                });

                creates.push(
                    p.then(
                        () => ({ ok: true, meta }),
                        (err) => ({ ok: false, meta, err })
                    )
                );
            }

            const settled = await Promise.all(creates);
            await bw.close();

            const selected = settled.filter((r) => r.ok).map((r) => r.meta);

            if (selected.length === 0) {
                console.log(`[${FN}] batch=${batchDocId} no new items to pay (all deduped/skipped).`);
                continue;
            }

            const items = selected.map((m) => m.item);

            await batchRef.set(
                {
                    fridayKey,
                    batchDocId,
                    status: "sending",
                    itemCount: items.length,
                    createdAt: nowServerTimestamp(),
                    trigger,
                    messageId: messageId || null,
                },
                { merge: true }
            );

            // Mark dedup docs as "sending"
            const bw2 = db.bulkWriter();
            for (const m of selected) {
                bw2.set(
                    db.collection("payoutDedup").doc(m.dedupId),
                    { status: "sending", sendingAt: nowServerTimestamp(), batchDocId },
                    { merge: true }
                );
            }
            await bw2.close();

            // Send PayPal batch
            const { paypalPayouts, client } = createPaypalPayoutsClient();
            const request = new paypalPayouts.payouts.PayoutsPostRequest();

            const senderBatchId = `monetizelt_${fridayKey}_${batchDocId}_${Date.now()}`;
            request.requestBody({
                sender_batch_header: {
                    sender_batch_id: senderBatchId,
                    email_subject: "You have a payout from Monetizelt",
                },
                items,
            });

            let resp;
            try {
                resp = await client.execute(request);
            } catch (e) {
                console.error(`[${FN}] PayPal batch send failed batch=${batchDocId}:`, e?.message);

                const bwFail = db.bulkWriter();
                for (const m of selected) {
                    bwFail.set(
                        db.collection("payoutDedup").doc(m.dedupId),
                        {
                            status: "deferred",
                            deferredAt: nowServerTimestamp(),
                            failureReason: e?.message || "PayPal batch request failed",
                        },
                        { merge: true }
                    );
                }
                await bwFail.close();

                await batchRef.set(
                    {
                        status: "failed_to_send",
                        error: e?.message || "PayPal batch request failed",
                        updatedAt: nowServerTimestamp(),
                    },
                    { merge: true }
                );

                deferredCount += selected.length;

                // ops signal
                await logSystemError(FN, createHttpError(502, "paypal_batch_send_failed", e?.message || "PayPal batch send failed"), {
                    batchDocId,
                    fridayKey,
                });

                continue;
            }

            sentItems += selected.length;

            const paypalBatchId = resp?.result?.batch_header?.payout_batch_id || null;

            await batchRef.set(
                {
                    status: "sent",
                    senderBatchId,
                    paypalBatchId,
                    sentAt: nowServerTimestamp(),
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            // Mark dedup docs as sent
            const bwSent = db.bulkWriter();
            for (const m of selected) {
                bwSent.set(
                    db.collection("payoutDedup").doc(m.dedupId),
                    {
                        status: "sent",
                        paypalBatchId,
                        senderBatchId,
                        sentAt: nowServerTimestamp(),
                    },
                    { merge: true }
                );
            }
            await bwSent.close();

            processedUsers += selected.length;

            // Immediate reconciliation attempt (best-effort)
            try {
                if (paypalBatchId) {
                    await reconcilePaypalBatch({
                        paypalBatchId,
                        batchDocId,
                        fridayKey,
                        trigger: `${FN}:immediate_reconcile`,
                        dashboardUrl,
                        settingsUrl,
                        payAddressUrl,
                    });
                }
            } catch (e) {
                console.error(`[${FN}] immediate reconcile failed batch=${batchDocId}:`, e?.message);
                await batchRef.set({ reconcileError: e?.message || "reconcile failed", updatedAt: nowServerTimestamp() }, { merge: true });
                await logSystemError(FN, e, { batchDocId, paypalBatchId, fridayKey });
            }

            // ✅ Respect PayPal & external API limits: wait a few seconds between batches
            await new Promise((r) => setTimeout(r, PAYPAL_PAYOUT_INTER_BATCH_DELAY_MS));
        }

        console.log(`[${FN}] sentItems=${sentItems} processedUsers=${processedUsers} skipped=${skippedCount}`);
        return { success: true, fridayKey, processedUsers, sentItems, skippedCount, deferredCount };
    } finally {
        await db.collection("payoutRunLocks").doc(fridayKey).set(
            { finishedAt: nowServerTimestamp(), updatedAt: nowServerTimestamp() },
            { merge: true }
        );
    }
}

/**
 * Reconcile PayPal batch results and apply:
 * - Deduct balances ONLY for successful items
 * - Mark history and send emails
 *
 * ✅ IMPORTANT CHANGE:
 * - No PayPal fee is deducted from seller balance (gross == net in our payout accounting).
 *
 * ✅ Per your request:
 * - If a PayPal error happens, email seller with a BUTTON to dashboard to update payout email.
 * - Never show raw links in the email body.
 */
async function reconcilePaypalBatch({
    paypalBatchId,
    batchDocId,
    fridayKey,
    trigger = "reconcile",
    dashboardUrl,
    settingsUrl,
    payAddressUrl,
} = {}) {
    const FN = "reconcilePaypalBatch";

    if (!paypalBatchId) throw createHttpError(400, "invalid_argument", "Missing paypalBatchId.");

    const { paypalPayouts, client } = createPaypalPayoutsClient();

    const getReq = new paypalPayouts.payouts.PayoutsGetRequest(paypalBatchId);
    const resp = await client.execute(getReq);
    const result = resp?.result || {};

    const batchStatus = result?.batch_header?.batch_status || null;
    const items = Array.isArray(result?.items) ? result.items : [];

    await db.collection("payoutBatches").doc(batchDocId).set(
        {
            reconcile: {
                lastRunAt: nowServerTimestamp(),
                batchStatus,
                itemCount: items.length,
                trigger,
            },
            updatedAt: nowServerTimestamp(),
        },
        { merge: true }
    );

    const nextFriday = nextFridayNoonUtc(new Date());
    const nextFridayKey = fridayKeyFromDate(nextFriday);

    // sender_item_id -> item
    const bySender = new Map();
    for (const it of items) {
        const senderItemId = it?.payout_item?.sender_item_id || it?.sender_item_id || null;
        if (senderItemId) bySender.set(senderItemId, it);
    }

    // Query dedup docs for this batch (may require index)
    const dedupSnap = await db.collection("payoutDedup").where("batchDocId", "==", batchDocId).limit(800).get();

    const bw = db.bulkWriter();

    for (const d of dedupSnap.docs) {
        const dedup = d.data() || {};
        const uid = String(dedup.uid || "");
        const senderItemId = String(dedup.senderItemId || d.id);
        const grossAmount = Number(dedup.grossAmount || 0);
        const paypalEmail = String(dedup.paypalEmail || "").trim();

        const it = bySender.get(senderItemId);
        const itemStatus = String(
            it?.transaction_status ||
            it?.payout_item?.transaction_status ||
            it?.payout_item?.transaction_status ||
            ""
        ).toUpperCase();
        const errName = it?.errors?.name || it?.payout_item?.errors?.name || null;
        const errMsg = it?.errors?.message || it?.payout_item?.errors?.message || null;

        if (!itemStatus) continue;

        const successLike = new Set(["SUCCESS", "UNCLAIMED"]);
        const failureLike = new Set(["FAILED", "RETURNED", "BLOCKED", "CANCELED", "DENIED"]);
        const pendingLike = new Set(["PENDING", "PROCESSING", "ONHOLD", "HELD"]);

        if (successLike.has(itemStatus)) {
            const historyId = `${fridayKey}_${uid}`;
            const historyRef = db.collection("payoutHistory").doc(historyId);

            await db.runTransaction(async (tx) => {
                const existingHistory = await tx.get(historyRef);
                if (existingHistory.exists) {
                    tx.set(d.ref, { status: "completed", finalizedAt: nowServerTimestamp(), paypalItemStatus: itemStatus }, { merge: true });
                    return;
                }

                const userRef = db.collection("users").doc(uid);
                const userSnap = await tx.get(userRef);
                if (!userSnap.exists) {
                    tx.set(historyRef, { status: "error_user_missing", fridayKey, uid, createdAt: nowServerTimestamp() }, { merge: true });
                    tx.set(d.ref, { status: "error_user_missing", paypalItemStatus: itemStatus }, { merge: true });
                    return;
                }

                const u = userSnap.data() || {};
                const balance = Number(u.balance || 0);

                if (!Number.isFinite(balance) || balance < grossAmount) {
                    tx.set(historyRef, {
                        fridayKey,
                        uid,
                        status: "skipped_insufficient_balance",
                        paypalEmail,
                        grossAmount,
                        balanceAtFinalize: balance,
                        paypalBatchId,
                        batchDocId,
                        paypalItemStatus: itemStatus,
                        createdAt: nowServerTimestamp(),
                    });
                    tx.set(d.ref, { status: "skipped_insufficient_balance", paypalItemStatus: itemStatus, finalizedAt: nowServerTimestamp() }, { merge: true });
                    return;
                }

                const { payoutFee, netAmount } = computeNetPayoutAmountUSD(grossAmount);

                // ✅ deduct full grossAmount (seller receives full balance amount)
                tx.update(userRef, {
                    balance: admin.firestore.FieldValue.increment(-grossAmount),
                    lastPayout: nowServerTimestamp(),
                    updatedAt: nowServerTimestamp(),
                    payoutCandidate: admin.firestore.FieldValue.delete(),
                });

                tx.set(historyRef, {
                    fridayKey,
                    uid,
                    paypalEmail,
                    grossAmount,
                    payoutFeeEst: Number(payoutFee || 0),
                    netAmount: Number(Number(netAmount).toFixed(2)),
                    status: "completed",
                    paypalBatchId,
                    batchDocId,
                    paypalItemStatus: itemStatus,
                    createdAt: nowServerTimestamp(),
                });

                // Transaction record: payout amount == grossAmount
                tx.set(db.collection("transactions").doc(), {
                    userId: uid,
                    type: "payout",
                    amount: Number(Number(netAmount).toFixed(2)),
                    grossAmount,
                    payoutFee: 0,
                    paypalEmail,
                    status: "completed",
                    date: nowServerTimestamp(),
                    createdAt: nowServerTimestamp(),
                    gateway: "paypal_payouts_batch",
                    paypalBatchId,
                    fridayKey,
                });

                tx.set(d.ref, { status: "completed", paypalItemStatus: itemStatus, finalizedAt: nowServerTimestamp() }, { merge: true });
            });

            // Email seller
            try {
                const userSnap = await db.collection("users").doc(uid).get();
                const to = userSnap.data()?.email;
                if (to && isEmail(to)) {
                    const { netAmount } = computeNetPayoutAmountUSD(grossAmount);

                    await sendEmail("payout_processed", {
                        to,
                        subject: "Your payout was processed",
                        title: "Payout processed",
                        preheader: `Payout: ${Number(netAmount).toFixed(2)} USD`,
                        bodyHtml: `
                          <p>Your weekly payout has been sent successfully.</p>
                          ${kvTable([
                            ["Schedule", `<span style="font-weight:800;color:#007bff;">${weeklyScheduleLabel()}</span>`],
                            ["PayPal email", `<span style="font-weight:800;">${paypalEmail}</span>`],
                            ["Amount sent", `<span style="font-weight:900;color:#28a745;">${Number(netAmount).toFixed(2)} USD</span>`],
                            ["Batch ID", `<span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;">${paypalBatchId}</span>`],
                            ["Week", `<span style="font-weight:800;">${fridayKey}</span>`],
                        ])}
                          ${emailButton({ href: dashboardUrl, label: "Open dashboard", tone: "primary" })}
                          <p style="color:#6c757d;font-size:10px;margin-top:10px;">
                            Processing times can vary depending on PayPal. Keep this email for your records.
                          </p>
                        `,
                        uid,
                    });
                }
            } catch (e) {
                console.error(`[${FN}] payout_processed email failed uid=${uid}:`, e?.message);
            }

            continue;
        }

        if (failureLike.has(itemStatus)) {
            const errorText = [errName, errMsg].filter(Boolean).join(": ").trim() || "Payout failed";

            // Mark dedup as failed and keep balance (do not deduct)
            bw.set(
                d.ref,
                {
                    status: "failed",
                    paypalItemStatus: itemStatus,
                    failedAt: nowServerTimestamp(),
                    failureReason: errorText,
                    nextAttemptFridayKey: nextFridayKey,
                },
                { merge: true }
            );

            // Postpone
            bw.set(
                db.collection("users").doc(uid),
                {
                    payoutCandidate: {
                        fridayKey: nextFridayKey,
                        status: "deferred_processing",
                        lastFailureAt: nowServerTimestamp(),
                        lastFailureReason: errorText,
                        postponedFrom: fridayKey,
                    },
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            // ✅ Notify user: action required, includes dashboard BUTTON (no raw links)
            try {
                const userSnap = await db.collection("users").doc(uid).get();
                const to = userSnap.data()?.email;

                if (to && isEmail(to)) {
                    await sendEmail("paypal_error_seller", {
                        to,
                        subject: "PayPal payout error — action may be required",
                        title: "Payout needs attention",
                        preheader: "PayPal reported an issue processing your payout. You can update your payout email from the dashboard.",
                        bodyHtml: `
                          <p>PayPal reported an issue while processing your weekly payout. Your balance was <strong>not</strong> deducted.</p>
                          ${kvTable([
                            ["Status", `<span style="font-weight:900;color:#dc3545;">${itemStatus}</span>`],
                            ["PayPal message", `<span style="font-weight:700;">${String(errorText).slice(0, 240)}</span>`],
                            ["Next attempt", `<span style="font-weight:800;color:#007bff;">We will retry next Friday if needed</span>`],
                        ])}
                          ${emailButton({ href: dashboardUrl, label: "Open dashboard to update PayPal email", tone: "primary" })}
                          ${emailButton({ href: settingsUrl, label: "Open settings", tone: "neutral" })}
                          <p style="color:#6c757d;font-size:10px;margin-top:10px;">
                            If your PayPal email is correct and this keeps happening, reply to this email and we will help.
                          </p>
                        `,
                        uid,
                    });
                }
            } catch (e) {
                console.error(`[${FN}] paypal_error_seller email failed uid=${uid}:`, e?.message);
            }

            continue;
        }

        if (pendingLike.has(itemStatus)) {
            bw.set(d.ref, { status: "pending", paypalItemStatus: itemStatus, lastPendingAt: nowServerTimestamp() }, { merge: true });
            continue;
        }

        bw.set(d.ref, { status: "unknown", paypalItemStatus: itemStatus, updatedAt: nowServerTimestamp() }, { merge: true });
    }

    await bw.close();

    return { paypalBatchId, batchStatus, items: items.length };
}

/* ============================= PRODUCT VALIDATION ============================= */

function validateProductInput({ title, description, price, category, subtype, coverMeta, assetsMeta }) {
    if (!title || String(title).trim().length < 2) {
        throw createHttpError(400, "invalid_argument", "Title is required (min 2 chars).");
    }
    if (!description || String(description).trim().length < 10) {
        throw createHttpError(400, "invalid_argument", "Description is required (min 10 chars).");
    }

    const p = Number(price);
    if (!Number.isFinite(p) || p < 1) {
        throw createHttpError(400, "invalid_argument", "Minimum price is $1.00.");
    }

    // ✅ Digital products removed: only video + music
    if (!["video", "music"].includes(category)) {
        throw createHttpError(400, "invalid_argument", "Invalid category. Only 'video' and 'music' are supported.");
    }

    if (category === "video" && !["single", "series"].includes(subtype)) {
        throw createHttpError(400, "invalid_argument", "Invalid video subtype.");
    }
    if (category === "music" && !["single", "album"].includes(subtype)) {
        throw createHttpError(400, "invalid_argument", "Invalid music subtype.");
    }

    if (!coverMeta || typeof coverMeta !== "object") {
        throw createHttpError(400, "invalid_argument", "coverMeta is required.");
    }
    const coverSize = Number(coverMeta.sizeBytes || 0);
    const coverType = String(coverMeta.contentType || "");
    if (!coverType.startsWith("image/")) throw createHttpError(400, "invalid_argument", "Cover must be an image.");
    if (!Number.isFinite(coverSize) || coverSize <= 0 || coverSize > COVER_MAX_BYTES) {
        throw createHttpError(400, "invalid_argument", "Cover max size is 5MB.");
    }

    if (!Array.isArray(assetsMeta) || assetsMeta.length < 1) {
        throw createHttpError(400, "invalid_argument", "At least one asset file is required.");
    }

    if (category === "video") {
        if (subtype === "single" && assetsMeta.length !== 1) {
            throw createHttpError(400, "invalid_argument", "Single video must have exactly 1 file.");
        }
        if (subtype === "series" && assetsMeta.length > VIDEO_SERIES_MAX_EPISODES) {
            throw createHttpError(400, "invalid_argument", `Series max ${VIDEO_SERIES_MAX_EPISODES} episodes/files.`);
        }
    }

    if (category === "music") {
        if (subtype === "single" && assetsMeta.length !== 1) {
            throw createHttpError(400, "invalid_argument", "Single track must have exactly 1 file.");
        }
        if (subtype === "album" && assetsMeta.length > MUSIC_ALBUM_MAX_TRACKS) {
            throw createHttpError(400, "invalid_argument", `Album max ${MUSIC_ALBUM_MAX_TRACKS} tracks/files.`);
        }
    }

    const extsVideo = new Set([".mp4", ".mov", ".webm", ".mkv"]);
    const extsMusic = new Set([".mp3", ".wav", ".ogg", ".flac"]);

    for (const [i, m] of assetsMeta.entries()) {
        const size = Number(m?.sizeBytes || 0);
        const originalName = String(m?.originalName || `file_${i + 1}`);
        const ext = safeExtFromName(originalName);

        if (!Number.isFinite(size) || size <= 0) {
            throw createHttpError(400, "invalid_argument", `Invalid sizeBytes for asset ${i + 1}.`);
        }

        if (category === "video") {
            if (!extsVideo.has(ext)) throw createHttpError(400, "invalid_argument", `Invalid video type: ${originalName}`);
            if (size > VIDEO_MAX_BYTES) throw createHttpError(400, "invalid_argument", `Video file too large (max 3GB): ${originalName}`);
        }

        if (category === "music") {
            if (!extsMusic.has(ext)) throw createHttpError(400, "invalid_argument", `Invalid audio type: ${originalName}`);
            if (size > MUSIC_MAX_BYTES) throw createHttpError(400, "invalid_argument", `Music file too large (max 1GB): ${originalName}`);
        }
    }
}

/* ============================= BATCH DELETE HELPER ============================= */

async function deleteQueryBatch(query) {
    const snap = await query.get();
    if (snap.empty) return 0;
    const batch = db.batch();
    snap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();
    return snap.size;
}

/* ============================= UPLOAD HELPERS (CHUNK COMPOSE, NO RAM CONCAT) ============================= */

function chunkObjectPath({ uid, sessionId, kind, index, chunkIndex }) {
    const idx = String(index);
    const ci = String(chunkIndex).padStart(6, "0");
    return `${TMP_UPLOAD_PREFIX}/${uid}/${sessionId}/${kind}_${idx}/chunk_${ci}`;
}

async function listChunks({ uid, sessionId, kind, index }) {
    const prefix = `${TMP_UPLOAD_PREFIX}/${uid}/${sessionId}/${kind}_${String(index)}/chunk_`;
    const [files] = await bucket.getFiles({ prefix });
    const chunkFiles = files
        .map((f) => f.name)
        .filter((name) => name.startsWith(prefix))
        .sort();
    return chunkFiles;
}

async function deleteByPrefix(prefix) {
    const [files] = await bucket.getFiles({ prefix });
    await Promise.allSettled(files.map((f) => f.delete({ ignoreNotFound: true })));
}

async function composeManyToDest({ sourceNames, destName, tmpPrefixForIntermediates }) {
    const FN = "composeManyToDest";
    const sources = Array.isArray(sourceNames) ? [...sourceNames] : [];
    if (sources.length < 1) throw createHttpError(400, "failed_precondition", "No chunks to compose.");

    const intermediates = [];

    let round = 0;
    while (sources.length > 32) {
        round++;
        const batch = sources.splice(0, 32);
        const intermediateName = `${tmpPrefixForIntermediates}/compose_round_${String(round).padStart(3, "0")}_${generateTokenHex(6)}`;
        await bucket.combine(batch, intermediateName);
        intermediates.push(intermediateName);
        sources.push(intermediateName);
    }

    await bucket.combine(sources, destName);

    if (intermediates.length) {
        await Promise.allSettled(intermediates.map((n) => bucket.file(n).delete({ ignoreNotFound: true })));
    }

    console.log(`[${FN}] composed sources=${sourceNames.length} intermediates=${intermediates.length} -> ${destName}`);
    return destName;
}

async function composeChunksToFinalObject({ uid, sessionId, kind, index, expectedTotalChunks, destPath, contentType }) {
    const chunks = await listChunks({ uid, sessionId, kind, index });

    if (chunks.length !== Number(expectedTotalChunks)) {
        throw createHttpError(400, "failed_precondition", `Missing chunks for ${kind} ${index}.`, {
            expectedTotalChunks,
            found: chunks.length,
        });
    }
    if (chunks.length < 1) {
        throw createHttpError(400, "failed_precondition", `No chunks uploaded for ${kind} ${index}.`);
    }

    const tmpComposePrefix = `${TMP_UPLOAD_PREFIX}/${uid}/${sessionId}/__compose/${kind}_${String(index)}`;
    await composeManyToDest({
        sourceNames: chunks,
        destName: destPath,
        tmpPrefixForIntermediates: tmpComposePrefix,
    });

    try {
        await bucket.file(destPath).setMetadata({
            contentType: contentType || "application/octet-stream",
            cacheControl: kind === "cover" ? "public, max-age=3600" : "private, max-age=0, no-store",
        });
    } catch (e) {
        console.error("setMetadata failed:", destPath, e?.message);
    }

    const prefix = `${TMP_UPLOAD_PREFIX}/${uid}/${sessionId}/${kind}_${String(index)}/`;
    await deleteByPrefix(prefix);

    await deleteByPrefix(`${TMP_UPLOAD_PREFIX}/${uid}/${sessionId}/__compose/${kind}_${String(index)}/`).catch(() => null);

    return destPath;
}

/* ============================= PRODUCT CANCELATION (DRAFT ABORT + CLEANUP) ============================= */

async function cleanupCanceledProduct({ uid, productId, sessionId }) {
    const pathsToDelete = [];

    // If product doc exists, collect final paths
    if (productId) {
        const pRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId));
        const pSnap = await pRef.get();
        if (pSnap.exists) {
            const p = pSnap.data() || {};
            if (p.uid === uid) {
                if (p.coverPath) pathsToDelete.push(String(p.coverPath));
                for (const a of Array.isArray(p.assets) ? p.assets : []) {
                    if (a?.filePath) pathsToDelete.push(String(a.filePath));
                }
            }
        }
    }

    // Delete final files best-effort (ignoreNotFound)
    for (const pth of pathsToDelete) {
        try {
            await bucket.file(pth).delete({ ignoreNotFound: true });
        } catch (e) {
            console.error("cleanupCanceledProduct delete file failed:", pth, e?.message);
        }
    }

    // Delete tmp uploads
    if (sessionId) {
        const tmpPrefix = `${TMP_UPLOAD_PREFIX}/${uid}/${String(sessionId)}/`;
        await deleteByPrefix(tmpPrefix).catch(() => null);
    }
}

exports.cancelProductCreation = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "cancelProductCreation";
        try {
            if (req2.method !== "POST") throw createHttpError(405, "method_not_allowed", "POST required.");

            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { productId = "", sessionId = "", clientRequestId = "" } = req2.body || {};
            let pid = String(productId || "").trim();
            let sid = String(sessionId || "").trim();
            const crid = normalizeClientRequestId(clientRequestId);

            // If we only have clientRequestId, derive deterministic ids
            if ((!pid || !sid) && crid) {
                if (!pid) pid = deterministicIdFromClientRequest("prod", decoded.uid, crid, 28);
                if (!sid) sid = deterministicIdFromClientRequest("sess", decoded.uid, crid, 28);
            }

            if (!pid && !sid && !crid) throw createHttpError(400, "invalid_argument", "productId or sessionId or clientRequestId is required.");

            // 0) Mark create request canceled (so in-flight createDraft can refuse if it checks)
            if (crid) {
                const reqDocId = requestDocIdFor(decoded.uid, crid);
                const reqRef = db.collection(PRODUCT_CREATE_REQUESTS_COLLECTION).doc(reqDocId);
                await reqRef.set(
                    {
                        uid: decoded.uid,
                        clientRequestId: crid,
                        status: "canceled",
                        canceledAt: nowServerTimestamp(),
                        updatedAt: nowServerTimestamp(),
                        productId: pid || null,
                        sessionId: sid || null,
                    },
                    { merge: true }
                );
            }

            // 1) Mark upload session canceled (if exists)
            if (sid) {
                const sRef = db.collection("uploadSessions").doc(sid);
                const sSnap = await sRef.get();
                if (sSnap.exists) {
                    const s = sSnap.data() || {};
                    if (s.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
                    await sRef.set({ status: "canceled", canceledAt: nowServerTimestamp(), updatedAt: nowServerTimestamp() }, { merge: true });
                    await sRef.delete().catch(() => null);
                }
            }

            // 2) Delete product draft doc if it exists and belongs to user
            if (pid) {
                const pRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(pid);
                const pSnap = await pRef.get();
                if (pSnap.exists) {
                    const p = pSnap.data() || {};
                    if (p.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
                    if (p.status && p.status !== PRODUCT_STATUS.DRAFT) {
                        throw createHttpError(409, "failed_precondition", "Only draft products can be canceled.");
                    }
                    await pRef.delete().catch(() => null);
                }
            }

            // 3) Storage cleanup (tmp + any final objects already composed)
            await cleanupCanceledProduct({ uid: decoded.uid, productId: pid || null, sessionId: sid || null });

            res2.status(200).json({ success: true, canceled: true });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, { body: req2.body });
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= HTTP: SELLER PROFILE ============================= */

exports.setSellerProfile = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "setSellerProfile";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const {
                description = "",
                contactEmail = "",
                contactLinks = {},
                photoPath = "",
                photoUrl = "",
                accountType = "",
                fullName = "",
                businessName = "",
            } = req2.body || {};

            if (contactEmail && !isEmail(contactEmail)) {
                throw createHttpError(400, "invalid_argument", "Invalid contactEmail format.");
            }

            const normType = normalizeAccountType(accountType);

            await db.collection("users").doc(decoded.uid).set(
                {
                    sellerProfile: {
                        description: String(description).slice(0, 1000),
                        contactEmail: contactEmail || "",
                        contactLinks: contactLinks && typeof contactLinks === "object" ? contactLinks : {},
                        photoPath: photoPath || "",
                        photoUrl: photoUrl || "",
                        accountType: normType,
                        fullName: String(fullName || "").slice(0, 120),
                        businessName: String(businessName || "").slice(0, 140),
                        updatedAt: nowServerTimestamp(),
                    },
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            res2.status(200).json({ success: true });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

exports.getSellerProfile = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getSellerProfile";
        try {
            const sellerUid = req2.query.uid;
            if (!sellerUid) throw createHttpError(400, "invalid_argument", "Missing uid.");

            const snap = await db.collection("users").doc(String(sellerUid)).get();
            if (!snap.exists) throw createHttpError(404, "not_found", "Seller not found.");

            const p = snap.data()?.sellerProfile || {};
            res2.status(200).json({
                success: true,
                profile: {
                    description: p.description || "",
                    contactEmail: p.contactEmail || "",
                    contactLinks: p.contactLinks || {},
                    photoUrl: p.photoUrl || "",
                    accountType: normalizeAccountType(p.accountType),
                    fullName: p.fullName || "",
                    businessName: p.businessName || "",
                },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= PUBLIC: SELLER INFO (FOR product.html MODAL) ============================= */

exports.getSellerInfo = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getSellerInfo";
        try {
            if (req2.method !== "GET") throw createHttpError(405, "method_not_allowed", "GET required.");

            const sellerId = String(req2.query.sellerId || req2.query.uid || "").trim();
            if (!sellerId) throw createHttpError(400, "invalid_argument", "Missing sellerId.");

            const snap = await db.collection("users").doc(sellerId).get();
            if (!snap.exists) throw createHttpError(404, "not_found", "Seller not found.");

            const seller = buildSellerPublicInfo(snap.data(), sellerId);

            res2.status(200).json({ success: true, seller });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, { query: req2.query });
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= HTTP: PAYOUT SETTINGS (WEEKLY ONLY) ============================= */

exports.updatePayoutSettings = onRequest({ invoker: "public", secrets: [sendgridApiKey, appBaseUrl] }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "updatePayoutSettings";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { paypalEmail } = req2.body || {};
            if (!paypalEmail || !isEmail(paypalEmail)) {
                throw createHttpError(400, "invalid_argument", "Valid paypalEmail is required.");
            }

            const firstNext = nextFridayNoonUtc(new Date());

            await db.collection("users").doc(decoded.uid).set(
                {
                    paypalEmail: String(paypalEmail).trim(),
                    payoutSchedule: {
                        type: "weekly_friday",
                        chosenAt: nowServerTimestamp(),
                        nextPayoutAt: admin.firestore.Timestamp.fromDate(firstNext),
                        minAmount: MIN_PAYOUT_AMOUNT,
                    },
                    payoutNextAt: admin.firestore.Timestamp.fromDate(firstNext),
                    onboardingComplete: true,
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            const userDoc = await db.collection("users").doc(decoded.uid).get();
            const to = userDoc.data()?.email;
            if (to && isEmail(to)) {
                const base = getPublicSiteOrigin();
                const dashboardUrl = `${base}/dashboard.html`;

                await sendEmail("payout_settings_updated", {
                    to,
                    subject: "Your payout settings are updated",
                    title: "Payout settings updated",
                    preheader: "Your PayPal email has been saved.",
                    bodyHtml: `
                      <p>Your payout method is ready. We’ll send payouts to:</p>
                      ${kvTable([
                        ["PayPal email", `<span style="font-weight:800;">${String(paypalEmail).trim()}</span>`],
                        ["Schedule", `<span style="font-weight:800;color:#007bff;">${weeklyScheduleLabel()}</span>`],
                        ["Minimum payout", `<span style="font-weight:800;">${MIN_PAYOUT_AMOUNT.toFixed(2)} USD</span>`],
                        ["Next payout", `<span style="font-weight:800;">${firstNext.toUTCString()}</span>`],
                    ])}
                      ${emailButton({ href: dashboardUrl, label: "Open your dashboard", tone: "primary" })}
                    `,
                    uid: decoded.uid,
                });
            }

            res2.status(200).json({
                success: true,
                payoutSchedule: {
                    type: "weekly_friday",
                    nextPayoutAt: firstNext.toISOString(),
                    minAmount: MIN_PAYOUT_AMOUNT,
                },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

exports.getPayoutSettings = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getPayoutSettings";
        try {
            const decoded = await requireAuth(req2);
            const snap = await db.collection("users").doc(decoded.uid).get();
            if (!snap.exists) throw createHttpError(404, "not_found", "User not found.");
            const u = snap.data();

            res2.status(200).json({
                success: true,
                paypalEmail: u.paypalEmail || null,
                payoutSchedule: u.payoutSchedule || { type: "weekly_friday", minAmount: MIN_PAYOUT_AMOUNT },
                payoutNextAt: u.payoutNextAt?.toDate?.()?.toISOString?.() || null,
                balance: Number(u.balance || 0),
                isBanned: !!u.isBanned,
                minPayoutAmount: MIN_PAYOUT_AMOUNT,
                accountStatus: u.accountStatus || "active",
                freezeUntil: u.freezeUntil?.toDate?.()?.toISOString?.() || null,
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= LEGACY COMPAT ============================= */

exports.getUserPaypalStatus = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getUserPaypalStatus";
        try {
            const decoded = await requireAuth(req2);
            const snap = await db.collection("users").doc(decoded.uid).get();
            if (!snap.exists) throw createHttpError(404, "not_found", "User not found.");
            const u = snap.data() || {};
            const active = !!u.paypalEmail;

            res2.status(200).json({
                success: true,
                active,
                paypalEmail: u.paypalEmail || null,
                payoutSchedule: u.payoutSchedule || { type: "weekly_friday", minAmount: MIN_PAYOUT_AMOUNT },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

exports.getUserData = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getUserData";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            await statsInitIfMissing(decoded.uid);

            const [userSnap, statsSnap] = await Promise.all([
                db.collection("users").doc(decoded.uid).get(),
                db.collection("userStats").doc(decoded.uid).get(),
            ]);

            if (!userSnap.exists) throw createHttpError(404, "not_found", "User not found.");
            const u = userSnap.data() || {};
            const st = statsSnap.data() || {};

            res2.status(200).json({
                success: true,
                user: {
                    uid: decoded.uid,
                    email: u.email || decoded.email || null,
                    displayName: u.displayName || null,
                    balance: Number(u.balance || 0),
                    paypalEmail: u.paypalEmail || null,
                    payoutSchedule: u.payoutSchedule || { type: "weekly_friday", minAmount: MIN_PAYOUT_AMOUNT },
                    strikes: u.strikes || { points: 0, reds: 0 },
                    isBanned: !!u.isBanned,
                    accountStatus: u.accountStatus || "active",
                    freezeUntil: u.freezeUntil?.toDate?.()?.toISOString?.() || null,
                },
                stats: {
                    generatedLinksCount: Number(st.generatedLinksCount || 0),
                    viewsCount: Number(st.viewsCount || 0),
                    ordersCount: Number(st.ordersCount || 0),
                    processedCount: Number(st.processedCount || 0),
                    lifetimeNetIncome: Number(st.lifetimeNetIncome || 0),

                    productsCreatedCount: Number(st.productsCreatedCount || 0),
                    productsActiveCount: Number(st.productsActiveCount || 0),
                    productsArchivedCount: Number(st.productsArchivedCount || 0),
                    productsDeletedCount: Number(st.productsDeletedCount || 0),
                },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

exports.updatePaypalEmail = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "updatePaypalEmail";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { paypalEmail } = req2.body || {};
            if (!paypalEmail || !isEmail(paypalEmail)) {
                throw createHttpError(400, "invalid_argument", "Valid paypalEmail is required.");
            }

            const next = nextFridayNoonUtc(new Date());

            await db.collection("users").doc(decoded.uid).set(
                {
                    paypalEmail: String(paypalEmail).trim(),
                    payoutSchedule: {
                        type: "weekly_friday",
                        chosenAt: nowServerTimestamp(),
                        nextPayoutAt: admin.firestore.Timestamp.fromDate(next),
                        minAmount: MIN_PAYOUT_AMOUNT,
                    },
                    payoutNextAt: admin.firestore.Timestamp.fromDate(next),
                    onboardingComplete: true,
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            res2.status(200).json({
                success: true,
                paypalEmail: String(paypalEmail).trim(),
                payoutSchedule: { type: "weekly_friday", nextPayoutAt: next.toISOString(), minAmount: MIN_PAYOUT_AMOUNT },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= HTTP: DASHBOARD SUMMARY ============================= */

exports.getDashboardSummary = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getDashboardSummary";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            await statsInitIfMissing(decoded.uid);

            const [userSnap, statsSnap] = await Promise.all([
                db.collection("users").doc(decoded.uid).get(),
                db.collection("userStats").doc(decoded.uid).get(),
            ]);

            const user = userSnap.data() || {};
            const stats = statsSnap.data() || {};

            res2.status(200).json({
                success: true,
                summary: {
                    generatedLinksCount: Number(stats.generatedLinksCount || 0),
                    viewsCount: Number(stats.viewsCount || 0),
                    ordersCount: Number(stats.ordersCount || 0),
                    processedCount: Number(stats.processedCount || 0),
                    incomeAvailable: Number(user.balance || 0),
                    lifetimeNetIncome: Number(stats.lifetimeNetIncome || 0),

                    productsCreatedCount: Number(stats.productsCreatedCount || 0),
                    productsActiveCount: Number(stats.productsActiveCount || 0),
                    productsArchivedCount: Number(stats.productsArchivedCount || 0),
                    productsDeletedCount: Number(stats.productsDeletedCount || 0),

                    strikes: user.strikes || { points: 0, reds: 0 },
                    paypalEmail: user.paypalEmail || null,
                    payoutSchedule: user.payoutSchedule || { type: "weekly_friday", minAmount: MIN_PAYOUT_AMOUNT },
                    payoutNextAt: user.payoutNextAt?.toDate?.()?.toISOString?.() || null,

                    accountStatus: user.accountStatus || "active",
                    freezeUntil: user.freezeUntil?.toDate?.()?.toISOString?.() || null,
                },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= HTTP: PRODUCTS (DRAFT + CHUNK UPLOADS) ============================= */

exports.createProductDraft = onRequest({ invoker: "public", secrets: [appBaseUrl] }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "createProductDraft";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { title, description, price, category, subtype, coverMeta, assetsMeta, clientRequestId = "" } = req2.body || {};

            validateProductInput({ title, description, price, category, subtype, coverMeta, assetsMeta });

            const userSnap = await db.collection("users").doc(decoded.uid).get();
            const u = userSnap.data() || {};
            if (!u.paypalEmail) {
                throw createHttpError(400, "failed_precondition", "Payout settings required before creating products (PayPal email).");
            }

            // ✅ Deterministic draft/session ids if clientRequestId is provided (enables cancel even if frontend never got ids)
            const crid = normalizeClientRequestId(clientRequestId);
            const productId = crid
                ? deterministicIdFromClientRequest("prod", decoded.uid, crid, 28)
                : db.collection(PRODUCT_COLLECTION_ACTIVE).doc().id;
            const sessionId = crid ? deterministicIdFromClientRequest("sess", decoded.uid, crid, 28) : generateTokenHex(20);

            // If this request was canceled before/during, refuse creation
            if (crid) {
                const reqRef = db.collection(PRODUCT_CREATE_REQUESTS_COLLECTION).doc(requestDocIdFor(decoded.uid, crid));
                const reqSnap = await reqRef.get().catch(() => null);
                if (reqSnap && reqSnap.exists && String(reqSnap.data()?.status || "") === "canceled") {
                    throw createHttpError(409, "canceled", "Product creation was canceled.");
                }
            }

            // If draft already exists (idempotent), return its session info
            const existingSnap = await db.collection(PRODUCT_COLLECTION_ACTIVE).doc(productId).get();
            if (existingSnap.exists) {
                const p0 = existingSnap.data() || {};
                if (p0.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
                if (p0.status && p0.status !== PRODUCT_STATUS.DRAFT) {
                    throw createHttpError(409, "failed_precondition", "Draft already finalized.");
                }
                const base0 = getPublicSiteOrigin();
                const shareableLink0 = `${base0}/product.html?productId=${productId}`;
                res2.status(200).json({
                    success: true,
                    productId,
                    shareableLink: shareableLink0,
                    upload: {
                        sessionId: p0?.uploadSession?.id || sessionId,
                        chunkSizeBytes: Number(p0?.uploadSession?.chunkSizeBytes || UPLOAD_CHUNK_SIZE_BYTES),
                        expiresAt: p0?.uploadSession?.expiresAt?.toDate?.()?.toISOString?.() || null,
                    },
                    reused: true,
                });
                return;
            }

            const now = Date.now();
            const expiresAt = new Date(now + UPLOAD_SESSION_TTL_MS);

            const coverExt = safeExtFromName(coverMeta.originalName);
            const coverPath = `covers/${decoded.uid}/${productId}/cover${coverExt || ""}`;

            const kind = inferKind(category, subtype);

            const assets = assetsMeta.map((m, i) => {
                const idx = i + 1;
                const ext = safeExtFromName(m.originalName);
                const fp = `products/${decoded.uid}/${productId}/asset_${idx}${ext || ""}`;
                const sizeBytes = Number(m.sizeBytes || 0);
                const totalChunks = Math.max(1, Math.ceil(sizeBytes / UPLOAD_CHUNK_SIZE_BYTES));

                return {
                    kind,
                    index: idx,
                    originalName: String(m.originalName || `file_${idx}`),
                    contentType: String(m.contentType || "application/octet-stream"),
                    sizeBytes,
                    totalChunks,
                    filePath: fp,
                };
            });

            const coverSizeBytes = Number(coverMeta.sizeBytes || 0);
            const coverTotalChunks = Math.max(1, Math.ceil(coverSizeBytes / UPLOAD_CHUNK_SIZE_BYTES));

            // ✅ Always custom domain link
            const base = getPublicSiteOrigin();
            const shareableLink = `${base}/product.html?productId=${productId}`;

            await db.runTransaction(async (tx) => {
                if (crid) {
                    const reqRef = db.collection(PRODUCT_CREATE_REQUESTS_COLLECTION).doc(requestDocIdFor(decoded.uid, crid));
                    const reqSnap = await tx.get(reqRef);
                    if (reqSnap.exists && String(reqSnap.data()?.status || "") === "canceled") {
                        throw createHttpError(409, "canceled", "Product creation was canceled.");
                    }
                    tx.set(
                        reqRef,
                        {
                            uid: decoded.uid,
                            clientRequestId: crid,
                            status: "created",
                            productId,
                            sessionId,
                            createdAt: nowServerTimestamp(),
                            updatedAt: nowServerTimestamp(),
                        },
                        { merge: true }
                    );
                }

                const productRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(productId);

                tx.set(productRef, {
                    uid: decoded.uid,
                    title: String(title).trim(),
                    description: String(description).trim(),
                    price: Number(price),
                    category,
                    subtype,
                    status: PRODUCT_STATUS.DRAFT,
                    shareableLink, // stored but responses compute from custom domain too

                    createRequestId: crid || null,

                    coverPath,
                    coverOriginalName: String(coverMeta.originalName || "cover"),
                    coverContentType: String(coverMeta.contentType || "image/jpeg"),
                    coverSizeBytes,
                    coverTotalChunks,

                    assets,
                    counters: { viewsCount: 0, salesCount: 0, netRevenue: 0 },

                    uploadSession: {
                        id: sessionId,
                        chunkSizeBytes: UPLOAD_CHUNK_SIZE_BYTES,
                        createdAt: admin.firestore.Timestamp.fromMillis(now),
                        expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
                        status: "open",
                    },

                    createdAt: nowServerTimestamp(),
                    updatedAt: nowServerTimestamp(),
                });

                const sessionRef = db.collection("uploadSessions").doc(sessionId);
                tx.set(sessionRef, {
                    uid: decoded.uid,
                    productId,
                    createRequestId: crid || null,
                    chunkSizeBytes: UPLOAD_CHUNK_SIZE_BYTES,
                    createdAt: admin.firestore.Timestamp.fromMillis(now),
                    expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
                    cover: {
                        originalName: String(coverMeta.originalName || "cover"),
                        contentType: String(coverMeta.contentType || "image/jpeg"),
                        sizeBytes: coverSizeBytes,
                        totalChunks: coverTotalChunks,
                        coverPath,
                    },
                    assets,
                    status: "open",
                });
            });

            // Keep legacy stat (draft links created)
            await statsInc(decoded.uid, { generatedLinksCount: 1 });

            res2.status(200).json({
                success: true,
                productId,
                shareableLink,
                upload: {
                    sessionId,
                    chunkSizeBytes: UPLOAD_CHUNK_SIZE_BYTES,
                    expiresAt: expiresAt.toISOString(),
                },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, { body: req2.body });
            res2
                .status(e.httpStatus || 500)
                .json({ success: false, error: e.message || "Internal error", code: e.code || "internal", meta: e.meta || null });
        }
    });
});

exports.uploadProductChunk = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "uploadProductChunk";
        try {
            if (req2.method !== "POST") throw createHttpError(405, "method_not_allowed", "POST required.");

            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const productId = String(req2.query.productId || "");
            const sessionId = String(req2.query.sessionId || "");
            const kind = String(req2.query.kind || "");
            const index = Number(req2.query.index || 0);
            const chunkIndex = Number(req2.query.chunkIndex || 0);
            const totalChunks = Number(req2.query.totalChunks || 0);

            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");
            if (!sessionId) throw createHttpError(400, "invalid_argument", "Missing sessionId.");
            if (!["cover", "asset"].includes(kind)) throw createHttpError(400, "invalid_argument", "Invalid kind.");
            if (!Number.isFinite(chunkIndex) || chunkIndex < 1) throw createHttpError(400, "invalid_argument", "Invalid chunkIndex.");
            if (!Number.isFinite(totalChunks) || totalChunks < 1) throw createHttpError(400, "invalid_argument", "Invalid totalChunks.");
            if (!Number.isFinite(index) || index < 0) throw createHttpError(400, "invalid_argument", "Invalid index.");

            // Product must still be a draft and belong to user
            const pSnap = await db.collection(PRODUCT_COLLECTION_ACTIVE).doc(productId).get();
            if (!pSnap.exists) throw createHttpError(404, "not_found", "Product not found (maybe canceled).");
            const p = pSnap.data() || {};
            if (p.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
            if (p.status !== PRODUCT_STATUS.DRAFT) throw createHttpError(409, "failed_precondition", "Product is not a draft.");

            const sessionSnap = await db.collection("uploadSessions").doc(sessionId).get();
            if (!sessionSnap.exists) throw createHttpError(404, "not_found", "Upload session not found (maybe canceled).");
            const session = sessionSnap.data();

            if (session.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
            if (String(session.productId) !== productId) throw createHttpError(403, "permission_denied", "Session does not match product.");
            if (session.status !== "open") throw createHttpError(409, "failed_precondition", "Upload session is not open.");

            const exp = session.expiresAt?.toDate ? session.expiresAt.toDate() : new Date(session.expiresAt);
            if (exp && exp.getTime() < Date.now()) throw createHttpError(410, "deadline_exceeded", "Upload session expired.");

            const chunkSize = Number(session.chunkSizeBytes || UPLOAD_CHUNK_SIZE_BYTES);

            const raw = req2.rawBody;
            if (!raw || !raw.length) throw createHttpError(400, "invalid_argument", "Missing chunk body.");
            if (raw.length > chunkSize) throw createHttpError(400, "invalid_argument", `Chunk too large. Max ${chunkSize} bytes.`);

            if (kind === "cover") {
                if (index !== 0) throw createHttpError(400, "invalid_argument", "Cover index must be 0.");
                const expTotal = Number(session.cover?.totalChunks || 0);
                if (expTotal && totalChunks !== expTotal) {
                    throw createHttpError(400, "invalid_argument", "totalChunks mismatch for cover.", { expected: expTotal, got: totalChunks });
                }
                if (chunkIndex > totalChunks) throw createHttpError(400, "invalid_argument", "chunkIndex out of range.");
            } else {
                const assets = Array.isArray(session.assets) ? session.assets : [];
                const asset = assets.find((a) => Number(a.index) === Number(index));
                if (!asset) throw createHttpError(400, "invalid_argument", "Unknown asset index.");
                const expTotal = Number(asset.totalChunks || 0);
                if (expTotal && totalChunks !== expTotal) {
                    throw createHttpError(400, "invalid_argument", "totalChunks mismatch for asset.", { expected: expTotal, got: totalChunks });
                }
                if (chunkIndex > totalChunks) throw createHttpError(400, "invalid_argument", "chunkIndex out of range.");
            }

            const objPath = chunkObjectPath({ uid: decoded.uid, sessionId, kind, index, chunkIndex });

            await bucket.file(objPath).save(raw, {
                resumable: false,
                metadata: { contentType: "application/octet-stream", cacheControl: "no-store" },
            });

            res2.status(200).json({ success: true, path: objPath });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, { query: req2.query });
            res2
                .status(e.httpStatus || 500)
                .json({ success: false, error: e.message || "Internal error", code: e.code || "internal", meta: e.meta || null });
        }
    });
});

exports.finalizeProductUploads = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "finalizeProductUploads";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { productId, sessionId } = req2.body || {};
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");
            if (!sessionId) throw createHttpError(400, "invalid_argument", "Missing sessionId.");

            const sessionRef = db.collection("uploadSessions").doc(String(sessionId));
            const sessionSnap = await sessionRef.get();
            if (!sessionSnap.exists) throw createHttpError(404, "not_found", "Upload session not found (maybe canceled).");
            const session = sessionSnap.data();

            if (session.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
            if (String(session.productId) !== String(productId)) throw createHttpError(403, "permission_denied", "Session does not match product.");
            if (session.status !== "open") throw createHttpError(409, "failed_precondition", "Upload session not open.");

            const exp = session.expiresAt?.toDate ? session.expiresAt.toDate() : new Date(session.expiresAt);
            if (exp && exp.getTime() < Date.now()) throw createHttpError(410, "deadline_exceeded", "Upload session expired.");

            const productRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId));
            const productSnap = await productRef.get();
            if (!productSnap.exists) throw createHttpError(404, "not_found", "Product not found (maybe canceled).");

            const p = productSnap.data();
            if (p.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");
            if (p.status !== PRODUCT_STATUS.DRAFT) {
                throw createHttpError(409, "failed_precondition", `Cannot finalize from status '${p.status}'.`);
            }

            const cover = session.cover || {};
            await composeChunksToFinalObject({
                uid: decoded.uid,
                sessionId: String(sessionId),
                kind: "cover",
                index: 0,
                expectedTotalChunks: Number(cover.totalChunks || 0),
                destPath: String(cover.coverPath || p.coverPath || ""),
                contentType: String(cover.contentType || p.coverContentType || "image/jpeg"),
            });

            const assets = Array.isArray(session.assets) ? session.assets : [];
            for (const a of assets) {
                await composeChunksToFinalObject({
                    uid: decoded.uid,
                    sessionId: String(sessionId),
                    kind: "asset",
                    index: Number(a.index),
                    expectedTotalChunks: Number(a.totalChunks || 0),
                    destPath: String(a.filePath || ""),
                    contentType: String(a.contentType || "application/octet-stream"),
                });

                try {
                    const [meta] = await bucket.file(String(a.filePath)).getMetadata();
                    const actual = Number(meta?.size || 0);
                    const expected = Number(a.sizeBytes || 0);
                    if (expected > 0 && actual > expected + 1024) {
                        await bucket.file(String(a.filePath)).delete({ ignoreNotFound: true });
                        throw createHttpError(400, "invalid_argument", `Composed file size mismatch for ${a.originalName}.`);
                    }
                } catch (e) {
                    if (e.httpStatus) throw e;
                    console.error("asset metadata verify failed:", a.filePath, e?.message);
                }
            }

            await productRef.set(
                {
                    status: PRODUCT_STATUS.ACTIVE,
                    publishedAt: nowServerTimestamp(),
                    uploadSession: { status: "finalized", finalizedAt: nowServerTimestamp() },
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            // Mark create request completed (if any)
            const crid = String(p.createRequestId || "").trim();
            if (crid) {
                const reqRef = db.collection(PRODUCT_CREATE_REQUESTS_COLLECTION).doc(requestDocIdFor(decoded.uid, crid));
                await reqRef.set({ status: "completed", completedAt: nowServerTimestamp(), updatedAt: nowServerTimestamp(), productId: String(productId), sessionId: String(sessionId) }, { merge: true }).catch(() => null);
            }

            await sessionRef.set({ status: "finalized", finalizedAt: nowServerTimestamp() }, { merge: true });
            await sessionRef.delete().catch(() => null);

            const tmpPrefix = `${TMP_UPLOAD_PREFIX}/${decoded.uid}/${String(sessionId)}/`;
            await deleteByPrefix(tmpPrefix).catch(() => null);

            // ✅ Stats: product becomes "created/active" only when it becomes ACTIVE
            await statsInc(decoded.uid, { productsCreatedCount: 1, productsActiveCount: 1 });

            res2.status(200).json({ success: true, status: PRODUCT_STATUS.ACTIVE });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2
                .status(e.httpStatus || 500)
                .json({ success: false, error: e.message || "Internal error", code: e.code || "internal", meta: e.meta || null });
        }
    });
});

/* ============================= HTTP: PRODUCT LIST ============================= */

exports.getLinks = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getLinks";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const base = getPublicSiteOrigin();

            // ✅ Only active collection. Archived products are moved away and won't appear in seller dashboard.
            const snap = await db
                .collection(PRODUCT_COLLECTION_ACTIVE)
                .where("uid", "==", decoded.uid)
                .orderBy("createdAt", "desc")
                .get();

            const products = snap.docs
                .map((d) => {
                    const p = d.data() || {};
                    const status = p.status || PRODUCT_STATUS.DRAFT;

                    // ✅ Do not return drafts to dashboard (prevents canceled/incomplete creations showing)
                    if (status === PRODUCT_STATUS.DRAFT) return null;
                    if (status === PRODUCT_STATUS.DELETED) return null;
                    if (status === PRODUCT_STATUS.ARCHIVED) return null;

                    const productUrl = `${base}/product.html?productId=${d.id}`;

                    return {
                        id: d.id,
                        title: p.title || "",
                        price: Number(p.price || 0),
                        category: p.category || "",
                        subtype: p.subtype || "",
                        status,
                        // ✅ Always custom domain
                        shareableLink: productUrl,
                        productUrl,
                        counters: p.counters || { viewsCount: 0, salesCount: 0, netRevenue: 0 },
                        createdAt: p.createdAt ? p.createdAt.toDate?.() || null : null,
                        updatedAt: p.updatedAt ? p.updatedAt.toDate?.() || null : null,
                    };
                })
                .filter(Boolean);

            res2.status(200).json({ success: true, links: products });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= HTTP: DELETE PRODUCT (ARCHIVE OR FULL DELETE) ============================= */

async function loadProductById(productId) {
    const pSnap = await db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId)).get();
    if (pSnap.exists) return { ref: pSnap.ref, snap: pSnap, data: pSnap.data(), collection: PRODUCT_COLLECTION_ACTIVE };

    const aSnap = await db.collection(PRODUCT_COLLECTION_ARCHIVED).doc(String(productId)).get();
    if (aSnap.exists) return { ref: aSnap.ref, snap: aSnap, data: aSnap.data(), collection: PRODUCT_COLLECTION_ARCHIVED };

    return null;
}

exports.deleteProduct = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "deleteProduct";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { productId } = req2.body || {};
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");

            const pActiveRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId));
            const productSnap = await pActiveRef.get();
            if (!productSnap.exists) throw createHttpError(404, "not_found", "Product not found.");

            const product = productSnap.data();
            if (product.uid !== decoded.uid) throw createHttpError(403, "permission_denied", "Forbidden.");

            const ordersSnap = await db.collection("orders").where("productId", "==", pActiveRef.id).limit(1).get();
            const hasOrders = !ordersSnap.empty;

            // ✅ Rule:
            // - If sales exist => move doc from products -> archivedProducts (removed from seller dashboard)
            // - If no sales => delete files + delete product
            if (hasOrders) {
                const archivedRef = db.collection(PRODUCT_COLLECTION_ARCHIVED).doc(pActiveRef.id);

                await db.runTransaction(async (tx) => {
                    const fresh = await tx.get(pActiveRef);
                    if (!fresh.exists) return;

                    const p = fresh.data() || {};
                    tx.set(
                        archivedRef,
                        {
                            ...p,
                            status: PRODUCT_STATUS.ARCHIVED,
                            archivedAt: nowServerTimestamp(),
                            updatedAt: nowServerTimestamp(),
                            archivedFrom: PRODUCT_COLLECTION_ACTIVE,
                        },
                        { merge: true }
                    );
                    tx.delete(pActiveRef);
                });

                // stats: active--, archived++
                await statsInc(decoded.uid, { productsActiveCount: -1, productsArchivedCount: 1 });

                res2.status(200).json({
                    success: true,
                    mode: "archived",
                    message: "Product archived (orders exist). Removed from seller dashboard, kept for buyers.",
                });
                return;
            }

            const paths = [];
            if (product.coverPath) paths.push(product.coverPath);
            for (const a of Array.isArray(product.assets) ? product.assets : []) {
                if (a.filePath) paths.push(a.filePath);
            }

            for (const pth of paths) {
                try {
                    await bucket.file(pth).delete({ ignoreNotFound: true });
                } catch (e) {
                    console.error("Failed deleting storage file:", pth, e?.message);
                }
            }

            await Promise.allSettled([
                deleteQueryBatch(db.collection("productViews").where("productId", "==", pActiveRef.id)),
                deleteQueryBatch(db.collection("paymentSessions").where("productId", "==", pActiveRef.id)),
            ]);

            await pActiveRef.delete();

            // stats: deleted++ and if it was ACTIVE, active-- (best-effort)
            if (product.status === PRODUCT_STATUS.ACTIVE) await statsInc(decoded.uid, { productsActiveCount: -1, productsDeletedCount: 1 });
            else await statsInc(decoded.uid, { productsDeletedCount: 1 });

            res2.status(200).json({ success: true, mode: "deleted", message: "Product deleted (no sales). Files removed." });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= PUBLIC: PRODUCT DETAILS + COVER STREAM ============================= */

exports.getProductDetails = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getProductDetails";
        try {
            const productId = req2.query.productId;
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");

            // ✅ Public details only from active products collection
            const docSnap = await db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId)).get();
            if (!docSnap.exists) throw createHttpError(404, "not_found", "Product not found.");

            const product = docSnap.data();
            const sellable = product.status === PRODUCT_STATUS.ACTIVE;
            const status = product.status || PRODUCT_STATUS.DRAFT;

            const apiBase = `https://${req2.get("host")}`;
            const coverUrl = sellable ? `${apiBase}/getProductCover?productId=${encodeURIComponent(docSnap.id)}` : null;

            const sellerDoc = await db.collection("users").doc(product.uid).get();
            const sellerData = sellerDoc.exists ? sellerDoc.data() : {};
            const sellerPublic = buildSellerPublicInfo(sellerData, product.uid);

            const sellerName =
                sellerPublic.accountType === SELLER_ACCOUNT_TYPE.BUSINESS
                    ? sellerPublic.businessName || sellerPublic.fullName || "Seller"
                    : sellerPublic.fullName || "Seller";

            const sellerProfile = sellerData?.sellerProfile || {};

            res2.status(200).json({
                success: true,
                product: {
                    id: docSnap.id,
                    title: product.title || "",
                    description: product.description || "",
                    price: Number(product.price || 0),
                    category: product.category || "",
                    subtype: product.subtype || "",
                    status,
                    sellable,
                    coverUrl,
                    // ✅ Always ensure shareable link uses custom domain
                    shareableLink: `${getPublicSiteOrigin()}/product.html?productId=${docSnap.id}`,

                    sellerUid: product.uid,
                    sellerId: product.uid,
                    sellerName,

                    sellerProfile: {
                        photoUrl: sellerProfile.photoUrl || sellerPublic.photoUrl || "",
                        description: sellerProfile.description || "",
                        contactEmail: sellerProfile.contactEmail || sellerPublic.email || "",
                        contactLinks: sellerProfile.contactLinks || sellerPublic.contactLinks || {},
                        accountType: normalizeAccountType(sellerProfile.accountType || sellerPublic.accountType),
                        fullName: sellerProfile.fullName || sellerPublic.fullName || "",
                        businessName: sellerProfile.businessName || sellerPublic.businessName || "",
                    },
                },
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

exports.getProductCover = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getProductCover";
        try {
            const productId = String(req2.query.productId || "");
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");

            // ✅ Cover can be served from active or archived (so buyer library thumbnails still work)
            const loaded = await loadProductById(productId);
            if (!loaded) throw createHttpError(404, "not_found", "Product not found.");

            const p = loaded.data || {};
            const coverPath = p.coverPath;
            if (!coverPath) throw createHttpError(404, "not_found", "No cover.");

            const file = bucket.file(coverPath);
            const [meta] = await file.getMetadata();

            res2.setHeader("Content-Type", meta.contentType || "image/jpeg");
            res2.setHeader("Cache-Control", "public, max-age=3600");
            res2.setHeader("X-Content-Type-Options", "nosniff");

            file.createReadStream()
                .on("error", (e) => {
                    console.error(FN, "stream error:", e?.message);
                    if (!res2.headersSent) res2.status(500).end();
                    else res2.end();
                })
                .pipe(res2);
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= PUBLIC: RECORD VIEW ============================= */

exports.recordProductView = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "recordProductView";
        try {
            const { productId, userAgent = "", viewerId = "" } = req2.body || {};
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");

            // Views only apply to active products collection
            const productRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId));
            const snap = await productRef.get();
            if (!snap.exists) throw createHttpError(404, "not_found", "Product not found.");

            const product = snap.data();
            if (product.status !== PRODUCT_STATUS.ACTIVE) {
                res2.status(200).json({ success: true, counted: false, ignored: true });
                return;
            }

            const ip = req2.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req2.ip || "";
            const viewerKey = sha256Hex(viewerId || ip || userAgent || "unknown");

            const now = new Date();
            const nowTs = admin.firestore.Timestamp.fromDate(now);
            const sixHoursAgoTs = admin.firestore.Timestamp.fromDate(new Date(Date.now() - 6 * 60 * 60 * 1000));

            const dedupId = `${productRef.id}_${viewerKey}`;
            const dedupRef = db.collection("productViewDedup").doc(dedupId);

            const deviceInfo = extractDeviceInfo(userAgent);

            const { counted } = await db.runTransaction(async (tx) => {
                const d = await tx.get(dedupRef);
                const last = d.exists ? d.data()?.lastViewedAt : null;

                const lastTs = last?.toMillis ? last : null;
                const recent = lastTs && lastTs.toMillis() >= sixHoursAgoTs.toMillis();

                if (recent) {
                    tx.set(
                        dedupRef,
                        {
                            productId: productRef.id,
                            sellerUid: product.uid,
                            viewerKey,
                            lastSeenAt: nowTs,
                        },
                        { merge: true }
                    );
                    return { counted: false };
                }

                tx.set(
                    dedupRef,
                    {
                        productId: productRef.id,
                        sellerUid: product.uid,
                        viewerKey,
                        lastViewedAt: nowTs,
                        lastSeenAt: nowTs,
                        firstSeenAt: d.exists ? d.data()?.firstSeenAt || nowTs : nowTs,
                        deviceInfo,
                    },
                    { merge: true }
                );

                return { counted: true };
            });

            if (!counted) {
                res2.status(200).json({ success: true, deduped: true });
                return;
            }

            await db.collection("productViews").add({
                productId: productRef.id,
                sellerUid: product.uid,
                viewerKey,
                deviceInfo,
                createdAt: nowServerTimestamp(),
            });

            await productRef.set({ "counters.viewsCount": admin.firestore.FieldValue.increment(1), updatedAt: nowServerTimestamp() }, { merge: true });
            await statsInc(product.uid, { viewsCount: 1 });

            res2.status(200).json({ success: true, counted: true });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= STRIPE CHECKOUT (BUYER EMAIL + DEVICE FINGERPRINT) ============================= */

exports.collectBuyerEmail = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "collectBuyerEmail";
        try {
            const { email, productId, userAgent = "", deviceFingerprint = "" } = req2.body || {};
            if (!email || !productId) throw createHttpError(400, "invalid_argument", "Missing email or productId.");
            if (!isEmail(email)) throw createHttpError(400, "invalid_argument", "Invalid email format.");

            const productSnap = await db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId)).get();
            if (!productSnap.exists) throw createHttpError(404, "not_found", "Product not found.");

            const p = productSnap.data();
            if (p.status !== PRODUCT_STATUS.ACTIVE) throw createHttpError(409, "failed_precondition", "Product not available for sale.");

            const sessionId = generateTokenHex(16);

            const fp = String(deviceFingerprint || "").trim();
            const fpHash = fp ? sha256Hex(fp) : null;

            await db.collection("paymentSessions").doc(sessionId).set({
                email: normalizeEmail(email),
                productId: String(productId),
                createdAt: nowServerTimestamp(),
                completed: false,
                deviceInfo: extractDeviceInfo(userAgent),
                deviceFingerprint: fp || null,
                deviceFingerprintHash: fpHash,
            });

            res2.status(200).json({ success: true, sessionId });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

exports.createStripeCheckoutSession = onRequest({ invoker: "public", secrets: [stripeSecretKey, appBaseUrl] }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "createStripeCheckoutSession";
        try {
            if (!stripe) stripe = require("stripe")(stripeSecretKey.value());

            const { productId, sessionId, successUrl, cancelUrl } = req2.body || {};
            if (!productId || !sessionId) throw createHttpError(400, "invalid_argument", "Missing productId or sessionId.");

            const sessionDoc = await db.collection("paymentSessions").doc(String(sessionId)).get();
            if (!sessionDoc.exists) throw createHttpError(404, "not_found", "Session not found.");
            if (sessionDoc.data().completed) throw createHttpError(409, "failed_precondition", "Session already completed.");

            const productDoc = await db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId)).get();
            if (!productDoc.exists) throw createHttpError(404, "not_found", "Product not found.");

            const product = productDoc.data();
            if (product.status !== PRODUCT_STATUS.ACTIVE) throw createHttpError(409, "failed_precondition", "Product not available for sale.");

            const apiBase = `https://${req2.get("host")}`;
            const checkoutImageUrl = `${apiBase}/getProductCover?productId=${encodeURIComponent(String(productId))}`;

            const unitAmount = Math.round(Number(product.price) * 100);

            const base = getPublicSiteOrigin();
            const successReturn =
                successUrl ||
                `${base}/product.html?productId=${productId}&success=true&session=${encodeURIComponent(sessionId)}`;
            const cancelReturn = cancelUrl || `${base}/product.html?productId=${productId}&cancel=true`;

            const metadata = {
                app_session_id: String(sessionId),
                app_product_id: String(productId),
                app_seller_uid: String(product.uid),
                app_product_title: String(product.title || ""),
            };

            const s = await stripe.checkout.sessions.create({
                mode: "payment",
                payment_method_types: ["card"],
                line_items: [
                    {
                        price_data: {
                            currency: "usd",
                            product_data: {
                                name: product.title,
                                description: product.description || undefined,
                                images: checkoutImageUrl ? [checkoutImageUrl] : [],
                            },
                            unit_amount: unitAmount,
                        },
                        quantity: 1,
                    },
                ],
                customer_email: sessionDoc.data().email || undefined,
                success_url: successReturn,
                cancel_url: cancelReturn,
                metadata,
            });

            await db.collection("paymentSessions").doc(String(sessionId)).set(
                {
                    stripeSessionId: s.id,
                    stripeStatus: "created",
                    updatedAt: nowServerTimestamp(),
                },
                { merge: true }
            );

            res2.status(200).json({ success: true, sessionId: s.id, url: s.url });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= 
   STRIPE WEBHOOK 
   Creates purchases + access codes with advanced security
   ============================= */

exports.stripeWebhook = onRequest(
    {
        invoker: "public",
        secrets: [stripeSecretKey, stripeWebhookSecret, sendgridApiKey, appBaseUrl, adminAlertEmail],
        region: "us-central1",
        memory: "512MiB",
        timeoutSeconds: 300,
    },
    async (req, res) => {
        const FN = "stripeWebhook";
        const startTime = Date.now();

        console.log(`[${FN}] 🎯 Webhook received at ${new Date().toISOString()}`);

        try {
            // ============ STEP 1: Initialize Stripe ============
            if (!stripe) {
                stripe = require("stripe")(stripeSecretKey.value());
                console.log(`[${FN}] ✅ Stripe initialized`);
            }

            // ============ STEP 2: Verify Webhook Signature ============
            const sig = req.get("Stripe-Signature");
            const rawBody = req.rawBody;

            if (!sig) {
                console.error(`[${FN}] ❌ Missing Stripe-Signature header`);
                return res.status(400).json({ error: "missing_signature" });
            }

            if (!rawBody) {
                console.error(`[${FN}] ❌ Missing rawBody`);
                return res.status(400).json({ error: "missing_body" });
            }

            let event;
            try {
                event = stripe.webhooks.constructEvent(
                    rawBody,
                    sig,
                    stripeWebhookSecret.value()
                );
                console.log(`[${FN}] ✅ Signature verified | Event: ${event.type} | ID: ${event.id}`);
            } catch (err) {
                console.error(`[${FN}] ❌ Signature verification failed:`, err?.message);
                return res.status(400).json({ error: "invalid_signature", message: err.message });
            }

            // ============ STEP 3: Filter Event Type ============
            if (event.type !== "checkout.session.completed") {
                console.log(`[${FN}] ⏭️ Ignoring event type: ${event.type}`);
                return res.json({ received: true, ignored: true, type: event.type });
            }

            const session = event.data.object;
            console.log(`[${FN}] 📦 Processing session: ${session.id}`);

            // ============ STEP 4: Extract & Validate Metadata ============
            const appSessionId = session.metadata?.app_session_id;
            const productId = session.metadata?.app_product_id;
            const sellerUid = session.metadata?.app_seller_uid;
            const productTitle = session.metadata?.app_product_title || "Product";
            const buyerEmail = normalizeEmail(
                session.customer_details?.email || session.customer_email
            );

            console.log(`[${FN}] 📋 Metadata extracted:`, {
                appSessionId,
                productId,
                sellerUid,
                productTitle,
                buyerEmail,
            });

            // Validate required fields
            const missingFields = [];
            if (!appSessionId) missingFields.push("app_session_id");
            if (!productId) missingFields.push("app_product_id");
            if (!sellerUid) missingFields.push("app_seller_uid");
            if (!buyerEmail) missingFields.push("buyer_email");

            if (missingFields.length > 0) {
                console.error(`[${FN}] ❌ Missing metadata:`, missingFields);
                await logSystemError(FN, new Error(`Missing metadata: ${missingFields.join(", ")}`), {
                    sessionId: session.id,
                    missingFields,
                });
                return res.status(200).json({
                    received: true,
                    error: "missing_metadata",
                    fields: missingFields
                });
            }

            // ============ STEP 5: Verify Payment Session ============
            const paymentSessionRef = db.collection("paymentSessions").doc(String(appSessionId));
            const paymentSessionDoc = await paymentSessionRef.get();

            if (!paymentSessionDoc.exists) {
                console.error(`[${FN}] ❌ Payment session not found: ${appSessionId}`);
                await logSystemError(FN, new Error("Payment session not found"), {
                    sessionId: session.id,
                    appSessionId,
                });
                return res.status(200).json({
                    received: true,
                    error: "payment_session_not_found"
                });
            }

            // Check if already completed (idempotency)
            if (paymentSessionDoc.data()?.completed) {
                console.log(`[${FN}] ⚠️ Already processed: ${appSessionId}`);
                return res.json({
                    received: true,
                    already_processed: true,
                    orderId: paymentSessionDoc.data()?.orderId
                });
            }

            console.log(`[${FN}] ✅ Payment session validated`);

            // ============ STEP 6: Verify Product ============
            const productRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId));
            const productDoc = await productRef.get();

            if (!productDoc.exists) {
                console.error(`[${FN}] ❌ Product not found: ${productId}`);
                await logSystemError(FN, new Error("Product not found"), {
                    sessionId: session.id,
                    productId,
                });
                return res.status(200).json({
                    received: true,
                    error: "product_not_found"
                });
            }

            const product = productDoc.data();

            if (product.status !== PRODUCT_STATUS.ACTIVE) {
                console.warn(`[${FN}] ⚠️ Product not active: ${productId} | Status: ${product.status}`);
                await logSystemError(FN, new Error("Product not active"), {
                    sessionId: session.id,
                    productId,
                    status: product.status,
                });
                return res.status(200).json({
                    received: true,
                    error: "product_not_active"
                });
            }

            const productPrice = Number(product.price);
            console.log(`[${FN}] ✅ Product validated | Price: $${productPrice.toFixed(2)}`);

            // ============ STEP 7: Calculate Fees & Amounts ============
            let stripeFee = null;

            try {
                const piId = session.payment_intent;
                if (piId) {
                    const pi = await stripe.paymentIntents.retrieve(piId, {
                        expand: ["charges.data.balance_transaction"],
                    });
                    const charge = pi?.charges?.data?.[0];
                    const bt = charge?.balance_transaction;
                    if (bt && typeof bt.fee === "number") {
                        stripeFee = bt.fee / 100;
                        console.log(`[${FN}] 💰 Exact Stripe fee retrieved: $${stripeFee.toFixed(2)}`);
                    }
                }
            } catch (e) {
                console.warn(`[${FN}] ⚠️ Could not retrieve exact Stripe fee:`, e?.message);
            }

            // Fallback calculation if exact fee unavailable
            if (stripeFee === null) {
                stripeFee = productPrice * STRIPE_FEE_RATE_FALLBACK + STRIPE_FEE_FIXED_FALLBACK;
                console.log(`[${FN}] 💰 Using fallback Stripe fee: $${stripeFee.toFixed(2)}`);
            }

            const netAfterStripe = Math.max(0, productPrice - stripeFee);
            const platformFee = netAfterStripe * PLATFORM_RATE;
            const sellerAmount = Math.max(0, netAfterStripe - platformFee);

            console.log(`[${FN}] 💵 Financial breakdown:`, {
                gross: `$${productPrice.toFixed(2)}`,
                stripeFee: `$${stripeFee.toFixed(2)}`,
                platformFee: `$${platformFee.toFixed(2)}`,
                sellerNet: `$${sellerAmount.toFixed(2)}`,
            });

            // ============ STEP 8: Generate Access Credentials ============
            const accessToken = generateTokenHex(32);
            const base = getPublicSiteOrigin();
            const accessUrl = `${base}/access.html?token=${accessToken}`;

            const accessCodePlain = generateAccessCode(10);
            const accessCodeHash = sha256Hex(normalizeAccessCode(accessCodePlain));
            const buyerEmailHash = sha256Hex(buyerEmail);

            console.log(`[${FN}] 🔑 Access credentials generated | Code: ${accessCodePlain}`);

            // ============ STEP 9: Extract Device Info ============
            const ps = paymentSessionDoc.data() || {};
            const orderDeviceInfo = ps.deviceInfo || {
                browser: "Unknown",
                os: "Unknown",
                device: "Unknown",
                userAgent: "",
            };

            const deviceFingerprint = String(ps.deviceFingerprint || "").trim() || null;
            const deviceFingerprintHash = ps.deviceFingerprintHash ||
                (deviceFingerprint ? sha256Hex(deviceFingerprint) : null);

            console.log(`[${FN}] 📱 Device info:`, {
                browser: orderDeviceInfo.browser,
                os: orderDeviceInfo.os,
                hasFingerprint: !!deviceFingerprintHash,
            });

            // ============ STEP 10: Prepare Database Records ============
            const orderRef = db.collection("orders").doc();
            const purchaseRef = db.collection("purchases").doc(orderRef.id);

            // 🔒 Initialize authorized devices - USE REGULAR TIMESTAMP
            const nowDate = admin.firestore.Timestamp.now();

            const authorizedDevices = deviceFingerprintHash
                ? [{
                    fingerprintHash: deviceFingerprintHash,
                    deviceInfo: orderDeviceInfo,
                    authorizedAt: nowDate,
                    source: "purchase",
                }]
                : [];

            const authorizedFingerprintHashes = deviceFingerprintHash
                ? [deviceFingerprintHash]
                : [];

            console.log(`[${FN}] 📝 Creating order: ${orderRef.id}`);

            // ============ STEP 11: Atomic Transaction ============
            await db.runTransaction(async (tx) => {
                // Double-check payment session hasn't been completed
                const freshPS = await tx.get(paymentSessionRef);
                if (!freshPS.exists) {
                    throw createHttpError(404, "not_found", "Payment session disappeared.");
                }
                if (freshPS.data()?.completed) {
                    console.log(`[${FN}] ⚠️ Race condition detected - already completed`);
                    return;
                }

                const txTimestamp = admin.firestore.FieldValue.serverTimestamp();

                // Create order
                tx.set(orderRef, {
                    productId: productRef.id,
                    productTitle,
                    buyerEmail,
                    buyerEmailHash,
                    sellerUid,
                    stripeSessionId: session.id,
                    stripePaymentIntent: session.payment_intent || null,
                    amountGross: productPrice,
                    stripeFee,
                    platformFee,
                    sellerAmount,
                    status: "completed",
                    accessToken,
                    accessUrl,
                    accessCodeHash,
                    createdAt: txTimestamp,
                    gateway: "stripe",
                    deviceInfo: orderDeviceInfo,
                    deviceFingerprint,
                    deviceFingerprintHash,
                    authorizedDevices,
                    authorizedFingerprintHashes,
                });

                // Create purchase
                tx.set(purchaseRef, {
                    email: buyerEmail,
                    emailHash: buyerEmailHash,
                    productId: productRef.id,
                    productTitle,
                    sellerUid,
                    orderId: orderRef.id,
                    stripeSessionId: session.id,
                    accessToken,
                    accessUrl,
                    accessCodeHash,
                    timestamp: txTimestamp,
                    createdAt: txTimestamp,
                    authorizedFingerprintHashes,
                });

                // Create buyer code
                tx.set(db.collection("buyerCodes").doc(accessCodeHash), {
                    email: buyerEmail,
                    emailHash: buyerEmailHash,
                    orderId: orderRef.id,
                    purchaseId: purchaseRef.id,
                    createdAt: txTimestamp,
                    lastUsedAt: null,
                });

                // Update product counters
                tx.set(productRef, {
                    "counters.salesCount": admin.firestore.FieldValue.increment(1),
                    "counters.netRevenue": admin.firestore.FieldValue.increment(sellerAmount),
                    updatedAt: txTimestamp,
                }, { merge: true });

                // Update seller balance
                tx.set(
                    db.collection("users").doc(String(sellerUid)),
                    {
                        balance: admin.firestore.FieldValue.increment(sellerAmount),
                        lastSale: txTimestamp,
                        updatedAt: txTimestamp,
                    },
                    { merge: true }
                );

                // Create transaction record
                tx.set(db.collection("transactions").doc(), {
                    userId: sellerUid,
                    productId: productRef.id,
                    productTitle,
                    orderId: orderRef.id,
                    type: "sale",
                    amount: sellerAmount,
                    grossAmount: productPrice,
                    stripeFee,
                    platformFee,
                    status: "completed",
                    buyerEmail,
                    gateway: "stripe",
                    date: txTimestamp,
                    createdAt: txTimestamp,
                });

                // Mark payment session as completed
                tx.set(paymentSessionRef, {
                    completed: true,
                    orderId: orderRef.id,
                    stripeStatus: "completed",
                    updatedAt: txTimestamp,
                }, { merge: true });
            });

            console.log(`[${FN}] ✅ Transaction committed successfully`);

            // ============ STEP 12: Update Stats ============
            try {
                await statsInc(String(sellerUid), {
                    ordersCount: 1,
                    lifetimeNetIncome: sellerAmount,
                });
                console.log(`[${FN}] ✅ Stats updated`);
            } catch (e) {
                console.error(`[${FN}] ⚠️ Stats update failed:`, e?.message);
            }

            // ============ STEP 13: Send Buyer Email ============
            try {
                await sendEmail("buyer_purchase_confirmed", {
                    to: buyerEmail,
                    subject: ` Purchase Confirmed: ${productTitle}`,
                    title: "Your purchase is confirmed!",
                    preheader: "Your access link and code are ready.",
                    bodyHtml: `
                        <p style="font-size:16px;line-height:24px;margin:16px 0;">
                            Thank you for your purchase! Your content is now ready to access.
                        </p>
                        ${emailButton({
                        href: accessUrl,
                        label: " Access Your Content",
                        tone: "success"
                    })}
                        <div style="background:#f8f9fa;border-radius:8px;padding:20px;margin:24px 0;">
                            <p style="margin:0 0 8px;font-weight:600;color:#212529;">
                                Your Access Code:
                            </p>
                            <p style="margin:0;">
                                <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:20px;font-weight:900;letter-spacing:2px;color:#007bff;">
                                    ${accessCodePlain}
                                </span>
                            </p>
                            <p style="margin:12px 0 0;font-size:13px;color:#6c757d;">
                                Keep this code safe. You'll need it to access your purchase.
                            </p>
                        </div>
<p style="font-size:14px;color:#6c757d;margin:24px 0 0;">
    If you have any issues, please contact 
    <a href="mailto:contact@monetizelt.com" 
       style="color:#007bff;text-decoration:none;font-weight:600;">
       contact@monetizelt.com
    </a>.
</p>
                    `,
                    productId: productRef.id,
                    meta: { orderId: orderRef.id },
                });
                console.log(`[${FN}] ✅ Buyer email sent to ${buyerEmail}`);
            } catch (e) {
                console.error(`[${FN}] ❌ Buyer email failed:`, e?.message);
                await logSystemError(FN, e, { context: "buyer_email", orderId: orderRef.id });
            }

            // ============ STEP 14: Send Seller Email ============
            try {
                const sellerDoc = await db.collection("users").doc(String(sellerUid)).get();
                const sellerEmail = sellerDoc.data()?.email;

                if (sellerEmail && isEmail(sellerEmail)) {
                    const dashUrl = `${base}/dashboard.html`;

                    await sendEmail("seller_sale_notification", {
                        to: sellerEmail,
                        subject: ` New Sale: ${productTitle}`,
                        title: "You made a sale!",
                        preheader: `You earned $${sellerAmount.toFixed(2)} USD`,
                        bodyHtml: `
                            <p style="font-size:16px;line-height:24px;margin:16px 0;">
                                Great news! Your product "<strong>${productTitle}</strong>" was just purchased.
                            </p>
                            <div style="background:#f8f9fa;border-radius:8px;padding:20px;margin:24px 0;">
                                <table style="width:100%;border-collapse:collapse;">
                                    <tr>
                                        <td style="padding:8px 0;color:#6c757d;">Gross amount:</td>
                                        <td style="padding:8px 0;text-align:right;font-weight:600;">
                                            $${productPrice.toFixed(2)}
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding:8px 0;color:#6c757d;">Stripe fee:</td>
                                        <td style="padding:8px 0;text-align:right;color:#dc3545;">
                                            -$${stripeFee.toFixed(2)}
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding:8px 0;color:#6c757d;">Platform fee:</td>
                                        <td style="padding:8px 0;text-align:right;color:#dc3545;">
                                            -$${platformFee.toFixed(2)}
                                        </td>
                                    </tr>
                                    <tr style="border-top:2px solid #dee2e6;">
                                        <td style="padding:12px 0 0;font-weight:600;font-size:16px;">
                                            Your earnings:
                                        </td>
                                        <td style="padding:12px 0 0;text-align:right;font-weight:700;font-size:18px;color:#28a745;">
                                            $${sellerAmount.toFixed(2)}
                                        </td>
                                    </tr>
                                </table>
                            </div>
                            ${emailButton({
                            href: dashUrl,
                            label: "📊 View Dashboard",
                            tone: "primary"
                        })}
                        `,
                        uid: String(sellerUid),
                        productId: productRef.id,
                    });
                    console.log(`[${FN}] ✅ Seller email sent to ${sellerEmail}`);
                } else {
                    console.warn(`[${FN}] ⚠️ Seller email not found or invalid for ${sellerUid}`);
                }
            } catch (e) {
                console.error(`[${FN}] ❌ Seller email failed:`, e?.message);
                await logSystemError(FN, e, { context: "seller_email", orderId: orderRef.id });
            }

            // ============ FINAL RESPONSE ============
            const processingTime = Date.now() - startTime;
            console.log(`[${FN}] ✅ Webhook completed successfully in ${processingTime}ms`);
            console.log(`[${FN}] 📦 Order: ${orderRef.id} | Buyer: ${buyerEmail} | Amount: $${sellerAmount.toFixed(2)}`);

            return res.json({
                received: true,
                success: true,
                orderId: orderRef.id,
                processingTime: `${processingTime}ms`,
            });

        } catch (e) {
            const processingTime = Date.now() - startTime;
            console.error(`[${FN}] ❌ Critical error after ${processingTime}ms:`, {
                message: e?.message,
                code: e?.code,
                stack: e?.stack,
            });

            await logSystemError(FN, e, {
                eventId: req.get("Stripe-Signature"),
                processingTime,
            });

            return res.status(200).json({
                received: true,
                error: true,
                message: e?.message,
                code: e?.code,
            });
        }
    }
);

/* ============================= BUYER LIBRARY + ACCESS (AUTHORIZED DEVICES ONLY) ============================= */

const MAX_AUTH_DEVICES_PER_ORDER = 2;

function uniqPush(arr, v) {
    const a = Array.isArray(arr) ? arr : [];
    if (!v) return a;
    if (!a.includes(v)) a.push(v);
    return a;
}

/**
 * ✅ FIX: Normalisation robuste qui gère tous les cas legacy
 */
function normalizeAuthorized(order) {
    const o = order || {};

    // Toujours retourner des tableaux valides
    let authorizedDevices = Array.isArray(o.authorizedDevices) ? [...o.authorizedDevices] : [];
    let authorizedFingerprintHashes = Array.isArray(o.authorizedFingerprintHashes) ? [...o.authorizedFingerprintHashes] : [];

    // Backfill hashes depuis devices array si manquant
    for (const d of authorizedDevices) {
        const h = String(d?.fingerprintHash || "").trim();
        if (h && !authorizedFingerprintHashes.includes(h)) {
            authorizedFingerprintHashes.push(h);
        }
    }

    // ✅ LEGACY SUPPORT: Si aucun device autorisé mais deviceFingerprintHash existe (achat initial)
    const legacyFpHash = String(o.deviceFingerprintHash || "").trim();
    if (legacyFpHash && authorizedFingerprintHashes.length === 0) {
        // Autoriser automatiquement l'appareil d'achat original
        authorizedFingerprintHashes.push(legacyFpHash);

        const legacyDevice = {
            fingerprintHash: legacyFpHash,
            deviceInfo: o.deviceInfo || { browser: "Unknown", os: "Unknown", device: "Unknown", userAgent: "" },
            firstAccessAt: null,
            addedAt: o.createdAt || null,
            source: "legacy_purchase_device"
        };
        authorizedDevices.push(legacyDevice);
    }

    return { authorizedDevices, authorizedFingerprintHashes };
}

function isFpAuthorized(order, fpHash) {
    if (!fpHash) return false;
    const { authorizedFingerprintHashes } = normalizeAuthorized(order);
    return authorizedFingerprintHashes.includes(fpHash);
}

/**
 * ✅ FIX: Migration qui persiste SEULEMENT si nécessaire
 */
async function migrateLegacyOrderAuthIfNeeded(orderDocRef, order) {
    const o = order || {};

    // Si déjà migré, retourner tel quel
    const hasArrays = Array.isArray(o.authorizedDevices) || Array.isArray(o.authorizedFingerprintHashes);
    if (hasArrays) {
        return { ...o, ...normalizeAuthorized(o) };
    }

    // Si pas de legacy fingerprint, initialiser avec tableaux vides
    const legacyFpHash = String(o.deviceFingerprintHash || "").trim();
    if (!legacyFpHash) {
        const empty = { authorizedDevices: [], authorizedFingerprintHashes: [] };

        try {
            await orderDocRef.set(empty, { merge: true });
            await db.collection("purchases").doc(String(orderDocRef.id))
                .set({ authorizedFingerprintHashes: [] }, { merge: true });
        } catch (e) {
            console.error("[migrateLegacyOrderAuthIfNeeded] Init failed:", e?.message);
        }

        return { ...o, ...empty };
    }

    // Migration nécessaire
    const legacyDeviceInfo = o.deviceInfo || {
        browser: "Unknown",
        os: "Unknown",
        device: "Unknown",
        userAgent: ""
    };

    const authorizedDevices = [
        {
            fingerprintHash: legacyFpHash,
            deviceInfo: legacyDeviceInfo,
            firstAccessAt: null,
            addedAt: o.createdAt || nowServerTimestamp(),
            source: "legacy_purchase_device",
        },
    ];
    const authorizedFingerprintHashes = [legacyFpHash];

    // Persister la migration
    try {
        await orderDocRef.set(
            {
                authorizedDevices,
                authorizedFingerprintHashes,
                updatedAt: nowServerTimestamp(),
            },
            { merge: true }
        );

        await db.collection("purchases").doc(String(orderDocRef.id))
            .set({
                authorizedFingerprintHashes,
                updatedAt: nowServerTimestamp()
            }, { merge: true });

    } catch (e) {
        console.error("[migrateLegacyOrderAuthIfNeeded] Write failed:", e?.message);
        await logSystemError("migrateLegacyOrderAuthIfNeeded", e, {
            orderId: orderDocRef.id,
            legacyFpHash: legacyFpHash.slice(0, 8) + "..."
        });
    }

    return { ...o, authorizedDevices, authorizedFingerprintHashes };
}

/* ============================= ACCESS CONTENT (AUTHORIZED DEVICES ONLY) ============================= */

exports.accessContent = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "accessContent";
        try {
            const token = String(req2.query.token || "").trim();
            const userAgent = String(req2.get("user-agent") || req2.query.userAgent || "");

            if (!token) {
                throw createHttpError(400, "invalid_argument", "Missing access token.");
            }

            const deviceFingerprint = getDeviceFingerprintFromReq(req2);
            const fpHash = deviceFingerprint ? sha256Hex(deviceFingerprint) : null;

            if (!fpHash) {
                throw createHttpError(400, "invalid_argument", "Unable to identify device. Please enable cookies and JavaScript.");
            }

            // Chercher l'ordre par token
            const ordersSnap = await db.collection("orders")
                .where("accessToken", "==", token)
                .limit(1)
                .get();

            if (ordersSnap.empty) {
                throw createHttpError(404, "not_found", "Invalid access token.");
            }

            const orderDoc = ordersSnap.docs[0];
            let order = orderDoc.data() || {};

            // Migration legacy
            order = await migrateLegacyOrderAuthIfNeeded(orderDoc.ref, order);

            const deviceInfo = extractDeviceInfo(userAgent);
            const alreadyAuthorized = isFpAuthorized(order, fpHash);

            if (!alreadyAuthorized) {
                // Appareil non autorisé

                if (req2.method !== "POST") {
                    // GET sans autorisation => demander vérification
                    throw createHttpError(
                        401,
                        "device_verification_required",
                        "This device is not authorized. Please verify using email + access code.",
                        { require: { email: true, code: true }, method: "POST" }
                    );
                }

                // POST => vérifier email + code et autoriser appareil
                const { email = "", code = "" } = req2.body || {};
                const emailNorm = normalizeEmail(email);

                if (!emailNorm || !isEmail(emailNorm)) {
                    throw createHttpError(400, "invalid_argument", "Valid email is required.");
                }
                if (!code || String(code).trim().length < 6) {
                    throw createHttpError(400, "invalid_argument", "Access code is required (min 6 chars).");
                }

                const emailHash = sha256Hex(emailNorm);
                const orderEmailHash = String(order.buyerEmailHash || sha256Hex(normalizeEmail(order.buyerEmail || "")));

                if (emailHash !== orderEmailHash) {
                    throw createHttpError(404, "not_found", "Invalid email or access code.");
                }

                // Vérifier le code
                const codeHash = sha256Hex(normalizeAccessCode(code));
                const codeSnap = await db.collection("buyerCodes").doc(codeHash).get();

                if (!codeSnap.exists) {
                    throw createHttpError(404, "not_found", "Invalid email or access code.");
                }

                const c = codeSnap.data() || {};
                if (String(c.emailHash || "") !== emailHash) {
                    throw createHttpError(404, "not_found", "Invalid email or access code.");
                }
                if (String(c.orderId || "") !== String(orderDoc.id)) {
                    throw createHttpError(404, "not_found", "Invalid email or access code.");
                }

                // Autoriser ce nouvel appareil
                try {
                    const r = await authorizeDeviceOnOrder({
                        orderDocRef: orderDoc.ref,
                        order,
                        fpHash,
                        deviceInfo,
                        reason: "access_content_email_code",
                    });

                    await db.collection("accessAttempts").add({
                        orderId: orderDoc.id,
                        reason: r.added ? "new_device_authorized" : "device_already_authorized",
                        deviceNumber: r.count,
                        deviceFingerprintHash: fpHash,
                        deviceInfo,
                        createdAt: nowServerTimestamp(),
                        allowed: true,
                    });

                    // Rafraîchir ordre
                    const fresh = await orderDoc.ref.get();
                    order = fresh.data() || order;

                } catch (e) {
                    // Max devices atteint
                    const { authorizedFingerprintHashes } = normalizeAuthorized(order);

                    await db.collection("accessAttempts").add({
                        orderId: orderDoc.id,
                        reason: "max_devices_reached",
                        attemptDeviceFingerprintHash: fpHash,
                        attemptDeviceInfo: deviceInfo,
                        authorizedDevicesCount: authorizedFingerprintHashes.length,
                        createdAt: nowServerTimestamp(),
                        allowed: false,
                    });

                    throw e;
                }

                // Marquer usage du code
                await codeSnap.ref.set(
                    {
                        lastUsedAt: nowServerTimestamp(),
                        lastUsedUA: deviceInfo
                    },
                    { merge: true }
                ).catch(() => null);
            }

            // Charger produit
            const loaded = await loadProductById(String(order.productId));
            if (!loaded) {
                throw createHttpError(404, "not_found", "Product not found.");
            }

            const product = loaded.data || {};
            const apiBase = `https://${req2.get("host")}`;

            // Construire liste de fichiers
            const files = [];
            for (const a of Array.isArray(product.assets) ? product.assets : []) {
                if (!a.filePath) continue;
                files.push({
                    kind: a.kind,
                    index: a.index,
                    originalName: a.originalName,
                    contentType: a.contentType,
                    sizeBytes: a.sizeBytes || null,
                    downloadUrl: `${apiBase}/downloadProductAsset?token=${encodeURIComponent(token)}&productId=${encodeURIComponent(order.productId)}&index=${encodeURIComponent(a.index)}`,
                });
            }

            const coverUrl = product.coverPath
                ? `${apiBase}/getProductCover?productId=${encodeURIComponent(order.productId)}`
                : null;

            const { authorizedFingerprintHashes } = normalizeAuthorized(order);

            // Logger accès
            await db.collection("accessLogs").add({
                orderId: orderDoc.id,
                productId: order.productId,
                buyerEmail: order.buyerEmail,
                deviceFingerprintHash: fpHash,
                deviceInfo,
                authorizedDevicesCount: authorizedFingerprintHashes.length,
                createdAt: nowServerTimestamp(),
            });

            // Marquer ordre comme "processed" si première fois
            let didProcess = false;
            let sellerUid = null;

            if (order.status === "completed") {
                await db.runTransaction(async (tx) => {
                    const fresh = await tx.get(orderDoc.ref);
                    const o = fresh.data();
                    if (o && o.status === "completed") {
                        tx.update(orderDoc.ref, {
                            status: "processed",
                            processedAt: nowServerTimestamp()
                        });
                        didProcess = true;
                        sellerUid = String(o.sellerUid);
                    }
                });
            }

            if (didProcess && sellerUid) {
                await statsInc(sellerUid, { processedCount: 1 });
            }

            // Réponse succès
            res2.status(200).json({
                success: true,
                product: {
                    title: product.title || "",
                    description: product.description || "",
                    category: product.category || "",
                    subtype: product.subtype || "",
                    coverUrl,
                    files,
                },
                devicesInfo: {
                    current: authorizedFingerprintHashes.length,
                    maximum: MAX_AUTH_DEVICES_PER_ORDER,
                },
            });

        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, {
                token: req2.query.token ? req2.query.token.slice(0, 8) + "..." : null,
                method: req2.method,
                hasFingerprint: !!getDeviceFingerprintFromReq(req2)
            });

            res2.status(e.httpStatus || 500).json({
                success: false,
                error: e.message || "Internal error",
                code: e.code || "internal",
                meta: e.meta || null,
            });
        }
    });
});

/* ============================= DOWNLOAD PRODUCT ASSET (AUTHORIZED DEVICES ONLY) ============================= */

exports.downloadProductAsset = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "downloadProductAsset";
        try {
            const token = String(req2.query.token || "").trim();
            const productId = String(req2.query.productId || "").trim();
            const index = Number(req2.query.index || 0);
            const userAgent = String(req2.get("user-agent") || req2.query.userAgent || "");

            if (!token) throw createHttpError(400, "invalid_argument", "Missing token.");
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");
            if (!Number.isFinite(index) || index < 1) {
                throw createHttpError(400, "invalid_argument", "Invalid index.");
            }

            const deviceFingerprint = getDeviceFingerprintFromReq(req2);
            const fpHash = deviceFingerprint ? sha256Hex(deviceFingerprint) : null;

            if (!fpHash) {
                throw createHttpError(400, "invalid_argument", "Unable to identify device.");
            }

            // Vérifier token
            const ordersSnap = await db.collection("orders")
                .where("accessToken", "==", token)
                .limit(1)
                .get();

            if (ordersSnap.empty) {
                throw createHttpError(404, "not_found", "Invalid access token.");
            }

            const orderDoc = ordersSnap.docs[0];
            let order = orderDoc.data() || {};

            if (String(order.productId) !== productId) {
                throw createHttpError(403, "permission_denied", "Token does not match product.");
            }

            // Migration legacy
            order = await migrateLegacyOrderAuthIfNeeded(orderDoc.ref, order);

            // Vérifier autorisation
            const allowed = isFpAuthorized(order, fpHash);

            if (!allowed) {
                await db.collection("accessAttempts").add({
                    orderId: orderDoc.id,
                    reason: "download_denied_device_not_authorized",
                    attemptDeviceFingerprintHash: fpHash,
                    attemptDeviceInfo: extractDeviceInfo(userAgent),
                    createdAt: nowServerTimestamp(),
                    allowed: false,
                });

                throw createHttpError(
                    403,
                    "permission_denied",
                    "This device is not authorized for this order."
                );
            }

            // Charger produit
            const loaded = await loadProductById(productId);
            if (!loaded) {
                throw createHttpError(404, "not_found", "Product not found.");
            }

            const product = loaded.data || {};

            const asset = (Array.isArray(product.assets) ? product.assets : [])
                .find((a) => Number(a.index) === index);

            if (!asset?.filePath) {
                throw createHttpError(404, "not_found", "File not found.");
            }

            const file = bucket.file(String(asset.filePath));
            const [meta] = await file.getMetadata();
            const size = Number(meta?.size || 0);
            const contentType = String(asset.contentType || meta?.contentType || "application/octet-stream");
            const filename = String(asset.originalName || `file_${index}`);

            const inlineOk =
                contentType.startsWith("video/") ||
                contentType.startsWith("audio/") ||
                contentType.startsWith("image/") ||
                contentType === "application/pdf";

            res2.setHeader("Content-Type", contentType);
            res2.setHeader("Cache-Control", "private, max-age=0, no-store");
            res2.setHeader("X-Content-Type-Options", "nosniff");
            res2.setHeader("Accept-Ranges", "bytes");
            res2.setHeader(
                "Content-Disposition",
                `${inlineOk ? "inline" : "attachment"}; filename="${filename.replace(/"/g, "")}"`
            );

            // Support Range requests
            const range = req2.headers.range;
            if (range && /^bytes=\d*-\d*$/.test(range)) {
                const [startStr, endStr] = range.replace("bytes=", "").split("-");
                const start = startStr ? parseInt(startStr, 10) : 0;
                const end = endStr ? parseInt(endStr, 10) : Math.max(0, size - 1);

                if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start < 0 || end >= size) {
                    res2.status(416).setHeader("Content-Range", `bytes */${size}`).end();
                    return;
                }

                res2.status(206);
                res2.setHeader("Content-Range", `bytes ${start}-${end}/${size}`);
                res2.setHeader("Content-Length", String(end - start + 1));

                file.createReadStream({ start, end })
                    .on("error", (e) => {
                        console.error(FN, "range stream error:", e?.message);
                        if (!res2.headersSent) res2.status(500).end();
                        else res2.end();
                    })
                    .pipe(res2);
                return;
            }

            // Full download
            if (Number.isFinite(size) && size > 0) {
                res2.setHeader("Content-Length", String(size));
            }

            file.createReadStream()
                .on("error", (e) => {
                    console.error(FN, "stream error:", e?.message);
                    if (!res2.headersSent) res2.status(500).end();
                    else res2.end();
                })
                .pipe(res2);

        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, { query: req2.query });
            res2.status(e.httpStatus || 500).json({
                success: false,
                error: e.message || "Internal error",
                code: e.code || "internal",
                meta: e.meta || null,
            });
        }
    });
});

/* ============================= REPORTING (AUTO-TAKEDOWN + 7-DAY FREEZE) ============================= */

/**
 * ✅ Only these reasons count toward auto-takedown:
 * Violence, Copyright, Adult, Scam
 */
const REPORT_REASON = {
    VIOLENCE: "violence",
    COPYRIGHT: "copyright",
    ADULT: "adult",
    SCAM: "scam",
};

const REPORT_REASON_LABEL = {
    [REPORT_REASON.VIOLENCE]: "Violence",
    [REPORT_REASON.COPYRIGHT]: "Copyright",
    [REPORT_REASON.ADULT]: "Adult content",
    [REPORT_REASON.SCAM]: "Scam / Fraud",
};

function normalizeReportReason(input) {
    const s = String(input || "").trim().toLowerCase();
    if (!s) return null;

    // Accept small variants but map to canonical set
    if (s === "violence" || s === "violent") return REPORT_REASON.VIOLENCE;
    if (s === "copyright" || s === "dmca" || s === "piracy") return REPORT_REASON.COPYRIGHT;
    if (s === "adult" || s === "nsfw" || s === "porn" || s === "pornography" || s === "sexual") return REPORT_REASON.ADULT;
    if (s === "scam" || s === "fraud" || s === "spam") return REPORT_REASON.SCAM;

    return null;
}

function freezeUntilDate(days = 7) {
    return new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000);
}

async function freezeSellerAccountForReports({ sellerUid, productId, productTitle, reasonKey }) {
    const userRef = db.collection("users").doc(String(sellerUid));
    const until = freezeUntilDate(7);
    const untilTs = admin.firestore.Timestamp.fromDate(until);

    await userRef.set(
        {
            accountStatus: "frozen",
            freezeUntil: untilTs,
            freeze: {
                type: "reports_auto_enforcement",
                productId: String(productId || ""),
                productTitle: String(productTitle || ""),
                reason: String(reasonKey || ""),
                frozenAt: nowServerTimestamp(),
                until: untilTs,
            },
            updatedAt: nowServerTimestamp(),
        },
        { merge: true }
    );

    // Best-effort: disable Auth to block sign-in refresh
    try {
        await admin.auth().updateUser(String(sellerUid), { disabled: true });
    } catch (e) {
        console.error("freeze auth disable failed:", e?.message);
    }

    return { until };
}

exports.reportProduct = onRequest({ invoker: "public", secrets: [sendgridApiKey, appBaseUrl] }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "reportProduct";
        try {
            const { productId, reason, reporterUid = "" } = req2.body || {};
            if (!productId) throw createHttpError(400, "invalid_argument", "Missing productId.");
            if (!reason || String(reason).length < 3) throw createHttpError(400, "invalid_argument", "Missing reason.");

            const reasonKey = normalizeReportReason(reason);
            if (!reasonKey) {
                throw createHttpError(400, "invalid_argument", "Invalid reason. Allowed: Violence, Copyright, Adult, Scam.");
            }

            const productRef = db.collection(PRODUCT_COLLECTION_ACTIVE).doc(String(productId));
            const productSnap = await productRef.get();
            if (!productSnap.exists) throw createHttpError(404, "not_found", "Product not found.");
            const product = productSnap.data();

            const ip = req2.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req2.ip || "";
            const reporterKey = sha256Hex(reporterUid || ip || "anonymous");

            // ✅ Dedupe per product + reason + reporter
            const reportId = `${productRef.id}_${reasonKey}_${reporterKey}`;
            const reportRef = db.collection("productReports").doc(reportId);

            const created = await db.runTransaction(async (tx) => {
                const existing = await tx.get(reportRef);
                if (existing.exists) return false;

                tx.set(reportRef, {
                    productId: productRef.id,
                    sellerUid: product.uid,
                    reason: reasonKey,
                    reporterKey,
                    createdAt: nowServerTimestamp(),
                });

                tx.set(
                    productRef,
                    {
                        reportAgg: {
                            [reasonKey]: {
                                uniqueCount: admin.firestore.FieldValue.increment(1),
                                lastUpdated: nowServerTimestamp(),
                            },
                        },
                        updatedAt: nowServerTimestamp(),
                    },
                    { merge: true }
                );

                return true;
            });

            // Load latest count
            const fresh = await productRef.get();
            const agg = Number(fresh.data()?.reportAgg?.[reasonKey]?.uniqueCount || 0);

            // ✅ Enforce once when threshold reached (>=3) for same allowed reason
            let enforced = false;
            let freezeInfo = null;

            if (created && agg >= 3) {
                const sellerUid = String(fresh.data()?.uid || product.uid || "");
                const productTitle = String(fresh.data()?.title || product.title || "Untitled");

                // Transaction ensures we don't enforce multiple times
                const { didEnforce } = await db.runTransaction(async (tx) => {
                    const pSnap2 = await tx.get(productRef);
                    if (!pSnap2.exists) return { didEnforce: false };
                    const p2 = pSnap2.data() || {};

                    const already = String(p2?.enforcement?.autoAction || "") === "reports_auto_takedown"
                        && String(p2?.enforcement?.reasonKey || "") === String(reasonKey);

                    if (already) return { didEnforce: false };
                    if (String(p2.status || "") !== PRODUCT_STATUS.ACTIVE) return { didEnforce: false };

                    tx.set(
                        productRef,
                        {
                            status: PRODUCT_STATUS.TAKEN_DOWN,
                            enforcement: {
                                autoAction: "reports_auto_takedown",
                                status: "taken_down_by_reports",
                                reasonKey,
                                reasonLabel: REPORT_REASON_LABEL[reasonKey] || reasonKey,
                                threshold: 3,
                                decidedAt: nowServerTimestamp(),
                                note: `Auto takedown: '${reasonKey}' reported by 3 unique reporters.`,
                            },
                            updatedAt: nowServerTimestamp(),
                        },
                        { merge: true }
                    );

                    return { didEnforce: true };
                });

                if (didEnforce) {
                    enforced = true;

                    // Freeze seller for 7 days
                    freezeInfo = await freezeSellerAccountForReports({
                        sellerUid,
                        productId: productRef.id,
                        productTitle,
                        reasonKey,
                    });

                    // Email seller: improved (English) + buttons only
                    try {
                        const sellerDoc = await db.collection("users").doc(sellerUid).get();
                        const sellerEmail = sellerDoc.data()?.email;

                        if (sellerEmail && isEmail(sellerEmail)) {
                            const base = getPublicSiteOrigin();
                            const dashboardUrl = `${base}/dashboard.html`;

                            const reasonLabel = REPORT_REASON_LABEL[reasonKey] || reasonKey;
                            const untilStr = freezeInfo?.until ? freezeInfo.until.toUTCString() : "in 7 days";

                            await sendEmail("product_takedown_reports", {
                                to: sellerEmail,
                                subject: "Product removed & account temporarily frozen (7 days)",
                                title: "Account temporarily frozen",
                                preheader: `Your product was removed due to repeated reports (${reasonLabel}).`,
                                bodyHtml: `
                                  <p>
                                    Your product <strong>${productTitle}</strong> has been removed from Monetizelt after receiving
                                    <strong> independent report</strong> for the same subject.
                                  </p>

                                  ${kvTable([
                                    ["Reported category", `<span style="font-weight:900;color:#dc3545;">${reasonLabel}</span>`],
                                    ["Product status", `<span style="font-weight:800;">Removed from sale</span>`],
                                    ["Account status", `<span style="font-weight:900;color:#dc3545;">Frozen</span>`],
                                    ["Freeze duration", `<span style="font-weight:800;">7 days</span>`],
                                    ["Expected reactivation", `<span style="font-weight:800;">${untilStr}</span>`],
                                ])}

                                  <p style="margin-top:12px;">
                                    During this time, your account is temporarily restricted while we make a final decision.
                                    If the report is confirmed, your account may be permanently banned.
                                  </p>

                                  ${emailButton({ href: dashboardUrl, label: "Open dashboard", tone: "primary" })}

                                  <p style="color:#6c757d;font-size:12px;margin-top:10px;">
                                    If you believe this is a mistake, reply to this email with any context or proof. We will review it.
                                    If everything is fine, access will be restored automatically after 7 days.
                                  </p>
                                `,
                                uid: sellerUid,
                                productId: productRef.id,
                            });
                        }
                    } catch (e) {
                        console.error(`[${FN}] product_takedown_reports email failed:`, e?.message);
                    }
                }
            }

            res2.status(200).json({
                success: true,
                created,
                reason: reasonKey,
                reasonLabel: REPORT_REASON_LABEL[reasonKey] || reasonKey,
                uniqueCountForReason: agg,
                enforced,
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= TRANSACTIONS ============================= */

exports.getTransactionHistory = onRequest({ invoker: "public" }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "getTransactionHistory";
        try {
            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const snap = await db.collection("transactions").where("userId", "==", decoded.uid).orderBy("createdAt", "desc").limit(50).get();

            const txs = snap.docs.map((d) => {
                const t = d.data();
                return {
                    id: d.id,
                    ...t,
                    createdAt: t.createdAt?.toDate?.() || null,
                    date: t.date?.toDate?.() || null,
                };
            });

            res2.status(200).json({ success: true, transactions: txs });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= USER ACCOUNT DELETE ============================= */

exports.deleteUserAccount = onRequest({ invoker: "public", secrets: [sendgridApiKey, appBaseUrl] }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "deleteUserAccount";
        try {
            const decoded = await requireAuth(req2);

            const userRef = db.collection("users").doc(decoded.uid);
            const userSnap = await userRef.get();
            if (!userSnap.exists) throw createHttpError(404, "not_found", "User not found.");

            const productsSnap = await db.collection(PRODUCT_COLLECTION_ACTIVE).where("uid", "==", decoded.uid).get();

            const batch = db.batch();
            productsSnap.docs.forEach((pdoc) => {
                // Best-effort: mark as archived (admin can migrate)
                batch.set(pdoc.ref, { status: PRODUCT_STATUS.ARCHIVED, updatedAt: nowServerTimestamp() }, { merge: true });
            });

            batch.set(db.collection("deletedAccounts").doc(), {
                uid: decoded.uid,
                email: userSnap.data()?.email || null,
                displayName: userSnap.data()?.displayName || null,
                deletedAt: nowServerTimestamp(),
                productsArchived: productsSnap.size,
            });

            batch.delete(db.collection("userStats").doc(decoded.uid));
            batch.delete(userRef);

            await batch.commit();

            try {
                await admin.auth().updateUser(decoded.uid, { disabled: true });
            } catch (e) {
                console.error("Failed disabling auth:", e?.message);
            }

            const to = userSnap.data()?.email;
            if (to && isEmail(to)) {
                await sendEmail("account_deleted", {
                    to,
                    subject: "Your Monetizelt account was deleted",
                    title: "Account deleted",
                    preheader: "Your account deletion was processed.",
                    bodyHtml: `
                      <p>Your account deletion was processed.</p>
                      <p style="color:#6c757d;font-size:12px;">
                        If you did not request this, please contact support immediately by replying to this email.
                      </p>
                    `,
                    uid: decoded.uid,
                });
            }

            res2.status(200).json({ success: true });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});

/* ============================= SCHEDULED PAYOUTS (THU PREP + FRI PAY) ============================= */

exports.prepareWeeklyPayoutCandidates = onSchedule(
    {
        schedule: "10 0 * * 4",
        timeZone: "UTC",
        memory: "256MiB",
        maxInstances: 1,
    },
    async () => {
        const FN = "prepareWeeklyPayoutCandidates";
        try {
            await prepareWeeklyPayoutCandidates({ trigger: FN });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
        }
    }
);

exports.processWeeklyFridayPayouts = onSchedule(
    {
        schedule: "5 12 * * 5",
        timeZone: "UTC",
        memory: "256MiB",
        maxInstances: 1,
        secrets: [paypalClientId, paypalClientSecret, sendgridApiKey, appBaseUrl, adminAlertEmail],
    },
    async () => {
        const FN = "processWeeklyFridayPayouts";
        try {
            await processWeeklyFridayPayouts({ trigger: FN });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
        }
    }
);

exports.reconcileRecentPayoutBatches = onSchedule(
    {
        schedule: "every 30 minutes",
        timeZone: "UTC",
        memory: "256MiB",
        maxInstances: 1,
        secrets: [paypalClientId, paypalClientSecret, sendgridApiKey, appBaseUrl, adminAlertEmail],
    },
    async () => {
        const FN = "reconcileRecentPayoutBatches";
        try {
            const snap = await db.collection("payoutBatches").where("status", "==", "sent").limit(20).get();
            const base = getPublicSiteOrigin();
            const dashboardUrl = `${base}/dashboard.html`;
            const settingsUrl = `${base}/settings.html`;
            const payAddressUrl = `${base}/pay-address.html`;

            for (const d of snap.docs) {
                const b = d.data() || {};
                if (!b.paypalBatchId) continue;
                try {
                    await reconcilePaypalBatch({
                        paypalBatchId: b.paypalBatchId,
                        batchDocId: d.id,
                        fridayKey: b.fridayKey,
                        trigger: FN,
                        dashboardUrl,
                        settingsUrl,
                        payAddressUrl,
                    });
                } catch (e) {
                    console.error(`[${FN}] reconcile failed batch=${d.id}:`, e?.message);
                    await d.ref.set({ reconcileError: e?.message || "reconcile failed", updatedAt: nowServerTimestamp() }, { merge: true });
                    await logSystemError(FN, e, { batchDocId: d.id, paypalBatchId: b.paypalBatchId });
                }

                await new Promise((r) => setTimeout(r, 700));
            }
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
        }
    }
);

/* ============================= PUB/SUB MANUAL TRIGGER ============================= */

exports.processPayoutsFromPubSub = onMessagePublished(
    {
        topic: "weekly-payouts-topic",
        region: "us-central1",
        secrets: [paypalClientId, paypalClientSecret, sendgridApiKey, appBaseUrl, adminAlertEmail],
        memory: "256MiB",
        maxInstances: 1,
    },
    async (event) => {
        const msg = event?.data?.message;
        const messageId = msg?.messageId || null;

        let payload = null;
        try {
            const raw = msg?.data ? Buffer.from(msg.data, "base64").toString("utf8") : "";
            payload = raw || null;
        } catch {
            payload = null;
        }

        console.log(`[processPayoutsFromPubSub] messageId=${messageId} payload=${payload}`);

        try {
            await processWeeklyFridayPayouts({ trigger: "pubsub:weekly-payouts-topic", messageId });
        } catch (e) {
            console.error("processPayoutsFromPubSub error:", e);
            await logSystemError("processPayoutsFromPubSub", e, { messageId, payload });
        }
    }
);

/* ============================= CLEANUP: EXPIRED UPLOAD SESSIONS ============================= */

exports.cleanupExpiredUploadSessions = onSchedule(
    {
        schedule: "every 6 hours",
        timeZone: "UTC",
        memory: "256MiB",
        maxInstances: 1,
    },
    async () => {
        const FN = "cleanupExpiredUploadSessions";
        const now = new Date();
        console.log(`[${FN}] Running at ${now.toISOString()}`);

        try {
            const snap = await db.collection("uploadSessions").get();
            let cleaned = 0;

            for (const doc of snap.docs) {
                const s = doc.data();
                const exp = s.expiresAt?.toDate ? s.expiresAt.toDate() : s.expiresAt ? new Date(s.expiresAt) : null;
                if (!exp || exp.getTime() > Date.now()) continue;

                const uid = s.uid;
                const sessionId = doc.id;

                const prefix = `${TMP_UPLOAD_PREFIX}/${uid}/${sessionId}/`;
                await deleteByPrefix(prefix).catch(() => null);
                await doc.ref.delete().catch(() => null);

                cleaned++;
            }

            console.log(`[${FN}] cleaned=${cleaned}`);
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
        }
    }
);

/* ============================= CLEANUP: UNFREEZE EXPIRED ACCOUNTS ============================= */

exports.unfreezeExpiredAccounts = onSchedule(
    {
        schedule: "every 60 minutes",
        timeZone: "UTC",
        memory: "256MiB",
        maxInstances: 1,
    },
    async () => {
        const FN = "unfreezeExpiredAccounts";
        const now = new Date();
        const nowTs = admin.firestore.Timestamp.fromDate(now);

        console.log(`[${FN}] Running at ${now.toISOString()}`);

        try {
            const snap = await db
                .collection("users")
                .where("accountStatus", "==", "frozen")
                .where("freezeUntil", "<=", nowTs)
                .limit(200)
                .get();

            if (snap.empty) return;

            const bw = db.bulkWriter();

            for (const doc of snap.docs) {
                const uid = doc.id;

                bw.set(
                    doc.ref,
                    {
                        accountStatus: "active",
                        freezeUntil: admin.firestore.FieldValue.delete(),
                        freeze: admin.firestore.FieldValue.delete(),
                        updatedAt: nowServerTimestamp(),
                        unfrozenAt: nowServerTimestamp(),
                    },
                    { merge: true }
                );

                // Best-effort: re-enable Auth
                try {
                    await admin.auth().updateUser(uid, { disabled: false });
                } catch (e) {
                    console.error(`[${FN}] auth enable failed uid=${uid}:`, e?.message);
                }
            }

            await bw.close();

            console.log(`[${FN}] unfrozen=${snap.size}`);
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e);
        }
    }
);

// ============================= SELLER QUARTERLY REPORT (EMAIL) =============================

function quarterRangeUtc(year, quarter) {
    const y = Number(year);
    const q = Number(quarter);

    if (!Number.isFinite(y) || y < 2000 || y > 2100) {
        throw createHttpError(400, "invalid_argument", "Invalid year.");
    }
    if (![1, 2, 3, 4].includes(q)) {
        throw createHttpError(400, "invalid_argument", "Invalid quarter. Use 1, 2, 3, or 4.");
    }

    const startMonth = (q - 1) * 3; // 0,3,6,9
    const endMonth = startMonth + 3;

    const start = new Date(Date.UTC(y, startMonth, 1, 0, 0, 0, 0));
    const end = new Date(Date.UTC(y, endMonth, 1, 0, 0, 0, 0));

    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const label = `Q${q} ${y} (${monthNames[startMonth]}–${monthNames[endMonth - 1]})`;

    return { year: y, quarter: q, start, end, label };
}

function toTs(d) {
    return admin.firestore.Timestamp.fromDate(d);
}

function money2(n) {
    const x = Number(n || 0);
    if (!Number.isFinite(x)) return "0.00";
    return x.toFixed(2);
}

function monthKeyUtc(date) {
    const d = date instanceof Date ? date : new Date(date);
    const y = d.getUTCFullYear();
    const m = String(d.getUTCMonth() + 1).padStart(2, "0");
    return `${y}-${m}`;
}

function monthLabelFromKey(key) {
    const [y, m] = String(key || "").split("-");
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const mi = Math.max(1, Math.min(12, Number(m || 1))) - 1;
    return `${monthNames[mi]} ${y}`;
}

function htmlMetricsTable(rows) {
    const border = "#007bff";
    const headBg = "#f2f8ff";
    const text = "#212529";
    const muted = "#6c757d";

    const thead = `
      <thead>
        <tr>
          ${rows.headers.map(h => `
            <th style="padding:9px 8px;border:1px solid ${border};background:${headBg};color:${muted};font-size:12px;text-align:left;font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;">
              ${h}
            </th>
          `).join("")}
        </tr>
      </thead>
    `;

    const tbody = `
      <tbody>
        ${rows.items.map(item => `
          <tr>
            ${item.map((cell, idx) => `
              <td style="padding:9px 8px;border:1px solid ${border};color:${idx === 0 ? muted : text};font-size:12.5px;font-weight:${idx === 0 ? 700 : 800};font-family:Poppins,Segoe UI,Tahoma,Geneva,Verdana,sans-serif;white-space:${idx === 0 ? "nowrap" : "normal"};">
                ${cell}
              </td>
            `).join("")}
          </tr>
        `).join("")}
      </tbody>
    `;

    return `
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%"
        style="border-collapse:collapse;border:2px solid ${border};border-radius:12px;overflow:hidden;">
        ${thead}
        ${tbody}
      </table>
    `;
}

exports.sendQuarterlyReport = onRequest({ invoker: "public", secrets: [sendgridApiKey, appBaseUrl] }, async (req, res) => {
    corsMiddleware(req, res, async (req2, res2) => {
        const FN = "sendQuarterlyReport";
        try {
            if (req2.method !== "POST") throw createHttpError(405, "method_not_allowed", "POST required.");

            const decoded = await requireAuth(req2);
            await ensureUserNotBanned(decoded.uid);

            const { quarter, year } = req2.body || {};
            const y = year || new Date().getUTCFullYear();
            const { start, end, label } = quarterRangeUtc(y, quarter);

            // Seller email
            const userSnap = await db.collection("users").doc(decoded.uid).get();
            const to = userSnap.data()?.email || decoded.email || null;
            if (!to || !isEmail(to)) {
                throw createHttpError(400, "failed_precondition", "Your account email is missing or invalid.");
            }

            const startTs = toTs(start);
            const endTs = toTs(end);

            // -------------------- SALES / EARNINGS (from transactions) --------------------
            // We use the existing index pattern: userId + createdAt ordering.
            // Then filter type === "sale" in code to avoid creating a new composite index.
            const txSnap = await db
                .collection("transactions")
                .where("userId", "==", decoded.uid)
                .orderBy("createdAt", "asc")
                .startAt(startTs)
                .endBefore(endTs)
                .limit(5000)
                .get();

            let salesCount = 0;
            let earningsNet = 0;
            let gross = 0;
            let stripeFees = 0;
            let platformFees = 0;

            const monthAgg = new Map(); // key -> { sales, earnings, gross, stripe, platform }
            const orderIds = new Set();

            for (const d of txSnap.docs) {
                const t = d.data() || {};
                if (String(t.type || "") !== "sale") continue;

                salesCount += 1;

                const a = Number(t.amount || 0); // sellerAmount
                const g = Number(t.grossAmount || 0);
                const sf = Number(t.stripeFee || 0);
                const pf = Number(t.platformFee || 0);

                earningsNet += Number.isFinite(a) ? a : 0;
                gross += Number.isFinite(g) ? g : 0;
                stripeFees += Number.isFinite(sf) ? sf : 0;
                platformFees += Number.isFinite(pf) ? pf : 0;

                const ca = t.createdAt?.toDate?.() || null;
                const mk = ca ? monthKeyUtc(ca) : null;

                if (mk) {
                    const cur = monthAgg.get(mk) || { sales: 0, earnings: 0, gross: 0, stripe: 0, platform: 0, views: null, processed: 0 };
                    cur.sales += 1;
                    cur.earnings += Number.isFinite(a) ? a : 0;
                    cur.gross += Number.isFinite(g) ? g : 0;
                    cur.stripe += Number.isFinite(sf) ? sf : 0;
                    cur.platform += Number.isFinite(pf) ? pf : 0;
                    monthAgg.set(mk, cur);
                }

                if (t.orderId) orderIds.add(String(t.orderId));
            }

            const ordersCount = salesCount; // completed purchases

            // -------------------- PROCESSED (best-effort via orders by ID) --------------------
            // Avoid new indexes: fetch orders by doc ID from the sale transactions.
            let processedCount = 0;

            if (orderIds.size > 0) {
                const ids = Array.from(orderIds);
                for (let i = 0; i < ids.length; i += 400) {
                    const chunk = ids.slice(i, i + 400);
                    const refs = chunk.map((id) => db.collection("orders").doc(id));
                    const snaps = await db.getAll(...refs);

                    for (const s of snaps) {
                        if (!s.exists) continue;
                        const o = s.data() || {};

                        // processedAt is set when access happens (first time)
                        const pa = o.processedAt?.toDate?.() || null;
                        if (pa && pa >= start && pa < end) {
                            processedCount += 1;

                            const mk = monthKeyUtc(pa);
                            const cur = monthAgg.get(mk) || { sales: 0, earnings: 0, gross: 0, stripe: 0, platform: 0, views: null, processed: 0 };
                            cur.processed += 1;
                            monthAgg.set(mk, cur);
                            continue;
                        }

                        // fallback: if status is processed AND createdAt is in range
                        const ca = o.createdAt?.toDate?.() || null;
                        if (String(o.status || "") === "processed" && ca && ca >= start && ca < end) {
                            processedCount += 1;

                            const mk = monthKeyUtc(ca);
                            const cur = monthAgg.get(mk) || { sales: 0, earnings: 0, gross: 0, stripe: 0, platform: 0, views: null, processed: 0 };
                            cur.processed += 1;
                            monthAgg.set(mk, cur);
                        }
                    }
                }
            }

            // -------------------- VIEWS (best-effort; may require a composite index) --------------------
            let viewsCount = null; // null => unavailable
            try {
                const viewsSnap = await db
                    .collection("productViews")
                    .where("sellerUid", "==", decoded.uid)
                    .where("createdAt", ">=", startTs)
                    .where("createdAt", "<", endTs)
                    .limit(5000)
                    .get();

                viewsCount = viewsSnap.size;

                for (const d of viewsSnap.docs) {
                    const v = d.data() || {};
                    const ca = v.createdAt?.toDate?.() || null;
                    if (!ca) continue;
                    const mk = monthKeyUtc(ca);
                    const cur = monthAgg.get(mk) || { sales: 0, earnings: 0, gross: 0, stripe: 0, platform: 0, views: 0, processed: 0 };
                    cur.views = Number(cur.views || 0) + 1;
                    monthAgg.set(mk, cur);
                }
            } catch (e) {
                // If missing index, still send the email with Views = N/A
                console.error(`[${FN}] views query failed (likely missing index):`, e?.message);
                viewsCount = null;
            }

            // Build month rows (3 months)
            const keys = [];
            {
                const d0 = new Date(start.getTime());
                for (let i = 0; i < 3; i++) {
                    keys.push(monthKeyUtc(d0));
                    d0.setUTCMonth(d0.getUTCMonth() + 1);
                }
            }

            const monthRows = keys.map((k) => {
                const m = monthAgg.get(k) || { sales: 0, earnings: 0, views: viewsCount === null ? null : 0, processed: 0 };
                const viewsCell = (m.views === null || m.views === undefined) ? "N/A" : String(m.views);
                return [
                    monthLabelFromKey(k),
                    String(m.sales || 0),
                    viewsCell,
                    String(m.processed || 0),
                    `${money2(m.earnings || 0)} USD`
                ];
            });

            const totalsTable = kvTable([
                ["Period", `<span style="font-weight:900;color:#007bff;">${label}</span>`],
                ["Sales", `<span style="font-weight:900;">${salesCount}</span>`],
                ["Product views", viewsCount === null ? `<span style="font-weight:900;color:#6c757d;">N/A</span>` : `<span style="font-weight:900;">${viewsCount}</span>`],
                ["Orders", `<span style="font-weight:900;">${ordersCount}</span>`],
                ["Processed", `<span style="font-weight:900;">${processedCount}</span>`],
                ["Gross revenue", `<span style="font-weight:900;">${money2(gross)} USD</span>`],
                ["Stripe fees", `<span style="font-weight:900;color:#6c757d;">${money2(stripeFees)} USD</span>`],
                ["Platform fees", `<span style="font-weight:900;color:#6c757d;">${money2(platformFees)} USD</span>`],
                ["Net earnings", `<span style="font-weight:900;color:#28a745;">${money2(earningsNet)} USD</span>`],
            ]);

            const monthlyTable = htmlMetricsTable({
                headers: ["Month", "Sales", "Views", "Processed", "Net earnings"],
                items: monthRows
            });

            const base = getPublicSiteOrigin();
            const dashboardUrl = `${base}/dashboard.html`;

            await sendEmail("seller_quarterly_report", {
                to,
                subject: `Your quarterly report — ${label}`,
                title: `Quarterly report — ${label}`,
                preheader: `Sales: ${salesCount} • Net: ${money2(earningsNet)} USD`,
                bodyHtml: `
                    <p>Here is your quarterly performance report. Keep pushing — consistency wins.</p>

                    <div style="margin:12px 0;">
                      ${totalsTable}
                    </div>

                    <div style="margin:12px 0;">
                      <div style="font-weight:900;color:#007bff;margin:0 0 8px 0;">Monthly breakdown</div>
                      ${monthlyTable}
                    </div>

                    ${emailButton({ href: dashboardUrl, label: "Open dashboard", tone: "primary" })}

                `,
                uid: decoded.uid,
                meta: {
                    quarter: Number(quarter),
                    year: Number(y),
                    start: start.toISOString(),
                    end: end.toISOString(),
                    salesCount,
                    ordersCount,
                    processedCount,
                    viewsCount,
                    earningsNet: Number(earningsNet.toFixed(2)),
                }
            });

            res2.status(200).json({
                success: true,
                sent: true,
                period: { label, start: start.toISOString(), end: end.toISOString() },
                totals: { salesCount, ordersCount, processedCount, viewsCount, gross, stripeFees, platformFees, earningsNet }
            });
        } catch (e) {
            console.error(FN, e);
            await logSystemError(FN, e, { body: req2.body });
            res2.status(e.httpStatus || 500).json({ success: false, error: e.message || "Internal error", code: e.code || "internal" });
        }
    });
});