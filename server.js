import "dotenv/config";
import express from "express";
import helmet from "helmet";
import session from "express-session";
import pgSession from "connect-pg-simple";
import pg from "pg";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { MercadoPagoConfig, Preference, Payment } from "mercadopago";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false } });
const PgStore = pgSession(session);
const PRICE = Number(process.env.COURSE_PRICE || 90000);
const mp = process.env.MP_ACCESS_TOKEN ? new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN }) : null;
const preferenceClient = mp ? new Preference(mp) : null;
const paymentClient = mp ? new Payment(mp) : null;

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new PgStore({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || "development-only-change-this",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 24 * 30 }
}));

const checkoutLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS students (
      id BIGSERIAL PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id UUID PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES students(id),
      amount INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      mp_preference_id TEXT,
      mp_payment_id TEXT UNIQUE,
      claim_token_hash TEXT NOT NULL,
      claim_used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    );
  `);
}

function normalizePhone(value) {
  let p = String(value || "").replace(/\D/g, "");
  if (p.startsWith("0")) p = p.slice(1);
  if (p.startsWith("15")) p = "549" + p.slice(2);
  if (p.startsWith("54") && !p.startsWith("549")) p = "549" + p.slice(2);
  if (!p.startsWith("549")) p = "549" + p;
  return p;
}
function cleanText(v, max=60) { return String(v || "").trim().replace(/[<>]/g, "").slice(0, max); }
function safeEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function requireStudent(req, res, next) {
  if (!req.session.studentId) return res.redirect("/ingresar");
  next();
}

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/ingresar", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/pago-exitoso", (req, res) => res.sendFile(path.join(__dirname, "public", "success.html")));
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/checkout", checkoutLimiter, async (req, res) => {
  try {
    if (!preferenceClient) return res.status(503).json({ error: "La tienda todavía no está conectada a Mercado Pago." });
    const firstName = cleanText(req.body.firstName);
    const lastName = cleanText(req.body.lastName);
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    if (!firstName || !lastName || phone.length < 11 || password.length < 8) {
      return res.status(400).json({ error: "Completá nombre, apellido, WhatsApp y una contraseña de al menos 8 caracteres." });
    }
    const exists = await pool.query("SELECT id FROM students WHERE phone=$1", [phone]);
    if (exists.rowCount) return res.status(409).json({ error: "Ese WhatsApp ya tiene una cuenta. Iniciá sesión o contactanos para recuperar el acceso." });

    const passwordHash = await bcrypt.hash(password, 12);
    const studentResult = await pool.query(
      "INSERT INTO students(first_name,last_name,phone,password_hash) VALUES($1,$2,$3,$4) RETURNING id",
      [firstName, lastName, phone, passwordHash]
    );
    const studentId = studentResult.rows[0].id;
    const orderId = crypto.randomUUID();
    const claimToken = crypto.randomBytes(32).toString("hex");
    const claimHash = crypto.createHash("sha256").update(claimToken).digest("hex");
    await pool.query(
      "INSERT INTO orders(id,student_id,amount,claim_token_hash) VALUES($1,$2,$3,$4)",
      [orderId, studentId, PRICE, claimHash]
    );

    const base = process.env.BASE_URL;
    if (!base || !base.startsWith("https://")) throw new Error("Configurá BASE_URL con la dirección HTTPS publicada de la web.");
    const preference = await preferenceClient.create({
      body: {
        items: [{ id: "curso-cm-bnja", title: "Curso de Community Management - BNJA.STUDIO", quantity: 1, currency_id: "ARS", unit_price: PRICE }],
        external_reference: orderId,
        notification_url: `${base}/api/mercadopago/webhook`,
        back_urls: {
          success: `${base}/pago-exitoso?order=${orderId}&claim=${claimToken}`,
          failure: `${base}/?pago=fallido`,
          pending: `${base}/?pago=pendiente`
        },
        auto_return: "approved",
        statement_descriptor: "BNJA STUDIO"
      }
    });
    await pool.query("UPDATE orders SET mp_preference_id=$1 WHERE id=$2", [preference.id, orderId]);
    res.json({ checkoutUrl: preference.init_point });
  } catch (err) {
    console.error("checkout:", err.message);
    res.status(500).json({ error: "No pudimos iniciar el pago. Revisá los datos e intentá nuevamente." });
  }
});

function verifyWebhook(req) {
  const secret = process.env.MP_WEBHOOK_SECRET;
  if (!secret) return false;
  const signature = req.header("x-signature") || "";
  const requestId = req.header("x-request-id") || "";
  const parts = Object.fromEntries(signature.split(",").map(x => x.trim().split("=")));
  const ts = parts.ts;
  const v1 = parts.v1;
  const dataId = String(req.query["data.id"] || req.query.id || "").toLowerCase();
  if (!ts || !v1 || !requestId || !dataId) return false;
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const expected = crypto.createHmac("sha256", secret).update(manifest).digest("hex");
  return safeEqual(expected, v1);
}

async function sendOwnerWhatsApp({ firstName, lastName, phone, amount, orderId }) {
  const { WHATSAPP_TOKEN, WHATSAPP_PHONE_NUMBER_ID, WHATSAPP_OWNER_NUMBER } = process.env;
  if (!WHATSAPP_TOKEN || !WHATSAPP_PHONE_NUMBER_ID || !WHATSAPP_OWNER_NUMBER) {
    console.log("WhatsApp no configurado; venta aprobada:", orderId);
    return;
  }
  const template = process.env.WHATSAPP_TEMPLATE_NAME || "nueva_venta_bnja";
  const language = process.env.WHATSAPP_TEMPLATE_LANGUAGE || "es_AR";
  const url = `https://graph.facebook.com/${process.env.GRAPH_API_VERSION || "v22.0"}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${WHATSAPP_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      to: WHATSAPP_OWNER_NUMBER,
      type: "template",
      template: {
        name: template,
        language: { code: language },
        components: [{ type: "body", parameters: [
          { type: "text", text: `${firstName} ${lastName}` },
          { type: "text", text: phone },
          { type: "text", text: `$${Number(amount).toLocaleString("es-AR")}` },
          { type: "text", text: orderId }
        ] }]
      }
    })
  });
  if (!response.ok) console.error("WhatsApp notification failed:", await response.text());
}

app.post("/api/mercadopago/webhook", async (req, res) => {
  try {
    if (!verifyWebhook(req)) return res.sendStatus(401);
    const type = req.query.type || req.body.type;
    const paymentId = req.query["data.id"] || req.body.data?.id;
    if (type !== "payment" || !paymentId) return res.sendStatus(200);
    const payment = await paymentClient.get({ id: paymentId });
    if (payment.status !== "approved" || payment.currency_id !== "ARS" || Number(payment.transaction_amount) !== PRICE) return res.sendStatus(200);
    const orderId = payment.external_reference;
    if (!orderId) return res.sendStatus(200);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT o.id,o.status,o.amount,s.id AS student_id,s.first_name,s.last_name,s.phone
         FROM orders o JOIN students s ON s.id=o.student_id WHERE o.id=$1 FOR UPDATE`, [orderId]
      );
      if (!found.rowCount) { await client.query("ROLLBACK"); return res.sendStatus(200); }
      const row = found.rows[0];
      if (row.status !== "paid" && Number(row.amount) === PRICE) {
        await client.query("UPDATE orders SET status='paid',mp_payment_id=$1,paid_at=NOW() WHERE id=$2", [String(payment.id), orderId]);
        await client.query("UPDATE students SET active=TRUE WHERE id=$1", [row.student_id]);
        await client.query("COMMIT");
        await sendOwnerWhatsApp({ ...row, amount: row.amount, orderId });
      } else {
        await client.query("COMMIT");
      }
    } catch (e) { await client.query("ROLLBACK"); throw e; }
    finally { client.release(); }
    res.sendStatus(200);
  } catch (err) {
    console.error("webhook:", err.message);
    res.sendStatus(500);
  }
});

app.get("/api/orders/:id/status", async (req, res) => {
  const result = await pool.query("SELECT status FROM orders WHERE id=$1", [req.params.id]);
  if (!result.rowCount) return res.status(404).json({ status: "not_found" });
  res.json({ status: result.rows[0].status });
});

app.post("/api/orders/:id/claim", async (req, res) => {
  try {
    const token = String(req.body.claim || "");
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    const result = await pool.query(
      `SELECT o.id,o.student_id,o.claim_token_hash,o.claim_used,o.status
       FROM orders o WHERE o.id=$1`, [req.params.id]
    );
    if (!result.rowCount) return res.sendStatus(404);
    const order = result.rows[0];
    if (order.status !== "paid" || order.claim_used || !safeEqual(hash, order.claim_token_hash)) return res.sendStatus(403);
    await pool.query("UPDATE orders SET claim_used=TRUE WHERE id=$1 AND claim_used=FALSE", [order.id]);
    req.session.studentId = order.student_id;
    res.json({ ok: true, redirect: "/curso" });
  } catch { res.sendStatus(500); }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const password = String(req.body.password || "");
  const result = await pool.query("SELECT id,password_hash,active FROM students WHERE phone=$1", [phone]);
  if (!result.rowCount || !result.rows[0].active || !(await bcrypt.compare(password, result.rows[0].password_hash))) {
    return res.status(401).json({ error: "WhatsApp o contraseña incorrectos, o el pago todavía no está aprobado." });
  }
  req.session.studentId = result.rows[0].id;
  res.json({ ok: true, redirect: "/curso" });
});

app.get("/contenido-curso", requireStudent, async (req, res) => {
  const result = await pool.query("SELECT active FROM students WHERE id=$1", [req.session.studentId]);
  if (!result.rowCount || !result.rows[0].active) return res.redirect("/ingresar");
  res.sendFile(path.join(__dirname, "private", "curso-real.html"));
});

app.get("/curso", requireStudent, async (req, res) => {
  const result = await pool.query("SELECT active FROM students WHERE id=$1", [req.session.studentId]);
  if (!result.rowCount || !result.rows[0].active) return res.redirect("/ingresar");
  res.redirect("/contenido-curso");
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true, redirect: "/" })));

const port = Number(process.env.PORT || 3000);
initDb().then(() => app.listen(port, () => console.log(`BNJA.STUDIO listo en puerto ${port}`)))
  .catch(err => { console.error("No se pudo iniciar la base de datos:", err); process.exit(1); });
