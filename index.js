const express = require('express');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const app = express();

const WEBHOOK_SECRET  = process.env.SALLA_WEBHOOK_SECRET  || '';
const ODOO_URL        = process.env.ODOO_URL               || 'https://erp.abajur.sa';
const ODOO_DB         = process.env.ODOO_DB                || 'abajur';
const ODOO_USER       = process.env.ODOO_USER              || 'A.alassaf@abajur.sa';
const ODOO_PASS       = process.env.ODOO_PASS              || '';
const CLIENT_ID       = process.env.SALLA_CLIENT_ID        || 'e0f94087-554f-47cd-aedb-a11240990e45';
const CLIENT_SECRET   = process.env.SALLA_CLIENT_SECRET    || '';

app.use(express.raw({ type: '*/*', limit: '5mb' }));

// ── HTTP helper (supports http + https) ───────────────────────────────────
function doRequest(urlStr, options, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const port = u.port || (u.protocol === 'https:' ? 443 : 80);
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = lib.request({
      hostname: u.hostname, port,
      path: u.pathname + u.search,
      method: options.method || 'POST',
      headers: { 'Content-Length': Buffer.byteLength(data), ...options.headers },
    }, res => {
      let d = '';
      res.on('data', x => d += x);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d) }); }
        catch { resolve({ status: res.statusCode, body: d }); }
      });
    });
    req.on('error', reject);
    req.end(data);
  });
}

// ── Odoo JSON-RPC helper ──────────────────────────────────────────────────
let _odooSession = null;

async function odooAuth() {
  const r = await doRequest(`${ODOO_URL}/web/session/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { jsonrpc: '2.0', method: 'call', id: 1,
       params: { db: ODOO_DB, login: ODOO_USER, password: ODOO_PASS } });
  const uid = r.body?.result?.uid;
  if (!uid) throw new Error(`Odoo auth failed: ${JSON.stringify(r.body).slice(0,200)}`);
  _odooSession = r.body.result.session_id;
  return uid;
}

async function odooSetParam(key, value) {
  await odooAuth();
  await doRequest(`${ODOO_URL}/web/dataset/call_kw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': `session_id=${_odooSession}` },
  }, {
    jsonrpc: '2.0', method: 'call', id: 2,
    params: {
      model: 'ir.config_parameter', method: 'set_param',
      args: [key, value], kwargs: {},
    },
  });
}

async function storeTokensInOdoo(accessToken, refreshToken, expiresIn) {
  if (!ODOO_PASS) { console.warn('ODOO_PASS not set — cannot store tokens'); return; }
  const expiry = new Date(Date.now() + (expiresIn || 3600) * 1000)
    .toISOString().replace('T', ' ').split('.')[0];
  await odooSetParam('salla.access_token',  accessToken);
  await odooSetParam('salla.refresh_token', refreshToken || '');
  await odooSetParam('salla.token_expiry',  expiry);
  console.log(`✅ Tokens stored in Odoo. Expiry: ${expiry}`);
}

// ── Webhook signature verify ───────────────────────────────────────────────
function verifySignature(raw, sig) {
  if (!WEBHOOK_SECRET) return true; // warn only — disabled during setup
  if (!sig) return false;
  const digest = crypto.createHmac('sha256', WEBHOOK_SECRET).update(raw).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(sig));
  } catch { return false; }
}

// ── OAuth callback ─────────────────────────────────────────────────────────
app.get('/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`<h2>❌ Error: ${error}</h2>`);
  if (!code) return res.send('<h2>No code received</h2>');
  if (!CLIENT_SECRET) return res.send('<h2>SALLA_CLIENT_SECRET not configured</h2>');

  console.log(`[callback] code received`);
  try {
    const redirectUri = `${req.protocol}://${req.get('host')}/callback`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }).toString();

    const r = await doRequest('https://accounts.salla.sa/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, body);

    const tok = r.body;
    console.log('Token response status:', r.status);
    if (!tok.access_token) {
      return res.send(`<h2>❌ No token</h2><pre>${JSON.stringify(tok, null, 2)}</pre>`);
    }

    await storeTokensInOdoo(tok.access_token, tok.refresh_token, tok.expires_in);
    res.send(`
      <h2>✅ Authorization complete!</h2>
      <p>Access token stored in Odoo successfully.</p>
      <p>Expires in: ${tok.expires_in}s</p>
      <p>Scope: ${tok.scope || 'N/A'}</p>
    `);
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send(`<h2>Error</h2><p>${err.message}</p>`);
  }
});

// ── Webhook endpoint ───────────────────────────────────────────────────────
app.post('/salla/webhook', async (req, res) => {
  const raw = req.body;

  const sig = req.headers['x-salla-signature'] || '';
  if (!verifySignature(raw, sig)) {
    console.warn('[webhook] invalid signature');
    return res.status(401).send('invalid signature');
  }

  let payload;
  try { payload = JSON.parse(raw); } catch { return res.status(400).send('bad json'); }

  const event = payload.event || '';
  console.log(`[webhook] ${new Date().toISOString()} event=${event}`);

  // Handle app.store.authorize → store tokens in Odoo
  if (event === 'app.store.authorize') {
    const data = payload.data || {};
    const access   = data.access_token  || data.token?.access_token  || '';
    const refresh  = data.refresh_token || data.token?.refresh_token || '';
    const expiresIn = parseInt(data.expires_in || data.token?.expires_in || 3600);
    if (access) {
      try { await storeTokensInOdoo(access, refresh, expiresIn); }
      catch (err) { console.error('storeTokens error:', err.message); }
    }
    return res.status(200).send('ok');
  }

  // Forward all other events directly to Odoo
  try {
    const r = await doRequest(`${ODOO_URL}/salla/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Salla-Signature': sig,
        'X-Forwarded-For': req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '',
      },
    }, raw);
    console.log(`[webhook] forwarded to Odoo → ${r.status}`);
  } catch (err) {
    console.error('[webhook] forward error:', err.message);
  }

  res.status(200).send('ok');
});

// ── Auth initiation helper ─────────────────────────────────────────────────
app.get('/auth', (req, res) => {
  if (!CLIENT_SECRET) {
    return res.send('<h2>SALLA_CLIENT_SECRET not set in env vars</h2>');
  }
  const redirectUri = encodeURIComponent(`${req.protocol}://${req.get('host')}/callback`);
  const url = `https://accounts.salla.sa/oauth2/auth?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=offline_access&state=abajur`;
  res.redirect(url);
});

// ── Helpers ────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  time: new Date().toISOString(),
  odoo: ODOO_URL,
  clientId: CLIENT_ID,
  webhookSecretSet: !!WEBHOOK_SECRET,
  clientSecretSet: !!CLIENT_SECRET,
  odooPassSet: !!ODOO_PASS,
}));

app.get('/', (req, res) => res.json({
  service: 'Salla→Odoo Relay (Abajur)',
  endpoints: {
    auth:     '/auth     → start OAuth',
    callback: '/callback → OAuth return',
    webhook:  '/salla/webhook → Salla webhooks (forward to Odoo)',
    health:   '/health',
  },
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Salla relay on :${PORT} | Odoo: ${ODOO_URL}`));
