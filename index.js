const express = require('express');
const crypto = require('crypto');
const https = require('https');
const app = express();

const WEBHOOK_SECRET = process.env.SALLA_WEBHOOK_SECRET || '';
const ODOO_URL = process.env.ODOO_URL || 'https://erp.abajur.sa';
const ODOO_DB = process.env.ODOO_DB || 'abajur';
const ODOO_USER = process.env.ODOO_USER || 'A.alassaf@abajur.sa';
const ODOO_PASS = process.env.ODOO_PASS || '0';
const CLIENT_ID = process.env.SALLA_CLIENT_ID || 'e0f94087-554f-47cd-aedb-a11240990e45';
const CLIENT_SECRET = process.env.SALLA_CLIENT_SECRET || '';

app.use(express.raw({ type: '*/*', limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Odoo helper ────────────────────────────────────────────────────────────
function odooRequest(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const options = {
      hostname: new URL(ODOO_URL).hostname, port: 443, path,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    };
    const req = https.request(options, res => {
      let d = '';
      res.on('data', x => d += x);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.end(data);
  });
}

async function storeTokensInOdoo(accessToken, refreshToken, expiresIn) {
  // Authenticate first
  const auth = await odooRequest('/web/session/authenticate', {
    jsonrpc: '2.0', method: 'call', id: 1,
    params: { db: ODOO_DB, login: ODOO_USER, password: ODOO_PASS }
  });
  const uid = auth.result?.uid;
  if (!uid) throw new Error('Odoo auth failed');

  const expiry = new Date(Date.now() + expiresIn * 1000)
    .toISOString().replace('T', ' ').split('.')[0];

  // Store each param
  const setParam = async (key, value) => {
    await odooRequest('/web/dataset/call_kw', {
      jsonrpc: '2.0', method: 'call', id: 1,
      params: { model: 'ir.config_parameter', method: 'set_param', args: [key, value], kwargs: {} }
    });
  };

  await setParam('salla.access_token', accessToken);
  await setParam('salla.refresh_token', refreshToken);
  await setParam('salla.token_expiry', expiry);
  console.log(`✅ Tokens stored in Odoo. Expiry: ${expiry}`);
}

// ── OAuth Callback (authorization_code flow) ───────────────────────────────
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;

  if (error) return res.send(`<h2>Error: ${error}</h2>`);
  if (!code) return res.send('<h2>No code received</h2>');

  console.log(`[callback] Got code: ${code.substring(0, 20)}...`);

  try {
    // Exchange code for token
    const tokenResp = await new Promise((resolve, reject) => {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: `${req.protocol}://${req.get('host')}/callback`
      }).toString();

      const options = {
        hostname: 'accounts.salla.sa', port: 443,
        path: '/oauth2/token', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
      };
      const r = https.request(options, resp => {
        let d = '';
        resp.on('data', x => d += x);
        resp.on('end', () => resolve(JSON.parse(d)));
      });
      r.on('error', reject);
      r.end(body);
    });

    console.log('Token response:', JSON.stringify(tokenResp).substring(0, 100));

    if (tokenResp.access_token) {
      await storeTokensInOdoo(
        tokenResp.access_token,
        tokenResp.refresh_token || '',
        tokenResp.expires_in || 3600
      );
      res.send(`<h2>✅ تم! Token stored in Odoo</h2><p>Access token received and stored successfully.</p><p>Expires in: ${tokenResp.expires_in}s</p>`);
    } else {
      res.send(`<h2>❌ Error</h2><pre>${JSON.stringify(tokenResp, null, 2)}</pre>`);
    }
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send(`<h2>Error</h2><p>${err.message}</p>`);
  }
});

// ── Webhook endpoint ───────────────────────────────────────────────────────
app.post('/salla/webhook', async (req, res) => {
  const raw = req.body;

  // Verify HMAC
  if (WEBHOOK_SECRET) {
    const sig = req.headers['x-salla-signature'] || '';
    const digest = crypto.createHmac('sha256', WEBHOOK_SECRET).update(raw).digest('hex');
    if (sig && !crypto.timingSafeEqual(Buffer.from(digest.padEnd(64,'0')), Buffer.from(sig.padEnd(64,'0')))) {
      return res.status(401).send('invalid signature');
    }
  }

  let payload;
  try { payload = JSON.parse(raw); } catch (e) { return res.status(400).send('bad json'); }

  const event = payload.event || '';
  const data = payload.data || {};
  console.log(`[webhook] ${new Date().toISOString()} Event: ${event}`);

  if (event === 'app.store.authorize') {
    const token = data.token || {};
    const access = data.access_token || token.access_token || '';
    const refresh = data.refresh_token || token.refresh_token || '';
    const expiresIn = parseInt(data.expires_in || token.expires_in || 3600);
    if (access) {
      try {
        await storeTokensInOdoo(access, refresh, expiresIn);
      } catch (err) {
        console.error('Failed to store token:', err.message);
        return res.status(500).send('error');
      }
    }
  }

  res.status(200).send('ok');
});

// ── Auth URL helper ────────────────────────────────────────────────────────
app.get('/auth', (req, res) => {
  const redirectUri = encodeURIComponent(`${req.protocol}://${req.get('host')}/callback`);
  const url = `https://accounts.salla.sa/oauth2/auth?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=offline_access&state=abajur`;
  res.redirect(url);
});

app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/', (req, res) => res.json({
  service: 'Salla→Odoo Relay',
  endpoints: { webhook: '/salla/webhook', auth: '/auth', callback: '/callback', health: '/health' }
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Salla relay on :${PORT}`));
