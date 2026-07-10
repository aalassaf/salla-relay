const express = require('express');
const crypto = require('crypto');
const https = require('https');
const app = express();

const WEBHOOK_SECRET = process.env.SALLA_WEBHOOK_SECRET || '';
const ODOO_URL = process.env.ODOO_URL || 'https://erp.abajur.sa';
const ODOO_DB = process.env.ODOO_DB || 'abajur';
const ODOO_USER = process.env.ODOO_USER || 'A.alassaf@abajur.sa';
const ODOO_PASS = process.env.ODOO_PASS || '0';

app.use(express.raw({ type: '*/*', limit: '5mb' }));

// ── Odoo RPC helper ────────────────────────────────────────────────────────
function odooRpc(model, method, args = [], kwargs = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      jsonrpc: '2.0', method: 'call', id: 1,
      params: { model, method, args, kwargs }
    });
    const url = new URL('/web/dataset/call_kw', ODOO_URL);
    const options = {
      hostname: url.hostname, port: 443, path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Login once and cache session
let sessionCookie = '';
async function odooLogin() {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      jsonrpc: '2.0', method: 'call', id: 1,
      params: { db: ODOO_DB, login: ODOO_USER, password: ODOO_PASS }
    });
    const options = {
      hostname: new URL(ODOO_URL).hostname, port: 443,
      path: '/web/session/authenticate', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = https.request(options, res => {
      let data = '';
      const cookies = res.headers['set-cookie'] || [];
      cookies.forEach(c => { if (c.startsWith('session_id')) sessionCookie = c.split(';')[0]; });
      res.on('data', d => data += d);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function setParam(key, value) {
  if (!sessionCookie) await odooLogin();
  // Find existing param
  const found = await odooRpc('ir.config_parameter', 'search_read',
    [[['key', '=', key]]], { fields: ['id', 'value'], limit: 1 });
  const records = found.result || [];
  if (records.length) {
    await odooRpc('ir.config_parameter', 'write', [[records[0].id], { value }]);
  } else {
    await odooRpc('ir.config_parameter', 'create', [[{ key, value }]]);
  }
}

// ── Webhook endpoint ───────────────────────────────────────────────────────
app.post('/salla/webhook', async (req, res) => {
  const raw = req.body;

  // Verify HMAC signature
  if (WEBHOOK_SECRET) {
    const sig = req.headers['x-salla-signature'] || '';
    const digest = crypto.createHmac('sha256', WEBHOOK_SECRET).update(raw).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(sig.padEnd(digest.length, '0')))) {
      console.log('Invalid signature');
      return res.status(401).send('invalid signature');
    }
  }

  let payload;
  try { payload = JSON.parse(raw); }
  catch (e) { return res.status(400).send('bad json'); }

  const event = payload.event || '';
  const data = payload.data || {};
  console.log(`[${new Date().toISOString()}] Event: ${event}`);

  try {
    if (event === 'app.store.authorize') {
      // Extract token
      const token = data.token || {};
      const access = data.access_token || token.access_token || '';
      const refresh = data.refresh_token || token.refresh_token || '';
      const expiresIn = parseInt(data.expires_in || token.expires_in || 3600);
      const expiry = new Date(Date.now() + expiresIn * 1000).toISOString().replace('T', ' ').split('.')[0];

      if (access) {
        await odooLogin(); // fresh login
        await setParam('salla.access_token', access);
        await setParam('salla.refresh_token', refresh);
        await setParam('salla.token_expiry', expiry);
        console.log(`✅ Token stored! Expires: ${expiry}`);
      }
    } else {
      console.log(`Event ${event} received — not handled by relay`);
    }
  } catch (err) {
    console.error('Error processing webhook:', err.message);
    return res.status(500).send('error');
  }

  res.status(200).send('ok');
});

// ── Health check ───────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ service: 'Salla→Odoo Relay', status: 'running' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Salla relay listening on :${PORT}`));
