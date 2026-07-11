/**
 * Salla → Odoo Relay (Abajur)
 * Full middleware: receives all Salla webhooks, processes them via Odoo JSON-RPC.
 * No direct webhook endpoint on Odoo needed.
 */
const express = require('express');
const crypto  = require('crypto');
const https   = require('https');
const http    = require('http');
const app     = express();

const WEBHOOK_SECRET = process.env.SALLA_WEBHOOK_SECRET || '';
const ODOO_URL       = process.env.ODOO_URL             || 'https://erp.abajur.sa';
const ODOO_DB        = process.env.ODOO_DB              || 'abajur';
const ODOO_USER      = process.env.ODOO_USER            || 'A.alassaf@abajur.sa';
const ODOO_PASS      = process.env.ODOO_PASS            || '';
const CLIENT_ID      = process.env.SALLA_CLIENT_ID      || 'e0f94087-554f-47cd-aedb-a11240990e45';
const CLIENT_SECRET  = process.env.SALLA_CLIENT_SECRET  || '';
const SALLA_API      = 'https://api.salla.dev/admin/v2';

app.use(express.raw({ type: '*/*', limit: '5mb' }));

// ── HTTP helper ────────────────────────────────────────────────────────────
function doRequest(urlStr, opts, body) {
  return new Promise((resolve, reject) => {
    const u   = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = lib.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: opts.method || 'POST',
      headers: { 'Content-Length': Buffer.byteLength(data), ...opts.headers },
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

// ── Odoo session ───────────────────────────────────────────────────────────
let _session = null;

async function odooAuth() {
  const r = await doRequest(`${ODOO_URL}/web/session/authenticate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
  }, { jsonrpc: '2.0', method: 'call', id: 1,
       params: { db: ODOO_DB, login: ODOO_USER, password: ODOO_PASS } });
  const uid = r.body?.result?.uid;
  if (!uid) throw new Error(`Odoo auth failed: ${JSON.stringify(r.body).slice(0,200)}`);
  _session = r.body.result.session_id;
  return uid;
}

async function odooRpc(model, method, args = [], kwargs = {}) {
  if (!_session) await odooAuth();
  const r = await doRequest(`${ODOO_URL}/web/dataset/call_kw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': `session_id=${_session}` },
  }, { jsonrpc: '2.0', method: 'call', id: Date.now(),
       params: { model, method, args, kwargs } });
  if (r.body?.error) {
    // Session expired — re-auth once
    if (r.body.error.code === 100 || JSON.stringify(r.body.error).includes('session')) {
      _session = null;
      await odooAuth();
      return odooRpc(model, method, args, kwargs);
    }
    throw new Error(r.body.error.data?.message || JSON.stringify(r.body.error));
  }
  return r.body?.result;
}

async function getParam(key) {
  return odooRpc('ir.config_parameter', 'get_param', [key]);
}

async function setParam(key, value) {
  return odooRpc('ir.config_parameter', 'set_param', [key, value]);
}

async function storeTokens(access, refresh, expiresIn) {
  if (!ODOO_PASS) { console.warn('[token] ODOO_PASS not set'); return; }
  const expiry = new Date(Date.now() + (expiresIn || 3600) * 1000)
    .toISOString().replace('T', ' ').split('.')[0];
  await setParam('salla.access_token',  access);
  await setParam('salla.refresh_token', refresh || '');
  await setParam('salla.token_expiry',  expiry);
  console.log(`[token] stored, expires ${expiry}`);
}

// ── Salla API helper ───────────────────────────────────────────────────────
async function sallaGet(path) {
  const token = await getParam('salla.access_token');
  if (!token) throw new Error('No Salla access token');
  const r = await doRequest(`${SALLA_API}${path}`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
  }, '');
  return r.body;
}

async function sallaUpdate(path, body) {
  const token = await getParam('salla.access_token');
  if (!token) throw new Error('No Salla access token');
  return doRequest(`${SALLA_API}${path}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
  }, body);
}

// ── Webhook signature ──────────────────────────────────────────────────────
function verifySignature(raw, sig) {
  if (!WEBHOOK_SECRET) return true;
  if (!sig) return false;
  const digest = crypto.createHmac('sha256', WEBHOOK_SECRET).update(raw).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(sig)); }
  catch { return digest === sig; }
}

// ── Status map ────────────────────────────────────────────────────────────
const STATUS_MAP = {
  pending: 'draft', under_review: 'draft', confirmed: 'sale',
  in_progress: 'sale', delivering: 'sale', completed: 'done',
  delivered: 'done', canceled: 'cancel',
};
const REVERSE_STATUS_MAP = { draft: 'pending', sale: 'confirmed', done: 'completed', cancel: 'canceled' };

// ── Event Handlers ─────────────────────────────────────────────────────────

async function handleAuthorize(data) {
  const access    = data.access_token  || data.token?.access_token  || '';
  const refresh   = data.refresh_token || data.token?.refresh_token || '';
  const expiresIn = parseInt(data.expires_in || data.token?.expires_in || 3600);
  if (access) await storeTokens(access, refresh, expiresIn);
}

async function handleOrderCreatedOrUpdated(data) {
  const sallaOrderId = String(data.id || '');
  if (!sallaOrderId) return;

  // Find or create partner
  const customer = data.customer || {};
  const email    = customer.email || '';
  const phone    = customer.mobile || customer.phone || '';
  const name     = [customer.first_name, customer.last_name].filter(Boolean).join(' ') || 'Salla Customer';

  let partners = await odooRpc('res.partner', 'search_read',
    [[email ? ['email', '=', email] : ['phone', '=', phone]]], { fields: ['id'], limit: 1 });
  let partnerId;
  if (partners?.length) {
    partnerId = partners[0].id;
  } else {
    partnerId = await odooRpc('res.partner', 'create', [{
      name, email, phone, customer_rank: 1,
    }]);
  }

  // Check existing order
  const existing = await odooRpc('sale.order', 'search_read',
    [[['x_salla_order_id', '=', sallaOrderId]]], { fields: ['id', 'state'], limit: 1 });

  const sallaStatus = typeof data.status === 'object' ? data.status?.slug : data.status || 'pending';

  if (existing?.length) {
    const order = existing[0];
    if (!['done', 'cancel'].includes(order.state)) {
      await odooRpc('sale.order', 'write', [[order.id], { x_salla_status: sallaStatus }]);
    }
    return;
  }

  // Build order lines
  const items = data.items || [];
  const lines = [];
  for (const item of items) {
    const sku = item.sku || '';
    if (!sku) continue;
    const products = await odooRpc('product.product', 'search_read',
      [[['default_code', '=', sku]]], { fields: ['id'], limit: 1 });
    if (!products?.length) { console.warn(`[order] SKU ${sku} not found`); continue; }
    const price = typeof item.price === 'object' ? parseFloat(item.price?.amount || 0) : parseFloat(item.price || 0);
    lines.push([0, 0, {
      product_id: products[0].id,
      product_uom_qty: parseFloat(item.quantity || 1),
      price_unit: price,
    }]);
  }
  if (!lines.length) { console.warn(`[order] ${sallaOrderId} has no mappable lines`); return; }

  await odooRpc('sale.order', 'create', [{
    partner_id: partnerId,
    x_salla_order_id: sallaOrderId,
    x_salla_status: sallaStatus,
    order_line: lines,
    note: `Salla Order #${data.reference_id || sallaOrderId}`,
  }]);
  console.log(`[order] created sale.order for Salla ${sallaOrderId}`);
}

async function handleProductCreatedOrUpdated(data) {
  const sku  = data.sku || '';
  if (!sku) return;
  let name = data.name;
  if (typeof name === 'object') name = name?.ar || name?.en || '';
  const price    = typeof data.price === 'object' ? parseFloat(data.price?.amount || 0) : parseFloat(data.price || 0);
  const sallaId  = String(data.id || '');

  const products = await odooRpc('product.template', 'search_read',
    [[['default_code', '=', sku]]], { fields: ['id', 'name'], limit: 1 });

  if (products?.length) {
    await odooRpc('product.template', 'write', [[products[0].id], {
      name: name || products[0].name,
      list_price: price || undefined,
      x_salla_id: sallaId,
    }]);
  } else {
    await odooRpc('product.template', 'create', [{
      name: name || `Salla ${sku}`,
      default_code: sku,
      list_price: price,
      type: 'consu',
      x_salla_id: sallaId,
    }]);
  }
  console.log(`[product] upserted SKU=${sku}`);
}

async function handleStockUpdated(data) {
  const sku = data.sku || data.product?.sku || '';
  const qty = data.quantity;
  if (!sku || qty === undefined) return;

  const locIdStr = await getParam('salla.stock_location_id') || '5';
  const locId    = parseInt(locIdStr);

  const products = await odooRpc('product.product', 'search_read',
    [[['default_code', '=', sku]]], { fields: ['id'], limit: 1 });
  if (!products?.length) { console.warn(`[stock] SKU ${sku} not in Odoo`); return; }

  const productId = products[0].id;
  const quants = await odooRpc('stock.quant', 'search_read',
    [[['product_id', '=', productId], ['location_id', '=', locId]]],
    { fields: ['quantity'], limit: 1 });
  const currentQty = quants?.length ? quants[0].quantity : 0;
  const delta = parseFloat(qty) - currentQty;

  if (Math.abs(delta) > 0.001) {
    await odooRpc('stock.quant', '_update_available_quantity',
      [], { product_id: productId, location_id: locId, quantity: delta });
  }
  console.log(`[stock] SKU=${sku} qty=${qty}`);
}

async function handlePaymentUpdated(data) {
  const sallaOrderId = String(data.order_id || data.id || '');
  if (!sallaOrderId) return;

  const orders = await odooRpc('sale.order', 'search_read',
    [[['x_salla_order_id', '=', sallaOrderId]]], { fields: ['id', 'state'], limit: 1 });
  if (!orders?.length) { console.warn(`[payment] no order for ${sallaOrderId}`); return; }

  const order = orders[0];
  if (order.state === 'draft') {
    await odooRpc('sale.order', 'action_confirm', [[order.id]]);
  }

  const invoices = await odooRpc('account.move', 'search_read',
    [[['invoice_origin', 'like', sallaOrderId], ['move_type', '=', 'out_invoice']]],
    { fields: ['id'], limit: 1 });
  if (invoices?.length) return;

  const invoiceIds = await odooRpc('sale.order', '_create_invoices', [[order.id]]);
  if (invoiceIds?.length) {
    await odooRpc('account.move', 'action_post', [invoiceIds]);
    console.log(`[payment] invoice created for Salla ${sallaOrderId}`);
  }
}

// ── Webhook dispatcher ─────────────────────────────────────────────────────
const HANDLERS = {
  'app.store.authorize':   (d) => handleAuthorize(d),
  'order.created':         (d) => handleOrderCreatedOrUpdated(d),
  'order.updated':         (d) => handleOrderCreatedOrUpdated(d),
  'product.created':       (d) => handleProductCreatedOrUpdated(d),
  'product.updated':       (d) => handleProductCreatedOrUpdated(d),
  'stock.updated':         (d) => handleStockUpdated(d),
  'payment.updated':       (d) => handlePaymentUpdated(d),
};

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
  const data  = payload.data  || {};
  console.log(`[webhook] ${new Date().toISOString()} event=${event}`);

  const handler = HANDLERS[event];
  if (!handler) {
    console.log(`[webhook] unhandled event: ${event}`);
    return res.status(200).send('ok');
  }

  // Respond immediately, process async
  res.status(200).send('ok');
  try { await handler(data); }
  catch (e) { console.error(`[webhook] handler error for ${event}:`, e.message); }
});

// ── OAuth ──────────────────────────────────────────────────────────────────
app.get('/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`<h2>❌ ${error}</h2>`);
  if (!code) return res.send('<h2>No code</h2>');
  if (!CLIENT_SECRET) return res.send('<h2>SALLA_CLIENT_SECRET not set</h2>');

  try {
    const redirectUri = `https://${req.get('host')}/callback`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      code, redirect_uri: redirectUri,
    }).toString();
    const r = await doRequest('https://accounts.salla.sa/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, body);
    const tok = r.body;
    if (!tok.access_token) return res.send(`<h2>❌ No token</h2><pre>${JSON.stringify(tok,null,2)}</pre>`);
    await storeTokens(tok.access_token, tok.refresh_token, tok.expires_in);
    res.send(`<h2>✅ Authorization complete!</h2><p>Scope: ${tok.scope || 'N/A'} | Expires: ${tok.expires_in}s</p>`);
  } catch (e) {
    res.status(500).send(`<h2>Error</h2><p>${e.message}</p>`);
  }
});

app.get('/auth', (req, res) => {
  if (!CLIENT_SECRET) return res.send('<h2>SALLA_CLIENT_SECRET not set</h2>');
  // Always use https behind Railway proxy
  const host = req.get('host');
  const redirectUri = encodeURIComponent(`https://${host}/callback`);
  res.redirect(`https://accounts.salla.sa/oauth2/auth?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=offline_access&state=abajur`);
});

// ── Health & root ──────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok', time: new Date().toISOString(),
    odoo: ODOO_URL,
    clientSecretSet: !!CLIENT_SECRET, odooPassSet: !!ODOO_PASS,
    webhookSecretSet: !!WEBHOOK_SECRET,
  });
});

app.get('/', (req, res) => res.json({
  service: 'Salla→Odoo Relay (Abajur) — Full Middleware',
  endpoints: {
    webhook:  'POST /salla/webhook — receives all Salla events',
    auth:     'GET  /auth         — start OAuth',
    callback: 'GET  /callback     — OAuth return',
    health:   'GET  /health',
  },
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Relay :${PORT} | Odoo: ${ODOO_URL}`));
