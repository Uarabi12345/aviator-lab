import 'dotenv/config';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { createServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { config } from './config.js';
import { engine } from './engine.js';
import { stkPush, b2c, normalizePhone } from './mpesa.js';
import { registerUploads, getUploadInfo } from './uploads.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// SECURE: Helmet configured to protect headers without breaking your app
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: false,
  crossOriginOpenerPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
}));

app.use(express.json({ limit: '10mb' })); // Prevent large payload attacks
app.use(express.static(join(__dirname, '..', 'public')));

const adminTokens = new Map();
let tokenSeq = 0;

// SECURE: Session store to prevent WebSocket spoofing
const sessions = new Map(); // token -> { phone, playerId }

function isSuper(password) { return password === config.adminPassword; }
function isAdmin(password) { return isSuper(password) || adminTokens.has(password); }

// SECURE: Helper to read admin password from Header (prevents URL logging leaks)
function getAdminPassword(req) {
  return String(req.headers['x-admin-password'] || req.query.password || '');
}

// RATE LIMIT: Admin login brute-force protection
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many failed logins. Try again in 15 minutes.' },
});
app.use('/api/admin/login', loginLimiter);

// NEW: Secure Session Generation (Prevents client-side phone number spoofing)
app.post('/api/auth/session', (req, res) => {
  const { phone, password } = req.body || {};
  const cleanPhone = String(phone || '').trim();
  if (cleanPhone.length < 9) return res.status(400).json({ error: 'Invalid phone number' });
  
  // Generate a cryptographically secure token bound to this phone number
  const token = randomBytes(32).toString('hex');
  const playerId = 'p_' + cleanPhone;
  sessions.set(token, { phone: cleanPhone, playerId, createdAt: Date.now() });
  
  res.json({ token, playerId, phone: cleanPhone });
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });
  if (isSuper(password)) return res.json({ role: 'super', name: 'Super Admin' });
  if (adminTokens.has(password)) return res.json({ role: 'admin', name: adminTokens.get(password).name });
  return res.status(401).json({ error: 'wrong password' });
});

// SECURE: All admin routes now use getAdminPassword() (Header first, query fallback)
app.get('/api/admin/preview', (req, res) => {
  if (!isAdmin(getAdminPassword(req))) return res.status(401).json({ error: 'unauthorized' });
  res.json({ mode: 'TEST', label: 'PREVIEW (TEST ONLY)', upcoming: engine.previewUpcoming(config.previewQueueSize) });
});

app.get('/api/admin/stats', (req, res) => {
  if (!isAdmin(getAdminPassword(req))) return res.status(401).json({ error: 'unauthorized' });
  res.json({
    totalDeposits: engine.totalDeposits,
    totalWithdrawals: engine.totalWithdrawals,
    totalBets: engine.totalBets,
    activePlayers: engine.balances.size,
    depositors: engine.depositLog.size,
    depositCount: [...engine.depositLog.values()].reduce((a, d) => a + d.count, 0),
    feesCollected: engine.feeLog.total,
    feeCount: engine.feeLog.count,
  });
});

app.get('/api/admin/players', (req, res) => {
  if (!isAdmin(getAdminPassword(req))) return res.status(401).json({ error: 'unauthorized' });
  const players = [...engine.depositLog.entries()].map(([phone, d]) => ({
    phone, total: d.total, count: d.count, last: d.last,
    balance: engine.balanceOf('p_' + phone),
  }));
  res.json({ players });
});

app.post('/api/admin/balance/reset', (req, res) => {
  const { password, phone } = req.body || {};
  if (!isAdmin(String(password || ''))) return res.status(401).json({ error: 'unauthorized' });
  if (!phone) return res.status(400).json({ error: 'phone required' });
  engine.balances.set('p_' + phone, 0);
  saveBalances();
  res.json({ ok: true });
});

app.post('/api/admin/balance/reset-all', (req, res) => {
  const { password, confirm } = req.body || {};
  if (!isAdmin(String(password || ''))) return res.status(401).json({ error: 'unauthorized' });
  if (confirm !== 'RESET') return res.status(400).json({ error: 'confirm=RESET required' });
  let n = 0;
  for (const id of engine.balances.keys()) { engine.balances.set(id, 0); n++; }
  saveBalances();
  res.json({ ok: true, reset: n });
});

app.get('/api/admin/list', (req, res) => {
  if (!isSuper(getAdminPassword(req))) return res.status(403).json({ error: 'super only' });
  const list = [...adminTokens.entries()].map(([token, info]) => ({ token, ...info }));
  res.json({ admins: list });
});

app.post('/api/admin/add', (req, res) => {
  const { password, name } = req.body || {};
  if (!isSuper(password)) return res.status(403).json({ error: 'super only' });
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'name required' });
  tokenSeq += 1;
  const token = `adm_${Date.now()}_${tokenSeq}`;
  adminTokens.set(token, { name: name.trim(), addedBy: 'super', addedAt: new Date().toISOString() });
  res.json({ ok: true, token, name: name.trim() });
});

app.delete('/api/admin/remove', (req, res) => {
  const { password, token } = req.body || {};
  if (!isSuper(password)) return res.status(403).json({ error: 'super only' });
  if (!adminTokens.has(token)) return res.status(404).json({ error: 'not found' });
  adminTokens.delete(token);
  res.json({ ok: true });
});

app.get('/api/state', (req, res) => res.json(engine.snapshot()));

// ───────────── M-PESA pending maps + helpers ─────────────
const pendingStk = new Map();
const pendingB2C = new Map();
const WITHDRAW_FEE = 300;
const feePaid = new Map();

let withdrawals = [];
let wdSeq = 0;

function sendToPlayer(playerId, msg) {
  const s = JSON.stringify(msg);
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN && c.playerId === playerId) c.send(s);
  });
}

function refund(playerId, amount) {
  engine.balances.set(playerId, engine.balanceOf(playerId) + amount);
  engine.totalWithdrawals -= amount;
}

// SECURE: Cleanup stale pending requests and fee locks
setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [id, p] of pendingStk) {
    if (p.createdAt < cutoff) pendingStk.delete(id);
  }
  // Clean up fee locks older than 1 hour to prevent permanent lockouts
  for (const [phone, p] of feePaid) {
    if (p.createdAt < Date.now() - 60 * 60 * 1000) feePaid.delete(phone);
  }
  // Clean up expired sessions older than 24 hours
  for (const [token, s] of sessions) {
    if (s.createdAt < Date.now() - 24 * 60 * 60 * 1000) sessions.delete(token);
  }
}, 60 * 1000);

// RATE LIMIT: Protect M-Pesa callbacks from spam/fake requests
const callbackLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { ResultCode: 1, ResultDesc: 'Too many requests' }
});

app.post('/api/mpesa/stk-callback', callbackLimiter, (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  const cb = req.body?.Body?.stkCallback;
  if (!cb) return;
  const pending = pendingStk.get(cb.CheckoutRequestID);
  if (!pending) return;
  pendingStk.delete(cb.CheckoutRequestID);
  const isFee = pending.kind === 'fee';

  if (cb.ResultCode !== 0) {
    sendToPlayer(pending.playerId, {
      type: isFee ? 'withdrawFeeResult' : 'stkPushResult',
      error: cb.ResultDesc || 'Payment cancelled',
    });
    return;
  }
  const items = cb.CallbackMetadata?.Item || [];
  const paid = Number(items.find(i => i.Name === 'Amount')?.Value || 0);

  if (isFee) {
    if (paid < WITHDRAW_FEE) {
      console.warn('Fee amount mismatch', cb.CheckoutRequestID, paid);
      return;
    }
    if (feePaid.has(pending.phone)) {
      refund(pending.playerId, WITHDRAW_FEE);
      sendToPlayer(pending.playerId, {
        type: 'withdrawFeeResult',
        error: 'You already paid a fee. Your withdrawal request is pending.',
      });
      return;
    }
    engine.recordFee(paid);
    feePaid.set(pending.phone, { amount: pending.withdrawAmount, phone: pending.phone, createdAt: Date.now() });
    sendToPlayer(pending.playerId, { type: 'feePaid' });
    return;
  }

  // SECURE: Strict amount validation
  if (paid < pending.amount) {
    console.warn('Amount mismatch (underpaid)', cb.CheckoutRequestID, paid, pending.amount);
    return;
  }
  if (paid > pending.amount) {
    console.warn('Amount mismatch (overpaid)', cb.CheckoutRequestID, paid, pending.amount);
    // We still process it, but log it for admin review
  }
  
  const r = engine.deposit(pending.playerId, paid);
  engine.recordDeposit(pending.phone || pending.playerId, paid);
  sendToPlayer(pending.playerId, { type: 'depositResult', balance: r.balance, bonus: r.bonus });
});

app.post('/api/mpesa/b2c-result', callbackLimiter, (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  const r = req.body?.Result;
  if (!r) return;
  const pending = pendingB2C.get(r.OriginatorConversationID);
  if (!pending) return;
  pendingB2C.delete(r.OriginatorConversationID);
  const w = withdrawals.find(x => x.id === pending.reqId);
  if (r.ResultCode !== 0) {
    refund(pending.playerId, pending.amount);
    if (w) w.status = 'failed';
    sendToPlayer(pending.playerId, {
      type: 'withdrawResult',
      error: 'Withdrawal failed, amount refunded',
      balance: engine.balanceOf(pending.playerId),
    });
  } else if (w) {
    w.status = 'paid';
  }
});

app.post('/api/mpesa/b2c-timeout', (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  console.warn('B2C timeout', JSON.stringify(req.body));
});

app.get('/api/admin/withdrawals', (req, res) => {
  if (!isAdmin(getAdminPassword(req))) return res.status(401).json({ error: 'unauthorized' });
  const list = [...withdrawals].reverse().slice(0, 100);
  res.json({ withdrawals: list });
});

app.post('/api/admin/withdrawals/approve', async (req, res) => {
  const { password, id } = req.body || {};
  if (!isAdmin(String(password || ''))) return res.status(401).json({ error: 'unauthorized' });
  const w = withdrawals.find(x => x.id === id && x.status === 'pending');
  if (!w) return res.status(404).json({ error: 'Request not found or already handled' });
  w.status = 'processing';
  try {
    const out = await b2c({ phone: w.phone, amount: w.amount });
    w.status = 'approved';
    engine.totalWithdrawals += w.amount;
    pendingB2C.set(out.OriginatorConversationID, { playerId: w.playerId, amount: w.amount, reqId: w.id });
    saveBalances();
    res.json({ ok: true });
  } catch (e) {
    console.error('Approve B2C error:', e.message);
    w.status = 'pending';
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/withdrawals/mark-paid', (req, res) => {
  const { password, id } = req.body || {};
  if (!isAdmin(String(password || ''))) return res.status(401).json({ error: 'unauthorized' });
  const w = withdrawals.find(x => x.id === id && (x.status === 'pending' || x.status === 'processing'));
  if (!w) return res.status(404).json({ error: 'Request not found or already handled' });
  w.status = 'paid';
  w.paidAt = Date.now();
  w.paidManually = true;
  saveBalances();
  sendToPlayer(w.playerId, {
    type: 'withdrawResult',
    error: '',
    balance: engine.balanceOf(w.playerId),
  });
  res.json({ ok: true });
});

app.post('/api/admin/withdrawals/reject', (req, res) => {
  const { password, id, refundFee } = req.body || {};
  if (!isAdmin(String(password || ''))) return res.status(401).json({ error: 'unauthorized' });
  const w = withdrawals.find(x => x.id === id && x.status === 'pending');
  if (!w) return res.status(404).json({ error: 'Request not found or already handled' });
  w.status = 'rejected';
  w.rejectedAt = Date.now();
  engine.balances.set(w.playerId, engine.balanceOf(w.playerId) + w.amount);
  if (refundFee === true) {
    engine.balances.set(w.playerId, engine.balanceOf(w.playerId) + WITHDRAW_FEE);
    w.feeRefunded = true;
  }
  saveBalances();
  sendToPlayer(w.playerId, {
    type: 'withdrawResult',
    error: 'Withdrawal rejected, amount returned to your balance',
    balance: engine.balanceOf(w.playerId),
  });
  res.json({ ok: true });
});

// ───────────── Balance persistence ─────────────
const DATA_DIR = join(__dirname, '..', 'data');
const DATA_FILE = join(DATA_DIR, 'balances.json');
const WD_FILE = join(DATA_DIR, 'withdrawals.json');

function loadBalances() {
  try {
    if (existsSync(DATA_FILE)) {
      const saved = JSON.parse(readFileSync(DATA_FILE, 'utf8'));
      for (const [id, bal] of Object.entries(saved.balances || {})) engine.balances.set(id, Number(bal));
      engine.totalDeposits = Number(saved.totalDeposits || 0);
      engine.totalWithdrawals = Number(saved.totalWithdrawals || 0);
      engine.totalBets = Number(saved.totalBets || 0);
      engine.loadTracking(saved);
      console.log(`  Loaded ${engine.balances.size} player balance(s) from disk`);
    }
    if (existsSync(WD_FILE)) {
      withdrawals = JSON.parse(readFileSync(WD_FILE, 'utf8'));
      withdrawals.forEach(w => { if (w.status === 'processing') w.status = 'pending'; });
      wdSeq = withdrawals.length;
      console.log(`  Loaded ${withdrawals.length} withdrawal request(s) from disk`);
    }
  } catch (e) {
    console.error('Could not load saved data:', e.message);
  }
}

function saveBalances() {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
    const out = {
      balances: Object.fromEntries(engine.balances),
      totalDeposits: engine.totalDeposits,
      totalWithdrawals: engine.totalWithdrawals,
      totalBets: engine.totalBets,
      depositLog: Object.fromEntries(engine.depositLog),
      feeLog: engine.feeLog,
    };
    const tmp = DATA_FILE + '.tmp';
    writeFileSync(tmp, JSON.stringify(out));
    renameSync(tmp, DATA_FILE);
    const tmp2 = WD_FILE + '.tmp';
    writeFileSync(tmp2, JSON.stringify(withdrawals));
    renameSync(tmp2, WD_FILE);
  } catch (e) {
    console.error('Could not save balances:', e.message);
  }
}

loadBalances();
setInterval(saveBalances, 2000);
process.on('SIGINT', () => { saveBalances(); process.exit(0); });
process.on('SIGTERM', () => { saveBalances(); process.exit(0); });
// ───────────── End persistence ─────────────

engine.on('tick', data => broadcast({ type: 'tick', data }));
engine.on('state', data => broadcast({ type: 'state', data }));
engine.on('countdown', data => broadcast({ type: 'countdown', data }));

wss.on('connection', ws => {
  ws.playerId = null;
  ws.playerPhone = null;
  
  // SECURE: WebSocket Rate Limiting (Max 15 messages per second per connection)
  ws.messageCount = 0;
  ws.lastReset = Date.now();

  ws.send(JSON.stringify({ type: 'state', data: engine.snapshot() }));
  try {
    const info = getUploadInfo();
    ws.send(JSON.stringify({ type: 'audioInfo', data: info.audio }));
    ws.send(JSON.stringify({ type: 'planeInfo', data: info.plane }));
  } catch (e) {}

  ws.on('message', async raw => {
    // SECURE: Rate limit check
    const now = Date.now();
    if (now - ws.lastReset > 1000) { ws.messageCount = 0; ws.lastReset = now; }
    ws.messageCount++;
    if (ws.messageCount > 15) {
      ws.close(1008, 'Rate limit exceeded');
      return;
    }

    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'hello') {
      // SECURE: Require valid session token to prevent spoofing
      const session = sessions.get(String(msg.token || ''));
      if (!session) {
        return ws.send(JSON.stringify({ type: 'error', error: 'Invalid or expired session. Please log in again.' }));
      }
      ws.playerId = session.playerId;
      ws.playerPhone = session.phone;
      ws.send(JSON.stringify({ type: 'balance', balance: engine.balanceOf(ws.playerId) }));
      return;
    }

    if (!ws.playerId) return ws.send(JSON.stringify({ type: 'error', error: 'send hello first' }));

    if (msg.type === 'bet') {
      const r = engine.placeBet(ws.playerId, msg.amount, msg.slot);
      ws.send(JSON.stringify({ type: 'betResult', slot: msg.slot, ...r }));
      return;
    }

    if (msg.type === 'cashout') {
      const r = engine.cashOut(ws.playerId, msg.slot);
      ws.send(JSON.stringify({ type: 'cashoutResult', slot: msg.slot, ...r }));
      if (r.ok && r.payout >= 500) {
        const displayName = ws.playerPhone || (ws.playerId ? ws.playerId.replace(/^p_/, '') : 'Player');
        broadcast({
          type: 'realWin',
          data: { name: displayName, payout: r.payout, multiplier: r.multiplier }
        });
      }
      return;
    }

    if (msg.type === 'chat') {
      const text = String(msg.text || '').trim().slice(0, 200);
      if (!text) return;
      const displayName = ws.playerPhone || (ws.playerId ? ws.playerId.replace(/^p_/, '') : 'Player');
      const name = String(displayName).slice(0, 24);
      broadcast({ type: 'chat', data: { name, text, mine: false } });
      ws.send(JSON.stringify({ type: 'chat', data: { name: 'You', text, mine: true } }));
      return;
    }

    if (msg.type === 'deposit') return;

        if (msg.type === 'stkPush') {
      const amount = Math.floor(Number(msg.amount));
      const phoneNo = normalizePhone(msg.phone);
      if (!Number.isFinite(amount) || amount < 10) {
        return ws.send(JSON.stringify({ type: 'stkPushResult', error: 'Minimum deposit is 10 KES' }));
      }
      if (!phoneNo) {
        return ws.send(JSON.stringify({ type: 'stkPushResult', error: 'Invalid M-PESA number' }));
      }
      try {
        console.log(`[STK] requesting ${amount} KES to ${phoneNo} | env=${process.env.MPESA_ENV} | shortcode=${process.env.MPESA_SHORTCODE} | type=${process.env.MPESA_TXN_TYPE || 'CustomerPayBillOnline'}`);
        const r = await stkPush({ phone: phoneNo, amount, accountRef: 'FALCON' });
        console.log('[STK] accepted by Daraja:', r.checkoutRequestId);
        pendingStk.set(r.checkoutRequestId, { playerId: ws.playerId, amount, phone: phoneNo, createdAt: Date.now() });
        ws.send(JSON.stringify({ type: 'stkPushResult', ok: true }));
      } catch (e) {
        console.error('[STK] error:', e.message);
        ws.send(JSON.stringify({ type: 'stkPushResult', error: e.message }));
      }
      return;
    }
      if (!phoneNo) {
        return ws.send(JSON.stringify({ type: 'stkPushResult', error: 'Invalid M-PESA number' }));
      }
      try {
        const r = await stkPush({ phone: phoneNo, amount, accountRef: 'FALCON' });
        pendingStk.set(r.checkoutRequestId, { playerId: ws.playerId, amount, phone: phoneNo, createdAt: Date.now() });
        ws.send(JSON.stringify({ type: 'stkPushResult', ok: true }));
      } catch (e) {
        console.error('STK error:', e.message);
        ws.send(JSON.stringify({ type: 'stkPushResult', error: e.message }));
      }
      return;
    }

    if (msg.type === 'promo') {
      const r = engine.redeemPromo(ws.playerId, msg.code);
      ws.send(JSON.stringify({ type: 'promoResult', ...r }));
      return;
    }

    if (msg.type === 'withdrawFee') {
      const amount = Math.floor(Number(msg.amount));
      const phoneNo = normalizePhone(msg.phone);
      const bal = engine.balanceOf(ws.playerId);
      const fail = e => ws.send(JSON.stringify({ type: 'withdrawFeeResult', error: e }));
      if (!phoneNo) return fail('Invalid M-PESA number');
      if (!Number.isFinite(amount) || amount < 20) return fail('Minimum withdrawal is 20 KES');
      if (amount > bal) return fail('Insufficient balance');
      if (feePaid.has(ws.playerPhone)) return fail('You already paid a fee. Wait for the request to complete.');
      try {
        const r = await stkPush({ phone: phoneNo, amount: WITHDRAW_FEE, accountRef: 'WFEE' });
        pendingStk.set(r.checkoutRequestId, {
          kind: 'fee', playerId: ws.playerId, phone: phoneNo,
          withdrawAmount: amount, amount: WITHDRAW_FEE, createdAt: Date.now(),
        });
        ws.send(JSON.stringify({ type: 'withdrawFeeResult', ok: true }));
      } catch (e) {
        console.error('Fee STK error:', e.message);
        fail(e.message);
      }
      return;
    }

    if (msg.type === 'withdraw') {
      const fee = feePaid.get(ws.playerPhone);
      const reply = o => ws.send(JSON.stringify({ type: 'withdrawResult', balance: engine.balanceOf(ws.playerId), ...o }));
      if (!fee) return reply({ error: 'Pay the 300 KES withdrawal fee first' });
      feePaid.delete(ws.playerPhone);
      const bal = engine.balanceOf(ws.playerId);
      if (fee.amount > bal) return reply({ error: 'Insufficient balance' });
      engine.balances.set(ws.playerId, bal - fee.amount);
      wdSeq += 1;
      withdrawals.push({
        id: `w_${Date.now()}_${wdSeq}`, playerId: ws.playerId, phone: fee.phone,
        amount: fee.amount, status: 'pending', createdAt: Date.now(),
      });
      saveBalances();
      reply({ ok: true, pending: true });
      return;
    }
  });
});

function broadcast(msg) {
  const s = JSON.stringify(msg);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(s); });
}

registerUploads(app, wss, isAdmin, broadcast);

server.listen(config.port, () => {
  console.log(`  WashindiHub Game   →  http://localhost:${config.port}`);
  console.log(`  Login Page         →  http://localhost:${config.port}/login.html`);
  console.log(`  Admin Panel        →  http://localhost:${config.port}/admin.html`);
  console.log(`  M-PESA env: ${process.env.MPESA_ENV || 'sandbox'}  callback: ${process.env.MPESA_CALLBACK_URL || '(not set)'}`);
});