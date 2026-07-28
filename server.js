const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3456;

// CORS - allow mobile browsers to access API
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// JSON body parser with large payload support
app.use(express.json({ limit: '10mb' }));

// Serve static files (the PWA frontend)
app.use(express.static(__dirname));

// Data directory for sync + accounts storage
const DATA_DIR = path.join(__dirname, '.sync_data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ============================================================
//  ACCOUNT SYSTEM
// ============================================================
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days

// Load accounts
function loadAccounts() {
  try {
    if (fs.existsSync(ACCOUNTS_FILE)) {
      return JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Load accounts error:', e.message);
  }
  return { users: {}, tokens: {} };
}

// Save accounts
function saveAccounts(accts) {
  try {
    fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accts, null, 2));
    return true;
  } catch (e) {
    console.error('Save accounts error:', e.message);
    return false;
  }
}

// Password hashing (PBKDF2 with random salt, 100000 iterations, 64 bytes)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const verify = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return hash === verify;
}

// Generate secure random token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Clean expired tokens
function cleanTokens(accts) {
  const now = Date.now();
  const tokens = accts.tokens || {};
  for (const t of Object.keys(tokens)) {
    if (tokens[t].expiresAt && tokens[t].expiresAt < now) {
      delete tokens[t];
    }
  }
  return tokens;
}

// Auth middleware - verify token
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ ok: false, error: '请先登录' });
  }
  const token = authHeader.slice(7);
  const accts = loadAccounts();
  accts.tokens = accts.tokens || {};

  const tokenData = accts.tokens[token];
  if (!tokenData) {
    return res.status(401).json({ ok: false, error: '登录已过期，请重新登录' });
  }
  if (tokenData.expiresAt && tokenData.expiresAt < Date.now()) {
    delete accts.tokens[token];
    saveAccounts(accts);
    return res.status(401).json({ ok: false, error: '登录已过期，请重新登录' });
  }
  req.username = tokenData.username;
  req.token = token;
  next();
}

// POST /api/auth/register - create account
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: '请输入用户名和密码' });
  }
  if (username.length < 2 || username.length > 30) {
    return res.status(400).json({ ok: false, error: '用户名需要2-30个字符' });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, error: '密码至少需要6个字符' });
  }

  const accts = loadAccounts();
  accts.users = accts.users || {};
  accts.tokens = cleanTokens(accts);

  if (accts.users[username]) {
    return res.status(409).json({ ok: false, error: '该用户名已被注册' });
  }

  accts.users[username] = {
    username: username,
    passwordHash: hashPassword(password),
    createdAt: Date.now()
  };

  saveAccounts(accts);
  console.log('新用户注册:', username);
  res.json({ ok: true, message: '注册成功，请登录' });
});

// POST /api/auth/login - login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: '请输入用户名和密码' });
  }

  const accts = loadAccounts();
  accts.users = accts.users || {};
  accts.tokens = cleanTokens(accts);

  const user = accts.users[username];
  if (!user) {
    return res.status(401).json({ ok: false, error: '用户名或密码错误' });
  }

  if (!verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ ok: false, error: '用户名或密码错误' });
  }

  const token = generateToken();
  accts.tokens[token] = {
    username: username,
    createdAt: Date.now(),
    expiresAt: Date.now() + TOKEN_EXPIRY
  };

  saveAccounts(accts);
  console.log('用户登录:', username);
  res.json({
    ok: true,
    token: token,
    username: username,
    expiresAt: Date.now() + TOKEN_EXPIRY
  });
});

// GET /api/auth/verify - verify token and get current user
app.get('/api/auth/verify', authMiddleware, (req, res) => {
  res.json({ ok: true, username: req.username });
});

// POST /api/auth/logout - logout (invalidate token)
app.post('/api/auth/logout', authMiddleware, (req, res) => {
  const accts = loadAccounts();
  accts.tokens = accts.tokens || {};
  delete accts.tokens[req.token];
  saveAccounts(accts);
  res.json({ ok: true, message: '已退出登录' });
});

// ============================================================
//  SYNC SYSTEM (now protected by auth)
// ============================================================

// Helper: get room file path
function roomFile(roomId) {
  const safe = roomId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return path.join(DATA_DIR, safe + '.json');
}

// Helper: load room data
function loadRoom(roomId) {
  const file = roomFile(roomId);
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch (e) {
    console.error('Load error:', e.message);
  }
  return null;
}

// Helper: save room data
function saveRoom(roomId, data) {
  const file = roomFile(roomId);
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
    return true;
  } catch (e) {
    console.error('Save error:', e.message);
    return false;
  }
}

// GET /api/sync/:roomId — fetch latest data (auth required)
app.get('/api/sync/:roomId', authMiddleware, (req, res) => {
  const data = loadRoom(req.params.roomId);
  if (data) {
    res.json({ ok: true, data: data.db, timestamp: data.ts, version: data.v || 1 });
  } else {
    res.json({ ok: true, data: null, timestamp: 0, version: 0 });
  }
});

// GET /api/sync/data — get all of user's own data (keyed by username)
app.get('/api/sync/data', authMiddleware, (req, res) => {
  const roomId = 'user_' + req.username;
  const data = loadRoom(roomId);
  if (data) {
    res.json({ ok: true, data: data.db, timestamp: data.ts, version: data.v || 1 });
  } else {
    res.json({ ok: true, data: null, timestamp: 0, version: 0 });
  }
});

// POST /api/sync/:roomId — push data (auth required)
app.post('/api/sync/:roomId', authMiddleware, (req, res) => {
  const roomId = req.params.roomId;
  const incoming = req.body;
  if (!incoming || !incoming.db) {
    return res.status(400).json({ ok: false, error: 'Invalid payload: missing db' });
  }

  const existing = loadRoom(roomId);

  if (!existing || (incoming.ts > existing.ts)) {
    const saved = saveRoom(roomId, {
      db: incoming.db,
      ts: incoming.ts,
      v: incoming.v || ((existing ? existing.v : 0) + 1)
    });
    return res.json({ ok: true, updated: true, version: incoming.v || 1 });
  }

  const merged = deepMerge(existing.db, incoming.db);
  const newVersion = (existing.v || 0) + 1;

  saveRoom(roomId, {
    db: merged,
    ts: Date.now(),
    v: newVersion
  });

  return res.json({ ok: true, updated: true, version: newVersion, merged: true });
});

// POST /api/sync/data — save own data (keyed by username, auto-sync for multi-device)
app.post('/api/sync/data', authMiddleware, (req, res) => {
  const roomId = 'user_' + req.username;
  const incoming = req.body;
  if (!incoming || !incoming.db) {
    return res.status(400).json({ ok: false, error: 'Invalid payload: missing db' });
  }

  const existing = loadRoom(roomId);

  if (!existing || (incoming.ts > existing.ts)) {
    saveRoom(roomId, {
      db: incoming.db,
      ts: incoming.ts,
      v: incoming.v || ((existing ? existing.v : 0) + 1)
    });
    // Also store who last pushed
    saveRoom(roomId + '_meta', { lastPushedBy: req.username, lastPushedAt: Date.now() });
    return res.json({ ok: true, updated: true, version: incoming.v || 1 });
  }

  const merged = deepMerge(existing.db, incoming.db);
  const newVersion = (existing.v || 0) + 1;

  saveRoom(roomId, {
    db: merged,
    ts: Date.now(),
    v: newVersion
  });
  saveRoom(roomId + '_meta', { lastPushedBy: req.username, lastPushedAt: Date.now() });

  return res.json({ ok: true, updated: true, version: newVersion, merged: true });
});

// POST /api/sync/:roomId/create — create a room (auth required)
app.post('/api/sync/:roomId/create', authMiddleware, (req, res) => {
  const roomId = req.params.roomId;
  const existing = loadRoom(roomId);
  if (existing) {
    return res.json({ ok: true, exists: true, version: existing.v || 1 });
  }
  saveRoom(roomId, {
    db: req.body.db || {},
    ts: Date.now(),
    v: 1
  });
  return res.json({ ok: true, created: true, version: 1 });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// Simple deep merge: incoming wins on conflict
function deepMerge(base, incoming) {
  if (!base || typeof base !== 'object') return incoming;
  if (!incoming || typeof incoming !== 'object') return incoming;

  const result = { ...base };

  for (const key of Object.keys(incoming)) {
    const baseVal = base[key];
    const incVal = incoming[key];

    if (Array.isArray(incVal)) {
      if (Array.isArray(baseVal) && incVal.length > 0 && incVal[0] && typeof incVal[0].id !== 'undefined') {
        const merged = [...baseVal];
        const baseIds = new Map(merged.map((x, i) => [x.id, i]));
        for (const item of incVal) {
          if (item && typeof item.id !== 'undefined') {
            const idx = baseIds.get(item.id);
            if (idx !== undefined) {
              merged[idx] = item;
            } else {
              merged.push(item);
              baseIds.set(item.id, merged.length - 1);
            }
          }
        }
        result[key] = merged;
      } else {
        result[key] = incVal;
      }
    } else if (incVal && typeof incVal === 'object' && !Array.isArray(incVal)) {
      result[key] = deepMerge(baseVal || {}, incVal);
    } else {
      result[key] = incVal;
    }
  }

  return result;
}

// ============================================================
//  DEFAULT ADMIN — ensures an account always exists
//  (Render free tier restarts wipe the filesystem)
// ============================================================
const DEFAULT_ADMIN = process.env.ADMIN_USER || 'admin';
const DEFAULT_PASS  = process.env.ADMIN_PASS || 'scx888888';

function ensureDefaultAdmin() {
  const accts = loadAccounts();
  accts.users = accts.users || {};
  const existing = Object.keys(accts.users);
  if (existing.length === 0) {
    accts.users[DEFAULT_ADMIN] = {
      username: DEFAULT_ADMIN,
      passwordHash: hashPassword(DEFAULT_PASS),
      createdAt: Date.now()
    };
    saveAccounts(accts);
    console.log('已创建默认管理员: ' + DEFAULT_ADMIN);
  }
}
ensureDefaultAdmin();

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log('  蜀川鑫同步服务已启动');
  console.log('  地址: http://0.0.0.0:' + PORT);
  console.log('  API:');
  console.log('    注册: POST /api/auth/register');
  console.log('    登录: POST /api/auth/login');
  console.log('    验证: GET  /api/auth/verify');
  console.log('    同步: GET/POST /api/sync/:roomId');
  console.log('    个人数据: GET/POST /api/sync/data');
  console.log('========================================');
});
