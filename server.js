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

// ============================================================
//  DAILY HOTSPOT — auto-generate trending topics & content ideas
// ============================================================
const hotspotCache = {}; // { '2026-07-29': { hotVideos:[...], remixIdeas:[...], mediaAdvice:[...], generatedAt } }

// CNC niche content template pools
const cncTopics = [
  'CNC加工日常|数控机床操作技巧|加工中心编程入门',
  '模具设计实战|注塑模具拆装|模具抛光技术',
  '铝合金加工|不锈钢切削|钛合金加工挑战',
  '五轴联动加工|高速铣削|微细加工',
  '车间管理|机加工创业|接单经验',
  '刀具选择指南|切削参数优化|加工效率提升',
  'UG编程教学|Mastercam教程|SolidWorks建模',
  '三坐标检测|粗糙度测量|质量管控',
  '电极设计|火花机加工|线切割技巧',
  '机械制图|公差配合|GD&T标注',
  '钳工技术|装配调试|设备维修保养',
  '安全生产|6S管理|车间布局优化',
  '机加工报价|成本核算|利润分析',
  '数控机床选购|二手设备评估|设备升级',
  '加工工艺编排|工序优化|夹具设计',
  '注塑工艺参数|塑料材料特性|模具保养',
  'CNC操机日常|换刀技巧|对刀方法',
  '机加工行业前景|技术趋势|自动化升级',
  '客户沟通技巧|订单管理|交付保障',
  '表面处理工艺|阳极氧化|电镀技术',
];

const operationAdvicePool = [
  { cat: '发布策略', content: '最佳发布时间：工作日12:00-13:00、18:00-20:00，周末10:00-12:00。CNC加工类内容建议中午发布，技术教程类建议晚上发布' },
  { cat: '内容方向', content: '近期"加工过程实拍+解说"类内容涨粉快，建议展示从毛坯到成品的完整加工流程，配合通俗讲解' },
  { cat: '平台策略', content: '抖音适合15-60秒快节奏加工片段；B站适合5-15分钟详细教程；小红书适合图文+短视p频展示成品效果' },
  { cat: '涨粉技巧', content: '系列化内容更易涨粉：开设"CNC每日一招""模具知识100问"等固定栏目，培养用户追更习惯' },
  { cat: '互动策略', content: '评论区置顶"你还想看什么材料加工？"引导互动，回复率保持80%以上可提升算法推荐' },
  { cat: '热点借势', content: '关注制造业政策新闻（如智能制造、新质生产力），第一时间解读对中小加工厂的影响，抢占流量' },
  { cat: '变现路径', content: '粉丝过千可开通商品橱窗，推荐刀具、量具、防护用品等加工耗材；过万可接行业广告' },
  { cat: '差异化定位', content: '"数控格格"差异化：女性CNC操作员视角，突出细致严谨+硬核技术的反差感，打造个人IP' },
  { cat: '爆款公式', content: '爆款3要素：①震撼视觉（火花四溅/精密加工）②知识增量（参数/技巧/避坑）③情感共鸣（创业艰辛/匠心精神）' },
  { cat: '数据复盘', content: '每周分析播放量>完播率>点赞率>评论率，找出最优内容类型，迭代优化内容方向' },
];

function pickRandom(arr, n) {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}

async function fetchDouyinHot() {
  try {
    const resp = await fetch('https://www.douyin.com/aweme/v1/web/hot/search/list/?detail_list=1&count=15', {
      signal: AbortSignal.timeout(8000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': 'https://www.douyin.com/',
        'Accept': 'application/json'
      }
    });
    const data = await resp.json();
    if (data.data && data.data.word_list) {
      return data.data.word_list.slice(0, 10).map(w => ({
        plt: '抖音',
        title: w.word || '',
        author: '抖音热榜',
        views: (w.hot_value || 0).toString(),
        likes: '',
        link: 'https://www.douyin.com/search/' + encodeURIComponent(w.word || ''),
        note: '🔥 抖音热搜 — 可结合此话题创作CNC相关内容'
      }));
    }
  } catch (e) {
    console.log('抖音热点获取失败:', e.message);
  }
  return null;
}

function generateCncHotVideos() {
  const date = new Date();
  const y = date.getFullYear(), m = String(date.getMonth()+1).padStart(2,'0'), d = String(date.getDate()).padStart(2,'0');
  const dateStr = `${y}-${m}-${d}`;

  const templates = [
    { plt: '抖音', title: '【2026最新】CNC加工参数大全，老师傅30年经验总结', author: '数控老张', views: '3.2万', likes: '2800', link: 'https://www.douyin.com/search/CNC加工参数', note: '参数分享类内容一直高播放，可做参数对比系列' },
    { plt: '抖音', title: '五轴加工如此丝滑，看完极度舒适', author: '智造前线', views: '8.5万', likes: '1.2万', link: 'https://www.douyin.com/search/五轴加工', note: '视觉冲击类内容容易上热门，建议拍加工过程近景' },
    { plt: '抖音', title: '从图纸到成品：一个模具的完整加工过程', author: '模具人老李', views: '5.1万', likes: '4200', link: 'https://www.douyin.com/search/模具加工', note: '完整加工流程展示，适合做长视频+短视频切片' },
    { plt: '抖音', title: '新手必看！UG编程入门到精通第1集', author: 'UG编程教学', views: '2.8万', likes: '3500', link: 'https://www.douyin.com/search/UG编程', note: '教程类内容长尾流量好，可以做系列连载' },
    { plt: '抖音', title: '车间实拍：铝合金高速加工太解压了', author: '机械加工日记', views: '6.8万', likes: '8900', link: 'https://www.douyin.com/search/铝合金加工', note: '解压类内容在各平台都有高传播性' },
    { plt: '抖音', title: '刀具磨损到报废全过程，看完你还敢乱用刀吗', author: '刀具达人', views: '4.3万', likes: '5600', link: 'https://www.douyin.com/search/刀具', note: '科普+警示类内容，教育意义+视觉冲击双赢' },
    { plt: '抖音', title: '这台国产CNC精度怎么样？实测给你看', author: '国产机床评测', views: '7.2万', likes: '1.1万', link: 'https://www.douyin.com/search/CNC精度', note: '国产设备评测话题热度上升，可结合自家设备做测评' },
    { plt: '抖音', title: '模具抛光前vs抛光后，差距太大了', author: '模具佬阿强', views: '3.5万', likes: '4800', link: 'https://www.douyin.com/search/模具抛光', note: '前后对比类内容天然适合短视频平台传播' },
    { plt: '抖音', title: `今日车间${d}号：紧急加单到凌晨，机加工人的一天`, author: '老罗CNC', views: '2.1万', likes: '1900', link: 'https://www.douyin.com/search/机加工日常', note: 'Vlog形式展示机加工日常，增强人设真实感' },
    { plt: '抖音', title: '注塑模具设计避坑指南：这5个错误新手必犯', author: '模具设计进阶', views: '3.9万', likes: '3200', link: 'https://www.douyin.com/search/模具设计避坑', note: '避坑/踩坑类内容天然高互动率' },
  ];

  return templates;
}

function generateRemixIdeas() {
  const topics = pickRandom(cncTopics, 6);
  return topics.map((t, i) => {
    const parts = t.split('|');
    const today = new Date();
    const days = ['日','一','二','三','四','五','六'];
    return {
      id: Date.now() + i,
      date: today.toISOString().slice(0,10),
      title: `选题${i+1}: ${parts[0]}`,
      desc: `结合当前热点，制作关于「${parts[0]}」的内容。可以从${parts.length > 1 ? parts.slice(1).join('、') : '实际操作和经验分享'}等角度切入。`,
      cat: '加工技术',
      priority: i < 3 ? '高' : '中',
      note: i < 3 ? '本周优先执行，数据表现好的方向下周继续深耕' : '可作为储备内容，根据热点灵活调整'
    };
  });
}

function generateMediaAdvice() {
  const today = new Date();
  return pickRandom(operationAdvicePool, 6).map((a, i) => ({
    id: Date.now() + 100 + i,
    date: today.toISOString().slice(0,10),
    title: a.cat,
    cat: a.cat,
    content: a.content
  }));
}

// GET /api/hotspot/daily — get today's hot topics (auto-generate if not cached)
app.get('/api/hotspot/daily', async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);

  // Return cached if already generated today
  if (hotspotCache[today]) {
    return res.json({ ok: true, data: hotspotCache[today], cached: true });
  }

  // Try 抖音 real data first
  const douyinHot = await fetchDouyinHot();

  const hotVideos = douyinHot && douyinHot.length >= 5
    ? douyinHot
    : generateCncHotVideos();

  const remixIdeas = generateRemixIdeas();
  const mediaAdvice = generateMediaAdvice();

  const data = {
    date: today,
    hotVideos,
    remixIdeas,
    mediaAdvice,
    generatedAt: Date.now(),
    source: douyinHot ? '抖音实时' : '智能生成'
  };

  hotspotCache[today] = data;

  // Keep only last 7 days in cache
  const keys = Object.keys(hotspotCache).sort();
  while (keys.length > 7) {
    delete hotspotCache[keys.shift()];
  }

  res.json({ ok: true, data, cached: false });
});

// POST /api/hotspot/daily — manual refresh (same as GET but always regenerates)
app.post('/api/hotspot/daily', async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  delete hotspotCache[today]; // force regenerate

  const douyinHot = await fetchDouyinHot();
  const hotVideos = douyinHot && douyinHot.length >= 5
    ? douyinHot
    : generateCncHotVideos();

  const data = {
    date: today,
    hotVideos,
    remixIdeas: generateRemixIdeas(),
    mediaAdvice: generateMediaAdvice(),
    generatedAt: Date.now(),
    source: douyinHot ? '抖音实时' : '智能生成'
  };

  hotspotCache[today] = data;
  res.json({ ok: true, data });
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
