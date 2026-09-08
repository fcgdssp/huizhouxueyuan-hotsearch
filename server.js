// server.js —— 「惠院热搜」后端
// 作用：跑一个本地服务器，用 SQLite 存数据，给前端提供接口。
// 启动：node server.js
// 访问：主页面 http://localhost:3000  后台 http://localhost:3000/admin.html

const express = require('express');
const path = require('path');
const crypto = require('crypto'); // Node 内置，用来给密码做哈希
const { DatabaseSync } = require('node:sqlite'); // Node 24 内置的 SQLite，无需额外安装
const SEED_ITEMS = require('./seed.json'); // 初始热搜，从 seed.json 读取

const app = express();
const PORT = process.env.PORT || 3000; // 可用 PORT=3001 node server.js 换端口

app.use(express.json());            // 解析请求里的 JSON 数据
app.use(express.static('public'));  // 托管 public/ 文件夹（主页面、后台都在里面）

// ---------- 数据库：打开（不存在会自动创建 data.db） ----------
const db = new DatabaseSync(path.join(__dirname, 'data.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cat TEXT NOT NULL,
    title TEXT NOT NULL,
    tuan INTEGER NOT NULL DEFAULT 0,
    mark TEXT NOT NULL DEFAULT '',
    badge TEXT NOT NULL DEFAULT '',
    badgeColor TEXT NOT NULL DEFAULT '',
    views TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    labelColor TEXT NOT NULL DEFAULT '',
    extra TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    clicks INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    status INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'normal',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
`);

// 兼容旧数据库：如果缺列就补上（不丢已有数据）
(function migrate() {
  const itemCols = db.prepare('PRAGMA table_info(items)').all().map(function (c) { return c.name; });
  if (itemCols.indexOf('sort_order') < 0) {
    db.exec('ALTER TABLE items ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0');
    db.exec('UPDATE items SET sort_order = id'); // 老数据按原 id 回填顺序
  }
  const msgCols = db.prepare('PRAGMA table_info(messages)').all().map(function (c) { return c.name; });
  if (msgCols.indexOf('status') < 0) {
    db.exec('ALTER TABLE messages ADD COLUMN status INTEGER NOT NULL DEFAULT 0');
  }
  const userCols = db.prepare('PRAGMA table_info(users)').all().map(function (c) { return c.name; });
  if (userCols.indexOf('role') < 0) {
    db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'normal'");
  }
  db.exec("UPDATE users SET role='super' WHERE username='admin'"); // 确保 admin 永远是超级管理员
})();



function seedIfEmpty() {
  const c = db.prepare('SELECT COUNT(*) AS c FROM items').get().c;
  if (c !== 0) return;
  const ins = db.prepare(
    'INSERT INTO items (id, cat, title, tuan, mark, badge, badgeColor, views, label, labelColor, extra, link, detail, sort_order) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  );
  SEED_ITEMS.forEach(function (it, idx) {
    ins.run(it.id, it.cat, it.title, it.to ? 1 : 0, it.mark || '', it.badge || '', it.badgeColor || '',
      it.views || '', it.label || '', it.labelColor || '', it.extra || '', it.link || '', it.detail || '', idx);
  });
  console.log('已导入 ' + SEED_ITEMS.length + ' 条热搜到数据库');
}
seedIfEmpty();

// ---------- 密码哈希（学习点：密码不能明文存，要用「盐 + 哈希」） ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');         // 随机盐，让同样的密码也有不同哈希
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex'); // 用 scrypt 算出 64 字节哈希
  return salt + ':' + hash;   // 存成「盐:哈希」
}
function verifyPassword(pw, stored) {
  const parts = String(stored).split(':');
  if (parts.length !== 2) return false;
  const salt = parts[0];
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  const a = Buffer.from(parts[1], 'hex');
  const b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b); // 恒定时间比较，防时序攻击
}

// 首次运行：没有管理员时，建一个默认账号 admin / admin123
if (db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0) {
  db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'super')").run('admin', hashPassword('admin123'));
  console.log('已创建默认管理员：admin / admin123（登录后请尽快改密码）');
}

// 数据库行 → 前端用的对象（把 tuan 转回 to，补 clicks）
function rowToItem(row) {
  return {
    id: row.id, cat: row.cat, title: row.title,
    to: !!row.tuan, mark: row.mark, badge: row.badge, badgeColor: row.badgeColor,
    views: row.views, label: row.label, labelColor: row.labelColor,
    extra: row.extra, link: row.link, detail: row.detail, clicks: row.clicks
  };
}

// ---------- 权限中间件：检查请求里的 token，没登录就拒绝 ----------
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ ok: false, msg: '未登录' });
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if (!s) return res.status(401).json({ ok: false, msg: '登录已失效，请重新登录' });
  req.user = db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id);
  next();
}

// 超级管理员专属：只有 role='super' 才放行
function requireSuper(req, res, next) {
  if (!req.user || req.user.role !== 'super') {
    return res.status(403).json({ ok: false, msg: '没有权限，只有超级管理员能操作' });
  }
  next();
}

// ---------- 接口（API） ----------

// 登录（公开）：用户名+密码 → 校验 → 发一个 token（存进 sessions 表）
app.post('/api/login', (req, res) => {
  const b = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get((b.username || '').trim());
  if (!u || !verifyPassword(b.password || '', u.password_hash)) {
    return res.status(401).json({ ok: false, msg: '用户名或密码错误' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, u.id);
  res.json({ ok: true, token: token, username: u.username, role: u.role });
});

// 登出（需登录）：删掉当前 token
app.post('/api/logout', requireAuth, (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  db.prepare('DELETE FROM sessions WHERE token=?').run(token);
  res.json({ ok: true });
});

// 当前登录用户（需登录）
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, username: req.user.username, role: req.user.role });
});

// 管理员列表（需登录）
app.get('/api/users', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all());
});

// 添加管理员（需登录）
app.post('/api/users', requireAuth, requireSuper, (req, res) => {
  const b = req.body || {};
  const uname = (b.username || '').trim();
  const pw = b.password || '';
  if (!uname || !pw) return res.status(400).json({ ok: false, msg: '账号和密码不能为空' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(uname)) {
    return res.status(400).json({ ok: false, msg: '账号已存在' });
  }
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(uname, hashPassword(pw));
  res.json({ ok: true });
});

// 修改自己的密码（需登录）
app.put('/api/users/password', requireAuth, (req, res) => {
  const pw = (req.body || {}).password || '';
  if (!pw) return res.status(400).json({ ok: false, msg: '密码不能为空' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(pw), req.user.id);
  res.json({ ok: true });
});

// 删除管理员（需超级管理员）
app.delete('/api/users/:id', requireAuth, requireSuper, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ ok: false, msg: '不能删除自己' });
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!target) return res.status(404).json({ ok: false, msg: '账号不存在' });
  if (target.role === 'super') return res.status(400).json({ ok: false, msg: '不能删除超级管理员' });
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);
  res.json({ ok: true });
});

// 热搜：查全部
app.get('/api/items', (req, res) => {
  const rows = db.prepare('SELECT * FROM items ORDER BY sort_order, id').all();
  res.json(rows.map(rowToItem));
});

// 热搜：新增
app.post('/api/items', requireAuth, (req, res) => {
  const b = req.body || {};
  const max = db.prepare('SELECT MAX(sort_order) AS m FROM items').get().m || 0;
  const info = db.prepare(
    'INSERT INTO items (cat, title, tuan, mark, badge, badgeColor, views, label, labelColor, extra, link, detail, sort_order) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(b.cat || '', b.title || '', b.to ? 1 : 0, b.mark || '', b.badge || '', b.badgeColor || '',
    b.views || '', b.label || '', b.labelColor || '', b.extra || '', b.link || '', b.detail || '', max + 1);
  res.json({ ok: true, id: info.lastInsertRowid });
});

// 热搜：修改
app.put('/api/items/:id', requireAuth, (req, res) => {
  const b = req.body || {};
  db.prepare(
    'UPDATE items SET cat=?, title=?, tuan=?, mark=?, badge=?, badgeColor=?, views=?, label=?, labelColor=?, extra=?, link=?, detail=? WHERE id=?'
  ).run(b.cat || '', b.title || '', b.to ? 1 : 0, b.mark || '', b.badge || '', b.badgeColor || '',
    b.views || '', b.label || '', b.labelColor || '', b.extra || '', b.link || '', b.detail || '', req.params.id);
  res.json({ ok: true });
});

// 热搜：删除
app.delete('/api/items/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM items WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// 热搜：点击量 +1（前端点词条时调用）
app.post('/api/items/:id/click', (req, res) => {
  db.prepare('UPDATE items SET clicks = clicks + 1 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// 热搜：上移 / 下移 / 置顶（在同一分类内调整顺序）
app.post('/api/items/:id/move', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const dir = (req.body && req.body.dir) || 'up';
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(id);
  if (!it) return res.json({ ok: false });
  const cat = it.cat;

  if (dir === 'top') {
    const min = db.prepare('SELECT MIN(sort_order) AS m FROM items WHERE cat=?').get(cat).m;
    db.prepare('UPDATE items SET sort_order=? WHERE id=?').run((min == null ? 0 : min) - 1, id);
  } else if (dir === 'up') {
    const prev = db.prepare('SELECT * FROM items WHERE cat=? AND sort_order < ? ORDER BY sort_order DESC, id DESC LIMIT 1').get(cat, it.sort_order);
    if (prev) {
      db.prepare('UPDATE items SET sort_order=? WHERE id=?').run(prev.sort_order, id);
      db.prepare('UPDATE items SET sort_order=? WHERE id=?').run(it.sort_order, prev.id);
    }
  } else if (dir === 'down') {
    const next = db.prepare('SELECT * FROM items WHERE cat=? AND sort_order > ? ORDER BY sort_order ASC, id ASC LIMIT 1').get(cat, it.sort_order);
    if (next) {
      db.prepare('UPDATE items SET sort_order=? WHERE id=?').run(next.sort_order, id);
      db.prepare('UPDATE items SET sort_order=? WHERE id=?').run(it.sort_order, next.id);
    }
  }
  res.json({ ok: true });
});

// 留言：查全部
app.get('/api/messages', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM messages ORDER BY id DESC').all());
});

// 留言：提交
app.post('/api/messages', (req, res) => {
  const b = req.body || {};
  const info = db.prepare('INSERT INTO messages (name, content) VALUES (?, ?)')
    .run(b.name || '匿名', (b.content || '').trim());
  res.json({ ok: true, id: info.lastInsertRowid });
});

// 留言：删除
app.delete('/api/messages/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM messages WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// 留言：切换「已处理/未处理」状态
app.post('/api/messages/:id/toggle', requireAuth, (req, res) => {
  db.prepare('UPDATE messages SET status = 1 - status WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log('惠院热搜后端已启动：');
  console.log('  主页面 http://localhost:' + PORT);
  console.log('  后台   http://localhost:' + PORT + '/admin.html');
});
