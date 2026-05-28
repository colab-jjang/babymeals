/**
 * 이유식 큐브 현황 - Cloudflare Worker API
 * 이메일/비밀번호 로그인 + JWT 인증
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
function err(msg, status = 400) { return json({ error: msg }, status); }

// ── JWT (간단한 HMAC-SHA256 구현) ──
async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function b64url(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

async function makeJWT(payload, secret) {
  const header = b64url({ alg: 'HS256', typ: 'JWT' });
  const body = b64url(payload);
  const sig = await hmacSign(secret, `${header}.${body}`);
  return `${header}.${body}.${sig}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expected = await hmacSign(secret, `${header}.${body}`);
    if (sig !== expected) return null;
    const payload = JSON.parse(atob(body.replace(/-/g,'+').replace(/_/g,'/')));
    if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

// ── 비밀번호 해싱 (SHA-256 기반) ──
async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function randomSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ── DB 초기화 ──
let dbInitialized = false;
async function initDB(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS babies (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      bday TEXT,
      avatar TEXT DEFAULT '👶',
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS cubes (
      id TEXT PRIMARY KEY,
      baby_id TEXT,
      user_id TEXT,
      name TEXT NOT NULL,
      emoji TEXT DEFAULT '🍱',
      cat_id TEXT NOT NULL,
      qty REAL DEFAULT 0,
      weight TEXT DEFAULT '',
      unit TEXT DEFAULT 'g',
      made_date TEXT,
      expire_date TEXT,
      allergy TEXT DEFAULT 'unknown',
      particle INTEGER DEFAULT 0,
      note TEXT DEFAULT '',
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      emoji TEXT DEFAULT '📦',
      color TEXT DEFAULT '#D4537E',
      is_default INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS history (
      id TEXT PRIMARY KEY,
      baby_id TEXT,
      user_id TEXT,
      cube_name TEXT NOT NULL,
      emoji TEXT DEFAULT '🍱',
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      memo TEXT DEFAULT '',
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS settings (
      user_id TEXT PRIMARY KEY,
      active_baby_id TEXT,
      theme_idx INTEGER DEFAULT 0,
      updated_at INTEGER DEFAULT (unixepoch())
    )`),
  ]);
}

async function ensureDefaultCategories(db, userId) {
  const existing = await db.prepare('SELECT id FROM categories WHERE user_id = ? LIMIT 1').bind(userId).first();
  if (!existing) {
    const defaults = [
      { id: 'veg', name: '채소', emoji: '🥦', color: '#1D9E75' },
      { id: 'fruit', name: '과일', emoji: '🍎', color: '#D85A30' },
      { id: 'grain', name: '곡물/죽', emoji: '🌾', color: '#EF9F27' },
      { id: 'protein', name: '단백질', emoji: '🥩', color: '#D4537E' },
      { id: 'fish', name: '해산물', emoji: '🐟', color: '#378ADD' },
      { id: 'dairy', name: '유제품/기타', emoji: '🧀', color: '#7F77DD' },
    ];
    await db.batch(defaults.map(c =>
      db.prepare('INSERT OR IGNORE INTO categories (id, user_id, name, emoji, color, is_default) VALUES (?,?,?,?,?,1)')
        .bind(`${userId}_${c.id}`, userId, c.name, c.emoji, c.color)
    ));
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') return new Response(null, { headers: CORS });

    if (!dbInitialized) { await initDB(env.DB); dbInitialized = true; }

    const JWT_SECRET = env.JWT_SECRET || 'baby-cube-secret-2024';

    try {
      if (path === '/api/ping') return json({ ok: true });

      // ── 회원가입 ──
      if (path === '/api/auth/register' && method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return err('이메일과 비밀번호를 입력해주세요');
        if (password.length < 6) return err('비밀번호는 6자 이상이어야 해요');
        const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
        if (existing) return err('이미 가입된 이메일이에요');
        const salt = randomSalt();
        const hash = await hashPassword(password, salt);
        const userId = 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2,6);
        await env.DB.prepare('INSERT INTO users (id, email, password_hash, salt) VALUES (?,?,?,?)')
          .bind(userId, email.toLowerCase(), hash, salt).run();
        const token = await makeJWT({ sub: userId, email: email.toLowerCase(), exp: Math.floor(Date.now()/1000) + 86400*365 }, JWT_SECRET);
        return json({ ok: true, token, userId });
      }

      // ── 로그인 ──
      if (path === '/api/auth/login' && method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return err('이메일과 비밀번호를 입력해주세요');
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
        if (!user) return err('이메일 또는 비밀번호가 틀렸어요');
        const hash = await hashPassword(password, user.salt);
        if (hash !== user.password_hash) return err('이메일 또는 비밀번호가 틀렸어요');
        const token = await makeJWT({ sub: user.id, email: user.email, exp: Math.floor(Date.now()/1000) + 86400*365 }, JWT_SECRET);
        return json({ ok: true, token, userId: user.id });
      }

      // ── 이후 모든 API는 JWT 인증 필요 ──
      const authHeader = request.headers.get('Authorization');
      const token = authHeader?.replace('Bearer ', '');
      if (!token) return err('로그인이 필요해요', 401);
      const payload = await verifyJWT(token, JWT_SECRET);
      if (!payload) return err('인증이 만료됐어요. 다시 로그인해주세요', 401);
      const userId = payload.sub;

      // ── init ──
      if (path === '/api/init' && method === 'GET') {
        await ensureDefaultCategories(env.DB, userId);
        const [babiesR, catsR, settingsR] = await Promise.all([
          env.DB.prepare('SELECT * FROM babies WHERE user_id = ? ORDER BY created_at').bind(userId).all(),
          env.DB.prepare('SELECT * FROM categories WHERE user_id = ? ORDER BY is_default DESC, created_at').bind(userId).all(),
          env.DB.prepare('SELECT * FROM settings WHERE user_id = ?').bind(userId).first(),
        ]);
        const babies = babiesR.results;
        const cats = catsR.results.map(r => ({ ...r, id: r.id.replace(`${userId}_`, '') }));
        const settings = settingsR || { user_id: userId, active_baby_id: null, theme_idx: 0 };
        const activeBabyId = settings.active_baby_id || babies[0]?.id || null;
        const [cubesR, histR] = await Promise.all([
          activeBabyId
            ? env.DB.prepare('SELECT * FROM cubes WHERE baby_id = ? ORDER BY created_at').bind(activeBabyId).all()
            : env.DB.prepare('SELECT * FROM cubes WHERE user_id = ? ORDER BY created_at').bind(userId).all(),
          activeBabyId
            ? env.DB.prepare('SELECT * FROM history WHERE baby_id = ? ORDER BY created_at DESC LIMIT 100').bind(activeBabyId).all()
            : env.DB.prepare('SELECT * FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').bind(userId).all(),
        ]);
        return json({ babies, categories: cats, settings, cubes: cubesR.results, history: histR.results });
      }

      // ── settings ──
      if (path === '/api/settings') {
        if (method === 'GET') {
          const row = await env.DB.prepare('SELECT * FROM settings WHERE user_id = ?').bind(userId).first();
          return json(row || { user_id: userId, active_baby_id: null, theme_idx: 0 });
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare(`INSERT INTO settings (user_id, active_baby_id, theme_idx, updated_at) VALUES (?,?,?,unixepoch())
            ON CONFLICT(user_id) DO UPDATE SET active_baby_id=excluded.active_baby_id, theme_idx=excluded.theme_idx, updated_at=unixepoch()`)
            .bind(userId, body.active_baby_id ?? null, body.theme_idx ?? 0).run();
          return json({ ok: true });
        }
      }

      // ── babies ──
      if (path === '/api/babies') {
        if (method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM babies WHERE user_id = ? ORDER BY created_at').bind(userId).all();
          return json(rows.results);
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare('INSERT OR REPLACE INTO babies (id, user_id, name, bday, avatar) VALUES (?,?,?,?,?)')
            .bind(body.id, userId, body.name, body.bday || null, body.avatar || '👶').run();
          await env.DB.prepare(`INSERT INTO settings (user_id, active_baby_id, theme_idx) VALUES (?,?,0)
            ON CONFLICT(user_id) DO UPDATE SET active_baby_id=COALESCE(active_baby_id, excluded.active_baby_id)`)
            .bind(userId, body.id).run();
          return json({ ok: true });
        }
      }
      const babyMatch = path.match(/^\/api\/babies\/([^/]+)$/);
      if (babyMatch) {
        const bid = babyMatch[1];
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM babies WHERE id = ? AND user_id = ?').bind(bid, userId).run();
          return json({ ok: true });
        }
      }

      // ── categories ──
      if (path === '/api/categories') {
        await ensureDefaultCategories(env.DB, userId);
        if (method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM categories WHERE user_id = ? ORDER BY is_default DESC, created_at').bind(userId).all();
          const clean = rows.results.map(r => ({ ...r, id: r.id.replace(`${userId}_`, '') }));
          return json(clean);
        }
        if (method === 'POST') {
          const body = await request.json();
          const realId = `${userId}_${body.id}`;
          await env.DB.prepare('INSERT OR REPLACE INTO categories (id, user_id, name, emoji, color, is_default) VALUES (?,?,?,?,?,?)')
            .bind(realId, userId, body.name, body.emoji, body.color, body.is_default ? 1 : 0).run();
          return json({ ok: true });
        }
      }
      const catMatch = path.match(/^\/api\/categories\/([^/]+)$/);
      if (catMatch) {
        const cid = `${userId}_${catMatch[1]}`;
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').bind(cid, userId).run();
          return json({ ok: true });
        }
      }

      // ── cubes ──
      if (path === '/api/cubes') {
        if (method === 'GET') {
          const babyId = url.searchParams.get('baby_id');
          const rows = babyId
            ? await env.DB.prepare('SELECT * FROM cubes WHERE baby_id = ? ORDER BY created_at').bind(babyId).all()
            : await env.DB.prepare('SELECT * FROM cubes WHERE user_id = ? ORDER BY created_at').bind(userId).all();
          return json(rows.results);
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare(`INSERT OR REPLACE INTO cubes (id, baby_id, user_id, name, emoji, cat_id, qty, weight, unit, made_date, expire_date, allergy, particle, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(body.id, body.baby_id||null, userId, body.name, body.emoji, body.cat_id, body.qty, body.weight||'', body.unit||'g', body.made_date||null, body.expire_date||null, body.allergy||'unknown', body.particle||0, body.note||'').run();
          return json({ ok: true });
        }
      }
      const cubeMatch = path.match(/^\/api\/cubes\/([^/]+)$/);
      if (cubeMatch) {
        const cid = cubeMatch[1];
        if (method === 'PUT') {
          const body = await request.json();
          await env.DB.prepare(`UPDATE cubes SET name=?,emoji=?,cat_id=?,qty=?,weight=?,unit=?,made_date=?,expire_date=?,allergy=?,particle=?,note=? WHERE id=? AND user_id=?`)
            .bind(body.name,body.emoji,body.cat_id,body.qty,body.weight||'',body.unit||'g',body.made_date||null,body.expire_date||null,body.allergy||'unknown',body.particle||0,body.note||'',cid,userId).run();
          return json({ ok: true });
        }
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM cubes WHERE id = ? AND user_id = ?').bind(cid, userId).run();
          return json({ ok: true });
        }
        if (method === 'PATCH') {
          const body = await request.json();
          await env.DB.prepare('UPDATE cubes SET qty=? WHERE id=? AND user_id=?').bind(body.qty, cid, userId).run();
          return json({ ok: true });
        }
      }

      // ── history ──
      if (path === '/api/history') {
        if (method === 'GET') {
          const babyId = url.searchParams.get('baby_id');
          const limit = parseInt(url.searchParams.get('limit') || '100');
          const rows = babyId
            ? await env.DB.prepare('SELECT * FROM history WHERE baby_id = ? ORDER BY created_at DESC LIMIT ?').bind(babyId, limit).all()
            : await env.DB.prepare('SELECT * FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').bind(userId, limit).all();
          return json(rows.results);
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare('INSERT INTO history (id, baby_id, user_id, cube_name, emoji, type, amount, memo) VALUES (?,?,?,?,?,?,?,?)')
            .bind(body.id, body.baby_id||null, userId, body.cube_name, body.emoji||'🍱', body.type, body.amount, body.memo||'').run();
          return json({ ok: true });
        }
      }
      const histMatch = path.match(/^\/api\/history\/([^/]+)$/);
      if (histMatch) {
        if (method === 'PATCH') {
          const body = await request.json();
          await env.DB.prepare('UPDATE history SET memo=? WHERE id=? AND user_id=?').bind(body.memo, histMatch[1], userId).run();
          return json({ ok: true });
        }
      }

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err(e.message, 500);
    }
  },
};
