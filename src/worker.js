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

async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function randomSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b=>b.toString(16).padStart(2,'0')).join('');
}

let dbInitialized = false;
async function initDB(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER DEFAULT (unixepoch()))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS babies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, bday TEXT, avatar TEXT DEFAULT '👶', created_at INTEGER DEFAULT (unixepoch()))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS cubes (id TEXT PRIMARY KEY, baby_id TEXT, user_id TEXT, name TEXT NOT NULL, emoji TEXT DEFAULT '🍱', cat_id TEXT NOT NULL, qty REAL DEFAULT 0, weight TEXT DEFAULT '', unit TEXT DEFAULT 'g', made_date TEXT, expire_date TEXT, allergy TEXT DEFAULT 'unknown', particle INTEGER DEFAULT 0, note TEXT DEFAULT '', created_at INTEGER DEFAULT (unixepoch()))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, emoji TEXT DEFAULT '📦', color TEXT DEFAULT '#D4537E', is_default INTEGER DEFAULT 0, created_at INTEGER DEFAULT (unixepoch()))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS history (id TEXT PRIMARY KEY, baby_id TEXT, user_id TEXT, cube_name TEXT NOT NULL, emoji TEXT DEFAULT '🍱', type TEXT NOT NULL, amount REAL NOT NULL, memo TEXT DEFAULT '', created_at INTEGER DEFAULT (unixepoch()))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS settings (user_id TEXT PRIMARY KEY, active_baby_id TEXT, theme_idx INTEGER DEFAULT 0, updated_at INTEGER DEFAULT (unixepoch()))`),
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

function uid8ref(){return Date.now().toString(36)+Math.random().toString(36).slice(2,6);}

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

      if (path === '/api/auth/register' && method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return err('이메일과 비밀번호를 입력해주세요');
        if (password.length < 6) return err('비밀번호는 6자 이상이어야 해요');
        const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
        if (existing) return err('이미 가입된 이메일이에요');
        const salt = randomSalt();
        const hash = await hashPassword(password, salt);
        const userId = 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2,6);
        await env.DB.prepare('INSERT INTO users (id, email, password_hash, salt) VALUES (?,?,?,?)').bind(userId, email.toLowerCase(), hash, salt).run();
        const token = await makeJWT({ sub: userId, email: email.toLowerCase(), exp: Math.floor(Date.now()/1000) + 86400*365 }, JWT_SECRET);
        return json({ ok: true, token, userId });
      }

      if (path === '/api/auth/forgot-password' && method === 'POST') {
        const { email } = await request.json();
        if (!email) return err('이메일을 입력해주세요');
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
        if (!user) return json({ ok: true });
        const resetToken = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b=>b.toString(16).padStart(2,'0')).join('');
        const expiresAt = Math.floor(Date.now()/1000) + 3600;
        await env.DB.prepare('INSERT OR REPLACE INTO password_resets (token, user_id, expires_at, used) VALUES (?,?,?,0)').bind(resetToken, user.id, expiresAt).run();
        const resetUrl = `https://babymeals.pages.dev?reset=${resetToken}`;
        const RESEND_KEY = env.RESEND_API_KEY;
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_KEY}` },
          body: JSON.stringify({ from: 'onboarding@resend.dev', to: ['iyhee8@gmail.com'], subject: '🍼 이유식 큐브 현황 — 비밀번호 재설정', html: `<p><a href="${resetUrl}">비밀번호 재설정 링크</a></p>` }),
        });
        return json({ ok: true });
      }

      if (path === '/api/auth/reset-password' && method === 'POST') {
        const { token: resetToken, newPassword } = await request.json();
        if (!resetToken || !newPassword) return err('올바르지 않은 요청이에요');
        if (newPassword.length < 6) return err('비밀번호는 6자 이상이어야 해요');
        const reset = await env.DB.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0').bind(resetToken).first();
        if (!reset) return err('유효하지 않은 링크예요');
        if (reset.expires_at < Math.floor(Date.now()/1000)) return err('링크가 만료됐어요. 다시 요청해주세요');
        const newSalt = randomSalt();
        const newHash = await hashPassword(newPassword, newSalt);
        await env.DB.prepare('UPDATE users SET password_hash=?, salt=? WHERE id=?').bind(newHash, newSalt, reset.user_id).run();
        await env.DB.prepare('UPDATE password_resets SET used=1 WHERE token=?').bind(resetToken).run();
        return json({ ok: true });
      }

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

      const authHeader = request.headers.get('Authorization');
      const token = authHeader?.replace('Bearer ', '');
      if (!token) return err('로그인이 필요해요', 401);
      const payload = await verifyJWT(token, JWT_SECRET);
      if (!payload) return err('인증이 만료됐어요. 다시 로그인해주세요', 401);
      const userId = payload.sub;

      if (path === '/api/auth/change-password' && method === 'POST') {
        const { currentPassword, newPassword } = await request.json();
        if (!currentPassword || !newPassword) return err('비밀번호를 입력해주세요');
        if (newPassword.length < 6) return err('새 비밀번호는 6자 이상이어야 해요');
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
        if (!user) return err('사용자를 찾을 수 없어요');
        const currentHash = await hashPassword(currentPassword, user.salt);
        if (currentHash !== user.password_hash) return err('현재 비밀번호가 틀렸어요');
        const newSalt = randomSalt();
        const newHash = await hashPassword(newPassword, newSalt);
        await env.DB.prepare('UPDATE users SET password_hash=?, salt=? WHERE id=?').bind(newHash, newSalt, userId).run();
        return json({ ok: true });
      }

      if (path === '/api/favorites') {
        if (method === 'GET') {
          const rows = await env.DB.prepare('SELECT food_name, reaction FROM favorites WHERE user_id = ?').bind(userId).all();
          return json(rows.results);
        }
        // POST = 토글 (큐브 카드에서 직접 탭할 때)
        if (method === 'POST') {
          const { food_name, reaction } = await request.json();
          const existing = await env.DB.prepare('SELECT id, reaction FROM favorites WHERE user_id = ? AND food_name = ?').bind(userId, food_name).first();
          if (existing) {
            if (existing.reaction === reaction) {
              await env.DB.prepare('DELETE FROM favorites WHERE user_id = ? AND food_name = ?').bind(userId, food_name).run();
              return json({ ok: true, reaction: null });
            } else {
              await env.DB.prepare('UPDATE favorites SET reaction = ? WHERE user_id = ? AND food_name = ?').bind(reaction, userId, food_name).run();
              return json({ ok: true, reaction });
            }
          } else {
            await env.DB.prepare('INSERT INTO favorites (id, user_id, food_name, reaction) VALUES (?,?,?,?)').bind(uid8ref(), userId, food_name, reaction).run();
            return json({ ok: true, reaction });
          }
        }
        // PUT = 무조건 덮어쓰기 (수정 모달에서 저장할 때)
        if (method === 'PUT') {
          const { food_name, reaction } = await request.json();
          if (!reaction || reaction === 'none') {
            await env.DB.prepare('DELETE FROM favorites WHERE user_id = ? AND food_name = ?').bind(userId, food_name).run();
            return json({ ok: true, reaction: null });
          }
          const existing = await env.DB.prepare('SELECT id FROM favorites WHERE user_id = ? AND food_name = ?').bind(userId, food_name).first();
          if (existing) {
            await env.DB.prepare('UPDATE favorites SET reaction = ? WHERE user_id = ? AND food_name = ?').bind(reaction, userId, food_name).run();
          } else {
            await env.DB.prepare('INSERT INTO favorites (id, user_id, food_name, reaction) VALUES (?,?,?,?)').bind(uid8ref(), userId, food_name, reaction).run();
          }
          return json({ ok: true, reaction });
        }
      }

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
        const [cubesR, histR, favsR] = await Promise.all([
          activeBabyId
            ? env.DB.prepare('SELECT * FROM cubes WHERE baby_id = ? ORDER BY created_at').bind(activeBabyId).all()
            : env.DB.prepare('SELECT * FROM cubes WHERE user_id = ? ORDER BY created_at').bind(userId).all(),
          activeBabyId
            ? env.DB.prepare('SELECT * FROM history WHERE baby_id = ? ORDER BY created_at DESC LIMIT 100').bind(activeBabyId).all()
            : env.DB.prepare('SELECT * FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').bind(userId).all(),
          env.DB.prepare('SELECT food_name FROM favorites WHERE user_id = ?').bind(userId).all(),
        ]);
        return json({ babies, categories: cats, settings, cubes: cubesR.results, history: histR.results, favorites: favsR.results.map(r=>({food_name:r.food_name,reaction:r.reaction})) });
      }

      if (path === '/api/settings') {
        if (method === 'GET') {
          const row = await env.DB.prepare('SELECT * FROM settings WHERE user_id = ?').bind(userId).first();
          return json(row || { user_id: userId, active_baby_id: null, theme_idx: 0 });
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare(`INSERT INTO settings (user_id, active_baby_id, theme_idx, updated_at) VALUES (?,?,?,unixepoch()) ON CONFLICT(user_id) DO UPDATE SET active_baby_id=excluded.active_baby_id, theme_idx=excluded.theme_idx, updated_at=unixepoch()`)
            .bind(userId, body.active_baby_id ?? null, body.theme_idx ?? 0).run();
          return json({ ok: true });
        }
      }

      if (path === '/api/babies') {
        if (method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM babies WHERE user_id = ? ORDER BY created_at').bind(userId).all();
          return json(rows.results);
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare('INSERT OR REPLACE INTO babies (id, user_id, name, bday, avatar) VALUES (?,?,?,?,?)').bind(body.id, userId, body.name, body.bday || null, body.avatar || '👶').run();
          await env.DB.prepare(`INSERT INTO settings (user_id, active_baby_id, theme_idx) VALUES (?,?,0) ON CONFLICT(user_id) DO UPDATE SET active_baby_id=COALESCE(active_baby_id, excluded.active_baby_id)`).bind(userId, body.id).run();
          return json({ ok: true });
        }
      }
      const babyMatch = path.match(/^\/api\/babies\/([^/]+)$/);
      if (babyMatch) {
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM babies WHERE id = ? AND user_id = ?').bind(babyMatch[1], userId).run();
          return json({ ok: true });
        }
      }

      if (path === '/api/categories') {
        await ensureDefaultCategories(env.DB, userId);
        if (method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM categories WHERE user_id = ? ORDER BY is_default DESC, created_at').bind(userId).all();
          return json(rows.results.map(r => ({ ...r, id: r.id.replace(`${userId}_`, '') })));
        }
        if (method === 'POST') {
          const body = await request.json();
          await env.DB.prepare('INSERT OR REPLACE INTO categories (id, user_id, name, emoji, color, is_default) VALUES (?,?,?,?,?,?)')
            .bind(`${userId}_${body.id}`, userId, body.name, body.emoji, body.color, body.is_default ? 1 : 0).run();
          return json({ ok: true });
        }
      }
      const catMatch = path.match(/^\/api\/categories\/([^/]+)$/);
      if (catMatch) {
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').bind(`${userId}_${catMatch[1]}`, userId).run();
          return json({ ok: true });
        }
      }

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
          // memo와 created_at 모두 업데이트 가능
          if (body.created_at !== undefined) {
            await env.DB.prepare('UPDATE history SET memo=?, created_at=? WHERE id=? AND user_id=?')
              .bind(body.memo ?? '', body.created_at, histMatch[1], userId).run();
          } else {
            await env.DB.prepare('UPDATE history SET memo=? WHERE id=? AND user_id=?')
              .bind(body.memo, histMatch[1], userId).run();
          }
          return json({ ok: true });
        }
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM history WHERE id=? AND user_id=?').bind(histMatch[1], userId).run();
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
