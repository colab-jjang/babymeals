/**
 * 이유식 큐브 현황 - Cloudflare Worker API
 * D1 데이터베이스와 연동하여 아기별 큐브 데이터를 관리합니다.
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function initDB(db) {
  await db.batch([
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

// 기본 카테고리 삽입 (없을 때만)
async function ensureDefaultCategories(db, userId) {
  const existing = await db.prepare(
    'SELECT id FROM categories WHERE user_id = ? LIMIT 1'
  ).bind(userId).first();

  if (!existing) {
    const defaults = [
      { id: 'veg', name: '채소', emoji: '🥦', color: '#1D9E75' },
      { id: 'fruit', name: '과일', emoji: '🍎', color: '#D85A30' },
      { id: 'grain', name: '곡물/죽', emoji: '🌾', color: '#EF9F27' },
      { id: 'protein', name: '단백질', emoji: '🥩', color: '#D4537E' },
      { id: 'fish', name: '해산물', emoji: '🐟', color: '#378ADD' },
      { id: 'dairy', name: '유제품/기타', emoji: '🧀', color: '#7F77DD' },
    ];
    const stmts = defaults.map(c =>
      db.prepare('INSERT OR IGNORE INTO categories (id, user_id, name, emoji, color, is_default) VALUES (?,?,?,?,?,1)')
        .bind(`${userId}_${c.id}`, userId, c.name, c.emoji, c.color)
    );
    await db.batch(stmts);
  }
}

let dbInitialized = false;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // DB 초기화 — Worker 인스턴스당 최초 1회만 실행
    if (!dbInitialized) {
      await initDB(env.DB);
      dbInitialized = true;
    }

    // user_id: 쿼리 파라미터로 전달 (간단한 기기 식별용)
    const userId = url.searchParams.get('uid');
    if (!userId && path !== '/api/ping') return err('uid required', 401);

    try {
      // ── ping ──
      if (path === '/api/ping') return json({ ok: true });

      // ── init: 앱 시작시 필요한 모든 데이터를 1번 요청으로 ──
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
            : env.DB.prepare('SELECT * FROM cubes ORDER BY created_at').all(),
          activeBabyId
            ? env.DB.prepare('SELECT * FROM history WHERE baby_id = ? ORDER BY created_at DESC LIMIT 100').bind(activeBabyId).all()
            : env.DB.prepare('SELECT * FROM history ORDER BY created_at DESC LIMIT 100').all(),
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
          await env.DB.prepare(`INSERT INTO settings (user_id, active_baby_id, theme_idx, updated_at)
            VALUES (?,?,?,unixepoch())
            ON CONFLICT(user_id) DO UPDATE SET
              active_baby_id=excluded.active_baby_id,
              theme_idx=excluded.theme_idx,
              updated_at=unixepoch()`)
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
          // 첫 아기면 active_baby_id 자동 설정
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
          // id에서 userId_ 접두사 제거해서 클라이언트로 전달
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
            : await env.DB.prepare('SELECT * FROM cubes ORDER BY created_at').bind().all();
          return json(rows.results);
        }
        if (method === 'POST') {
          const body = await request.json();
          const babyId = body.baby_id || null;
          await env.DB.prepare(`INSERT OR REPLACE INTO cubes
            (id, baby_id, name, emoji, cat_id, qty, weight, unit, made_date, expire_date, allergy, particle, note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
            .bind(body.id, babyId, body.name, body.emoji, body.cat_id, body.qty,
                  body.weight || '', body.unit || 'g', body.made_date || null,
                  body.expire_date || null, body.allergy || 'unknown',
                  body.particle || 0, body.note || '').run();
          return json({ ok: true });
        }
      }
      const cubeMatch = path.match(/^\/api\/cubes\/([^/]+)$/);
      if (cubeMatch) {
        const cid = cubeMatch[1];
        if (method === 'PUT') {
          const body = await request.json();
          await env.DB.prepare(`UPDATE cubes SET
            name=?, emoji=?, cat_id=?, qty=?, weight=?, unit=?, made_date=?,
            expire_date=?, allergy=?, particle=?, note=?
            WHERE id=?`)
            .bind(body.name, body.emoji, body.cat_id, body.qty, body.weight || '',
                  body.unit || 'g', body.made_date || null, body.expire_date || null,
                  body.allergy || 'unknown', body.particle || 0, body.note || '', cid).run();
          return json({ ok: true });
        }
        if (method === 'DELETE') {
          await env.DB.prepare('DELETE FROM cubes WHERE id = ?').bind(cid).run();
          return json({ ok: true });
        }
        if (method === 'PATCH') {
          // 수량만 업데이트
          const body = await request.json();
          await env.DB.prepare('UPDATE cubes SET qty=? WHERE id=?').bind(body.qty, cid).run();
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
            : await env.DB.prepare('SELECT * FROM history ORDER BY created_at DESC LIMIT ?').bind(limit).all();
          return json(rows.results);
        }
        if (method === 'POST') {
          const body = await request.json();
          const babyId = body.baby_id || null;
          await env.DB.prepare('INSERT INTO history (id, baby_id, cube_name, emoji, type, amount, memo) VALUES (?,?,?,?,?,?,?)')
            .bind(body.id, babyId, body.cube_name, body.emoji || '🍱', body.type, body.amount, body.memo || '').run();
          return json({ ok: true });
        }
      }
      const histMatch = path.match(/^\/api\/history\/([^/]+)$/);
      if (histMatch) {
        const hid = histMatch[1];
        if (method === 'PATCH') {
          const body = await request.json();
          await env.DB.prepare('UPDATE history SET memo=? WHERE id=?').bind(body.memo, hid).run();
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
