'use strict';

module.exports = function veliOnayKur(app, pool, bcrypt, girisGerekli) {
  const hata = (mesaj, status = 400) =>
    Object.assign(new Error(mesaj), { status });

  const idOku = value => {
    if (!/^\d+$/.test(String(value))) {
      throw hata('Geçersiz kayıt numarası');
    }

    const id = Number(value);

    if (!Number.isSafeInteger(id) || id < 1) {
      throw hata('Geçersiz kayıt numarası');
    }

    return id;
  };

  const idsOku = value => {
    if (!Array.isArray(value) || !value.length || value.length > 10) {
      throw hata('1 ile 10 arasında çocuk seçmelisin');
    }

    return [...new Set(value.map(idOku))].sort((a, b) => a - b);
  };

  const yanit = fn => async (req, res, next) => {
    res.set('Cache-Control', 'no-store');

    try {
      await fn(req, res, next);
    } catch (e) {
      if (!e.status && e.code !== '23505') {
        console.error('Veli onayı:', {
          tur: e.name,
          kod: e.code || null,
        });
      }

      res.status(e.code === '23505' ? 409 : e.status || 500).json({
        mesaj: e.code === '23505'
          ? 'E-posta veya çocuk için başka kayıt var. Listeyi yenile.'
          : e.status
            ? e.message
            : 'İşlem tamamlanamadı. Sunucu kayıtlarını kontrol edin.',
      });
    }
  };

  async function kullanici(db, req, rol, kilit = false) {
    const u = (
      await db.query(
        `SELECT id,role,athlete_id FROM users WHERE id=$1
         ${kilit ? 'FOR SHARE' : ''}`,
        [req.user.id]
      )
    ).rows[0];

    if (!u) throw hata('Oturum geçersiz', 401);
    if (rol && u.role !== rol) throw hata('Bu işlem için yetkin yok', 403);

    return u;
  }

  async function islem(fn) {
    const c = await pool.connect();

    try {
      await c.query('BEGIN');
      await c.query('SELECT pg_advisory_xact_lock(60629, 1)');

      const result = await fn(c);

      await c.query('COMMIT');
      return result;
    } catch (e) {
      await c.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      c.release();
    }
  }

  const bosKosulu = `
    NOT EXISTS (
      SELECT 1 FROM parent_athletes p WHERE p.athlete_id=a.id
    )
    AND NOT EXISTS (
      SELECT 1 FROM users u
      WHERE u.role='veli' AND u.athlete_id=a.id
    )
    AND NOT EXISTS (
      SELECT 1 FROM parent_link_requests r
      WHERE r.athlete_id=a.id AND r.status='bekliyor'
    )
  `;

  async function basvuruEkle(c, parentId, ids) {
    const mevcut = (
      await c.query(
        `SELECT count(*)::integer AS sayi FROM (
          SELECT athlete_id FROM parent_athletes WHERE parent_id=$1
          UNION
          SELECT athlete_id FROM parent_link_requests
          WHERE parent_id=$1 AND status='bekliyor'
        ) t`,
        [parentId]
      )
    ).rows[0].sayi;

    if (mevcut + ids.length > 10) {
      throw hata('En fazla 10 aktif çocuk bağlantısı olabilir');
    }

    const secilen = await c.query(
      `SELECT a.id FROM athletes a
       WHERE a.id=ANY($1::bigint[]) AND ${bosKosulu}
       ORDER BY a.id FOR UPDATE`,
      [ids]
    );

    if (secilen.rows.length !== ids.length) {
      throw hata(
        'Seçilen çocuklardan biri artık uygun değil. Listeyi yenile.',
        409
      );
    }

    for (const id of ids) {
      await c.query(
        `INSERT INTO parent_link_requests(parent_id,athlete_id)
         VALUES($1,$2)`,
        [parentId, id]
      );
    }
  }

  app.get('/athletes/register-list', yanit(async (_req, res) => {
    const r = await pool.query(
      `SELECT a.id,a.isim,a.dogum_yili,a.grup FROM athletes a
       WHERE ${bosKosulu}
       ORDER BY a.isim,a.id`
    );

    res.json(r.rows);
  }));

  app.post('/auth/register', yanit(async (req, res) => {
    const b = req.body || {};

    if (b.role !== 'veli') {
      throw hata('Bu ekran yalnızca veli kaydı içindir', 403);
    }

    const email = typeof b.email === 'string'
      ? b.email.trim().toLowerCase()
      : '';

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      throw hata('Geçerli e-posta gir');
    }

    if (
      typeof b.password !== 'string' ||
      b.password.length < 8 ||
      Buffer.byteLength(b.password, 'utf8') > 72
    ) {
      throw hata('Şifre en az 8 karakter ve en fazla 72 UTF-8 baytı olmalı');
    }

    const ids = idsOku(b.athlete_ids);
    const hash = await bcrypt.hash(b.password, 10);

    const user = await islem(async c => {
      await c.query(
        'SELECT pg_advisory_xact_lock(hashtext($1))',
        [email]
      );

      const eski = await c.query(
        'SELECT id FROM users WHERE lower(email)=$1',
        [email]
      );

      if (eski.rows.length) {
        throw hata('Bu e-posta zaten kayıtlı. Giriş yapabilirsin.', 409);
      }

      const u = (
        await c.query(
          `INSERT INTO users(email,password_hash,role,athlete_id)
           VALUES($1,$2,'veli',NULL)
           RETURNING id,email,role,athlete_id`,
          [email, hash]
        )
      ).rows[0];

      await basvuruEkle(c, u.id, ids);
      return u;
    });

    res.status(201).json({ ...user, onay_bekliyor: true });
  }));

  app.post('/auth/accept-invite', (_req, res) => {
    res.status(410).json({
      mesaj: 'Davetle kayıt kapalı. Veli Kayıt Ol ekranını kullanın.',
    });
  });

  app.get('/parent-link-requests', girisGerekli, yanit(async (req, res) => {
    const u = await kullanici(pool, req);

    if (!['antrenor', 'veli'].includes(u.role)) {
      throw hata('Yetkin yok', 403);
    }

    const r = await pool.query(
      `SELECT
         r.id,r.parent_id,r.athlete_id,r.status,r.source,
         r.created_at,r.reviewed_at,r.review_note,
         u.email AS parent_email,
         a.isim AS athlete_name,a.grup,a.dogum_yili
       FROM parent_link_requests r
       JOIN users u ON u.id=r.parent_id
       JOIN athletes a ON a.id=r.athlete_id
       WHERE ($1::boolean OR r.parent_id=$2)
       ORDER BY
         (r.status='bekliyor') DESC,
         r.created_at DESC,
         r.id DESC`,
      [u.role === 'antrenor', u.id]
    );

    res.json(r.rows);
  }));

  app.post('/parent-link-requests', girisGerekli, yanit(async (req, res) => {
    const ids = idsOku(req.body?.athlete_ids);

    await islem(async c => {
      const u = await kullanici(c, req, 'veli', true);
      await basvuruEkle(c, u.id, ids);
    });

    res.status(201).json({
      mesaj: 'Başvurun antrenör onayına gönderildi.',
    });
  }));

  app.patch('/parent-link-requests/:id', girisGerekli, yanit(async (req, res) => {
    const id = idOku(req.params.id);
    const decision = req.body?.decision;

    const note = typeof req.body?.note === 'string'
      ? req.body.note.trim()
      : '';

    if (!['onaylandi', 'reddedildi'].includes(decision)) {
      throw hata('Geçersiz karar');
    }

    if (note.length > 500) {
      throw hata('Açıklama en fazla 500 karakter olabilir');
    }

    if (decision === 'reddedildi' && !note) {
      throw hata('Ret nedenini yazmalısın');
    }

    const result = await islem(async c => {
      const coach = await kullanici(c, req, 'antrenor', true);

      const r = (
        await c.query(
          'SELECT * FROM parent_link_requests WHERE id=$1 FOR UPDATE',
          [id]
        )
      ).rows[0];

      if (!r) throw hata('Başvuru bulunamadı', 404);

      if (r.status !== 'bekliyor') {
        if (r.status === decision) {
          return { id: r.id, status: r.status };
        }

        throw hata(
          'Bu başvuru daha önce sonuçlandırıldı. Listeyi yenile.',
          409
        );
      }

      const parent = (
        await c.query(
          "SELECT id FROM users WHERE id=$1 AND role='veli' FOR UPDATE",
          [r.parent_id]
        )
      ).rows[0];

      if (!parent) throw hata('Veli hesabı bulunamadı', 409);

      await c.query(
        'SELECT id FROM athletes WHERE id=$1 FOR UPDATE',
        [r.athlete_id]
      );

      if (decision === 'onaylandi') {
        const other = await c.query(
          `SELECT parent_id FROM parent_athletes
           WHERE athlete_id=$1 AND parent_id<>$2
           UNION
           SELECT id FROM users
           WHERE role='veli' AND athlete_id=$1 AND id<>$2`,
          [r.athlete_id, r.parent_id]
        );

        if (other.rows.length) {
          throw hata('Bu çocuk başka bir veliye bağlı', 409);
        }

        await c.query(
          `INSERT INTO parent_athletes(parent_id,athlete_id)
           VALUES($1,$2)
           ON CONFLICT (parent_id,athlete_id) DO NOTHING`,
          [r.parent_id, r.athlete_id]
        );

        await c.query(
          `UPDATE users SET athlete_id=(
             SELECT min(athlete_id)
             FROM parent_athletes
             WHERE parent_id=$1
           )
           WHERE id=$1`,
          [r.parent_id]
        );
      }

      await c.query(
        `UPDATE parent_link_requests
         SET status=$1,reviewed_at=now(),reviewed_by=$2,review_note=$3
         WHERE id=$4`,
        [decision, coach.id, note, id]
      );

      return { id: r.id, status: decision };
    });

    res.json(result);
  }));

  app.get('/auth/children', girisGerekli, yanit(async (req, res) => {
    const u = await kullanici(pool, req, 'veli');

    const r = await pool.query(
      `SELECT a.id,a.isim,a.dogum_yili,a.grup
       FROM athletes a
       JOIN parent_athletes p ON p.athlete_id=a.id
       WHERE p.parent_id=$1
       ORDER BY a.id`,
      [u.id]
    );

    res.json(r.rows);
  }));

  app.patch('/users/:id/link-athlete', girisGerekli, yanit(async (req, res, next) => {
    await kullanici(pool, req, 'antrenor');

    const u = (
      await pool.query(
        'SELECT role FROM users WHERE id=$1',
        [idOku(req.params.id)]
      )
    ).rows[0];

    if (u?.role === 'veli') {
      throw hata(
        'Veli bağlantısını Veli Onayları ekranından yönetmelisin',
        409
      );
    }

    next();
  }));

  const ozelYollar =
    /^\/(athletes|performance|rankings|report-cards|dues|attendance|trainings|calendar-events|users)(\/|$)/i;

  app.use((req, res, next) => {
    if (!ozelYollar.test(req.path) || req.method === 'OPTIONS') {
      return next();
    }

    girisGerekli(req, res, () => kontrol(req, res, next));
  });

  const kontrol = yanit(async (req, res, next) => {
    const u = await kullanici(pool, req);

    if (u.role !== 'veli') return next();

    const links = (
      await pool.query(
        'SELECT athlete_id FROM parent_athletes WHERE parent_id=$1',
        [u.id]
      )
    ).rows;

    if (!links.length) {
      throw hata('Çocuğunla eşleşmen antrenör onayı bekliyor.', 403);
    }

    const izinli = id =>
      links.some(x => String(x.athlete_id) === String(id));

    const explicit = req.query.athleteId ?? req.headers['x-athlete-id'];

    if (explicit != null && !izinli(idOku(explicit))) {
      throw hata('Bu çocuğa erişim yetkin yok', 403);
    }

    const due = /^\/dues\/(\d+)(?:\/|$)/i.exec(req.path);

    if (due) {
      const d = (
        await pool.query(
          'SELECT athlete_id FROM dues WHERE id=$1',
          [idOku(due[1])]
        )
      ).rows[0];

      if (!d || !izinli(d.athlete_id)) {
        throw hata('Aidat bulunamadı veya yetkin yok', 403);
      }
    }

    if (/^\/trainings(?:\/|$)/i.test(req.path)) {
      throw hata('Veliler antrenman içeriğine erişemez', 403);
    }

    const path = req.path.replace(/\/$/, '').toLowerCase();

    if (req.method === 'GET' && path === '/athletes') {
      const r = await pool.query(
        `SELECT
           a.id,a.isim,a.dogum_yili,a.grup,
           a.en_iyi_derece,a.en_iyi_derece_stil
         FROM athletes a
         JOIN parent_athletes p ON p.athlete_id=a.id
         WHERE p.parent_id=$1
         ORDER BY a.isim`,
        [u.id]
      );

      return res.json(r.rows);
    }

    if (req.method === 'GET' && path === '/performance') {
      const id = explicit == null
        ? links[0].athlete_id
        : idOku(explicit);

      const r = await pool.query(
        'SELECT * FROM performance WHERE athlete_id=$1 ORDER BY id',
        [id]
      );

      return res.json(r.rows);
    }

    next();
  });
};