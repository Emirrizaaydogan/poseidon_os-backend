module.exports = function yoklamaKur(app, pool, girisGerekli) {
  const hata = (mesaj, status = 400) =>
    Object.assign(new Error(mesaj), { status });

  const idOku = v => {
    if (!/^\d+$/.test(String(v))) {
      throw hata('Geçersiz kayıt numarası');
    }

    const n = Number(v);

    if (!Number.isSafeInteger(n) || n < 1) {
      throw hata('Geçersiz kayıt numarası');
    }

    return n;
  };

  const cevap = (res, e) => {
    res.status(e.status || 500).json({
      mesaj: e.status
        ? e.message
        : 'Yoklama işlemi tamamlanamadı'
    });
  };

  async function kullanici(db, req, kilitle = false) {
    const r = await db.query(
      `SELECT id, role, athlete_id
       FROM users
       WHERE id = $1
       ${kilitle ? 'FOR SHARE' : ''}`,
      [req.user.id]
    );

    if (!r.rows.length) {
      throw hata('Oturum geçersiz', 401);
    }

    return r.rows[0];
  }

  app.get('/attendance', girisGerekli, async (req, res) => {
    res.set('Cache-Control', 'no-store');

    try {
      const u = await kullanici(pool, req);

      const t = req.query.trainingId == null
        ? null
        : idOku(req.query.trainingId);

      let a = req.query.athleteId == null
        ? null
        : idOku(req.query.athleteId);

      if (u.role === 'veli') {
        const children = (
          await pool.query(
            `SELECT athlete_id
             FROM parent_athletes
             WHERE parent_id = $1
             ORDER BY athlete_id`,
            [u.id]
          )
        ).rows;

        a = a ?? idOku(
          req.headers['x-athlete-id'] ??
          children[0]?.athlete_id
        );

        const yetkili = children.some(
          c => String(c.athlete_id) === String(a)
        );

        if (!yetkili) {
          throw hata(
            'Bu çocuğun yoklamasına erişemezsin',
            403
          );
        }
      } else if (u.role === 'sporcu') {
        if (
          !u.athlete_id ||
          (a !== null && String(a) !== String(u.athlete_id))
        ) {
          throw hata(
            'Sporcu eşleştirmesi bulunamadı veya erişim yetkin yok',
            403
          );
        }

        a = idOku(u.athlete_id);
      } else if (u.role !== 'antrenor') {
        throw hata('Yetkin yok', 403);
      }

      if (t !== null) {
        const training = await pool.query(
          'SELECT id FROM trainings WHERE id = $1',
          [t]
        );

        if (!training.rows.length) {
          throw hata('Antrenman bulunamadı', 404);
        }

        const r = await pool.query(
          `SELECT
             y.id,
             $1::integer AS training_id,
             s.id AS athlete_id,
             s.isim AS athlete_isim,
             s.grup,
             y.giris_zamani,
             y.cikis_zamani
           FROM athletes s
           LEFT JOIN attendance y
             ON y.athlete_id = s.id
            AND y.training_id = $1
           WHERE ($2::bigint IS NULL OR s.id = $2)
           ORDER BY s.isim, s.id`,
          [t, a]
        );

        return res.json(r.rows);
      }

      const r = await pool.query(
        `SELECT
           y.*,
           s.isim AS athlete_isim,
           s.grup,
           t.baslik AS training_baslik
         FROM attendance y
         JOIN athletes s ON s.id = y.athlete_id
         JOIN trainings t ON t.id = y.training_id
         WHERE ($1::bigint IS NULL OR s.id = $1)
           AND y.giris_zamani IS NOT NULL
         ORDER BY
           COALESCE(y.cikis_zamani, y.giris_zamani) DESC,
           y.id DESC
         LIMIT 50`,
        [a]
      );
if (u.role !== 'antrenor') {
  for (const kayit of r.rows) {
    delete kayit.training_baslik;
  }
}
      res.json(r.rows);
    } catch (e) {
      cevap(res, e);
    }
  });

  app.post('/attendance', girisGerekli, async (req, res) => {
    let c;

    try {
      c = await pool.connect();
      await c.query('BEGIN');

      const u = await kullanici(c, req, true);

      if (u.role !== 'antrenor') {
        throw hata(
          'Yoklamayı yalnızca antrenör işaretleyebilir',
          403
        );
      }

      const b = req.body || {};
      const t = idOku(b.training_id);
      const a = idOku(b.athlete_id);

      if (!['giris', 'cikis'].includes(b.tip)) {
        throw hata('Geçersiz yoklama işlemi');
      }

      const training = await c.query(
        'SELECT id FROM trainings WHERE id = $1 FOR SHARE',
        [t]
      );

      if (!training.rows.length) {
        throw hata('Antrenman bulunamadı', 404);
      }

      const athlete = await c.query(
        'SELECT id FROM athletes WHERE id = $1 FOR SHARE',
        [a]
      );

      if (!athlete.rows.length) {
        throw hata('Sporcu bulunamadı', 404);
      }

      // Aynı çocuk/antrenman için işlemleri sıraya alır.
      await c.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`yoklama:${t}:${a}`]
      );

      const old = (
        await c.query(
          `SELECT *
           FROM attendance
           WHERE training_id = $1 AND athlete_id = $2
           FOR UPDATE`,
          [t, a]
        )
      ).rows[0];

      let row = old;

      if (b.tip === 'giris' && !old?.giris_zamani) {
        if (old) {
          row = (
            await c.query(
              `UPDATE attendance
               SET giris_zamani = clock_timestamp(),
                   giris_isaretleyen = $2
               WHERE id = $1
               RETURNING *`,
              [old.id, u.id]
            )
          ).rows[0];
        } else {
          row = (
            await c.query(
              `INSERT INTO attendance (
                 training_id,
                 athlete_id,
                 giris_zamani,
                 giris_isaretleyen
               )
               VALUES ($1, $2, clock_timestamp(), $3)
               RETURNING *`,
              [t, a, u.id]
            )
          ).rows[0];
        }
      }

      if (b.tip === 'cikis') {
        if (!old?.giris_zamani) {
          throw hata(
            'Önce Girdi olarak işaretlemelisin',
            409
          );
        }

        if (!old.cikis_zamani) {
          row = (
            await c.query(
              `UPDATE attendance
               SET cikis_zamani = GREATEST(
                     clock_timestamp(),
                     giris_zamani
                   ),
                   cikis_isaretleyen = $2
               WHERE id = $1
               RETURNING *`,
              [old.id, u.id]
            )
          ).rows[0];
        }
      }

      await c.query('COMMIT');
      res.json(row);
    } catch (e) {
      if (c) {
        await c.query('ROLLBACK').catch(() => {});
      }

      cevap(res, e);
    } finally {
      if (c) c.release();
    }
  });
};