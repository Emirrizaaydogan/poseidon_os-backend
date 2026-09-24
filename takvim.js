module.exports = function takvimKur(app, pool, girisGerekli) {
  const fail = (mesaj, status = 400) =>
    Object.assign(new Error(mesaj), { status });

  const fields =
    'id,tur,baslik,tarih::text AS tarih,aciklama,belgeler';

  const idOku = v => {
    if (
      !/^\d+$/.test(String(v)) ||
      !Number.isSafeInteger(Number(v)) ||
      Number(v) < 1
    ) {
      throw fail('Geçersiz etkinlik numarası');
    }

    return Number(v);
  };

  async function yetki(req, antrenor = false) {
    const r = await pool.query(
      'SELECT role FROM users WHERE id=$1',
      [req.user.id]
    );

    const role = r.rows[0]?.role;

    if (!role) throw fail('Oturum geçersiz', 401);

    if (
      !['antrenor', 'veli', 'sporcu'].includes(role) ||
      (antrenor && role !== 'antrenor')
    ) {
      throw fail('Bu işlem için antrenör yetkisi gerekiyor', 403);
    }
  }

  function validate(b) {
    if (!b || !['yaris', 'tatil', 'odeme'].includes(b.tur)) {
      throw fail('Etkinlik türünü seç');
    }

    const text = (v, max) => {
      if (typeof v !== 'string' || v.trim().length > max) {
        throw fail('Metin alanı geçersiz veya çok uzun');
      }

      return v.trim();
    };

    const baslik = text(b.baslik, 120);
    const aciklama = text(b.aciklama ?? '', 2000);

    if (!baslik) throw fail('Başlık gerekli');

    if (b.tur === 'tatil' && !aciklama) {
      throw fail('Tatil nedenini yaz');
    }

    if (
      typeof b.tarih !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}$/.test(b.tarih)
    ) {
      throw fail('Tarih geçersiz');
    }

    const d = new Date(b.tarih + 'T00:00:00Z');

    if (
      !Number.isFinite(d.getTime()) ||
      d.toISOString().slice(0, 10) !== b.tarih ||
      b.tarih < '2020-01-01' ||
      b.tarih > '2100-12-31'
    ) {
      throw fail('Tarih geçersiz');
    }

    let belgeler = [];

    if (b.tur === 'yaris') {
      if (!Array.isArray(b.belgeler) || b.belgeler.length > 30) {
        throw fail('En fazla 30 belge yazabilirsin');
      }

      belgeler = [
        ...new Set(
          b.belgeler.map(v => text(v, 200)).filter(Boolean)
        )
      ];
    }

    return [
      b.tur,
      baslik,
      b.tarih,
      aciklama,
      JSON.stringify(belgeler)
    ];
  }

  function hata(res, e) {
    if (!e.status) {
      console.error('Takvim:', e.code || e.name);
    }

    res.status(e.status || 500).json({
      mesaj: e.status
        ? e.message
        : 'Takvim işlemi tamamlanamadı'
    });
  }

  app.get('/calendar-events', girisGerekli, async (req, res) => {
    res.set('Cache-Control', 'no-store');

    try {
      await yetki(req);

      const r = await pool.query(
        `SELECT ${fields}
         FROM club_calendar_events
         ORDER BY tarih, id`
      );

      res.json(r.rows);
    } catch (e) {
      hata(res, e);
    }
  });

  app.post('/calendar-events', girisGerekli, async (req, res) => {
    try {
      await yetki(req, true);
      const values = validate(req.body);

      const r = await pool.query(
        `INSERT INTO club_calendar_events
          (tur,baslik,tarih,aciklama,belgeler,created_by,updated_by)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6,$6)
         RETURNING ${fields}`,
        [...values, req.user.id]
      );

      res.status(201).json(r.rows[0]);
    } catch (e) {
      hata(res, e);
    }
  });

  app.put('/calendar-events/:id', girisGerekli, async (req, res) => {
    try {
      await yetki(req, true);
      const values = validate(req.body);

      const r = await pool.query(
        `UPDATE club_calendar_events
         SET tur=$1, baslik=$2, tarih=$3, aciklama=$4,
             belgeler=$5::jsonb,
             updated_by=$6, updated_at=now()
         WHERE id=$7
         RETURNING ${fields}`,
        [...values, req.user.id, idOku(req.params.id)]
      );

      if (!r.rows.length) {
        throw fail('Etkinlik bulunamadı', 404);
      }

      res.json(r.rows[0]);
    } catch (e) {
      hata(res, e);
    }
  });

  app.delete('/calendar-events/:id', girisGerekli, async (req, res) => {
    try {
      await yetki(req, true);

      const r = await pool.query(
        'DELETE FROM club_calendar_events WHERE id=$1 RETURNING id',
        [idOku(req.params.id)]
      );

      if (!r.rows.length) {
        throw fail('Etkinlik bulunamadı', 404);
      }

      res.status(204).send();
    } catch (e) {
      hata(res, e);
    }
  });
};