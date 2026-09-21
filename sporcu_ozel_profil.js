const { randomUUID } = require('node:crypto');
const { createClient } = require('@supabase/supabase-js');

const GROUPS = [
  'A Rh+', 'A Rh-', 'B Rh+', 'B Rh-',
  'AB Rh+', 'AB Rh-', '0 Rh+', '0 Rh-'
];

const MAX = 2 * 1024 * 1024;

const fail = (mesaj, status = 400) =>
  Object.assign(new Error(mesaj), { status });

module.exports = function sporcuOzelProfilKur(
  app,
  pool,
  girisGerekli,
  injectedStorage
) {
  let cached;

  function storage() {
    if (injectedStorage) return injectedStorage;

    if (!cached) {
      const key =
        process.env.SUPABASE_SECRET_KEY ||
        process.env.SUPABASE_SERVICE_ROLE_KEY;

      if (!key || !process.env.SUPABASE_URL) {
        throw fail('Fotoğraf depolama ayarları henüz yapılmadı', 503);
      }

      cached = createClient(process.env.SUPABASE_URL, key, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
        global: {
          fetch: (url, opts) =>
            fetch(url, {
              ...opts,
              signal: AbortSignal.timeout(20000),
            }),
        },
      }).storage.from('poseidon-athlete-photos');
    }

    return cached;
  }

  async function coach(db, id) {
    const r = await db.query(
      `SELECT id FROM public.users
       WHERE id = $1 AND role = 'antrenor'`,
      [id]
    );

    if (!r.rows.length) {
      throw fail('Bu bilgilere yalnızca antrenör erişebilir', 403);
    }
  }

  function validate(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw fail('Sporcu özel bilgileri geçersiz');
    }

    function txt(key, max) {
      const value = input[key];

      if (value == null || value === '') return null;

      if (
        typeof value !== 'string' ||
        value.trim().length > max
      ) {
        throw fail('Geçersiz alan: ' + key);
      }

      return value.trim() || null;
    }

    const blood = txt('kan_grubu', 12);
    const tc = txt('tc_kimlik_no', 11);
    const license = txt('lisans_no', 64);

    if (blood && !GROUPS.includes(blood)) {
      throw fail('Geçerli kan grubu seç');
    }

    if (tc && !/^[1-9][0-9]{10}$/.test(tc)) {
      throw fail(
        'T.C. kimlik numarası 11 rakam olmalı ve 0 ile başlamamalı'
      );
    }

    if (input.photo && input.remove_photo === true) {
      throw fail('Fotoğraf silme ve yükleme aynı anda yapılamaz');
    }

    let photo = null;

    if (input.photo != null) {
      const data = input.photo.data;

      if (
        typeof data !== 'string' ||
        data.length > 4 * Math.ceil(MAX / 3) ||
        data.length % 4 !== 0 ||
        /[^A-Za-z0-9+/=]/.test(data)
      ) {
        throw fail('Fotoğraf en fazla 2 MB olabilir');
      }

      const bytes = Buffer.from(data, 'base64');

      if (
        !bytes.length ||
        bytes.length > MAX ||
        bytes.toString('base64') !== data
      ) {
        throw fail('Fotoğraf verisi geçersiz');
      }

      let mime;
      let ext;

      if (
        bytes.subarray(0, 8).equals(
          Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
        )
      ) {
        mime = 'image/png';
        ext = 'png';
      } else if (
        bytes[0] === 255 &&
        bytes[1] === 216 &&
        bytes[2] === 255
      ) {
        mime = 'image/jpeg';
        ext = 'jpg';
      } else {
        throw fail('Fotoğraf JPG veya PNG olmalı');
      }

      photo = { bytes, mime, ext };
    }

    return {
      kan_grubu: blood,
      tc_kimlik_no: tc,
      lisans_no: license,
      photo,
      action: photo
        ? 'replace'
        : input.remove_photo === true
          ? 'remove'
          : 'keep',
      path: null,
    };
  }

  async function upload(prepared) {
    if (!prepared.photo) return;

    const path =
      `profiles/${randomUUID()}.${prepared.photo.ext}`;

    const r = await storage().upload(
      path,
      prepared.photo.bytes,
      {
        contentType: prepared.photo.mime,
        upsert: false,
      }
    );

    if (r.error) {
      throw fail('Fotoğraf yüklenemedi; kayıt tamamlanmadı', 502);
    }

    prepared.path = path;
  }

  async function cleanup(path) {
    if (!path) return;

    try {
      const r = await storage().remove([path]);

      if (r.error) {
        console.error('Profil fotoğrafı temizlenemedi:', path);
      }
    } catch (_) {
      console.error('Profil fotoğrafı temizlenemedi:', path);
    }
  }

  async function save(db, athleteId, p, userId) {
    const old = (
      await db.query(
        `SELECT photo_path, photo_mime
         FROM public.athlete_private_profiles
         WHERE athlete_id = $1
         FOR UPDATE`,
        [athleteId]
      )
    ).rows[0];

    const path =
      p.action === 'keep'
        ? old?.photo_path || null
        : p.path;

    const mime =
      p.action === 'keep'
        ? old?.photo_mime || null
        : p.photo?.mime || null;

    await db.query(
      `INSERT INTO public.athlete_private_profiles (
         athlete_id, kan_grubu, tc_kimlik_no, lisans_no,
         photo_path, photo_mime, updated_by
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (athlete_id) DO UPDATE SET
         kan_grubu = EXCLUDED.kan_grubu,
         tc_kimlik_no = EXCLUDED.tc_kimlik_no,
         lisans_no = EXCLUDED.lisans_no,
         photo_path = EXCLUDED.photo_path,
         photo_mime = EXCLUDED.photo_mime,
         updated_by = EXCLUDED.updated_by,
         updated_at = now()`,
      [
        athleteId,
        p.kan_grubu,
        p.tc_kimlik_no,
        p.lisans_no,
        path,
        mime,
        userId,
      ]
    );

    return old?.photo_path && old.photo_path !== path
      ? old.photo_path
      : null;
  }

  function error(res, e) {
   if (!e.status) {
  let mesaj = String(e.message || 'Hata açıklaması bulunamadı');

  const gizliDegerler = [
    process.env.SUPABASE_SECRET_KEY,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    process.env.SUPABASE_URL,
    process.env.DATABASE_URL,
    process.env.JWT_SECRET,
  ];

  for (const deger of gizliDegerler) {
    if (deger) {
      mesaj = mesaj.split(deger).join('[GİZLENDİ]');
    }
  }

  mesaj = mesaj
    .replace(/sb_secret_[A-Za-z0-9_-]+/g, '[GİZLİ ANAHTAR]')
    .replace(
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
      '[GİZLİ TOKEN]'
    );

  console.error('Sporcu özel profil:', {
    tur: e.name,
    kod: e.code || null,
    mesaj,
  });
}
    res.status(e.code === '23505' ? 409 : e.status || 500).json({
      mesaj:
        e.code === '23505'
          ? 'Bu T.C. kimlik numarası başka bir sporcuya kayıtlı'
          : e.status
            ? e.message
            : 'Sporcu bilgileri işlenemedi',
    });
  }

  function id(req) {
    const n = Number(req.params.id);

    if (!Number.isSafeInteger(n) || n <= 0) {
      throw fail('Geçersiz sporcu');
    }

    return n;
  }

  app.get(
    '/athletes/:id/private-profile',
    girisGerekli,
    async (req, res) => {
      try {
        await coach(pool, req.user.id);

        const r = await pool.query(
          `SELECT
             a.id, a.isim,
             p.kan_grubu, p.tc_kimlik_no, p.lisans_no,
             p.photo_path, p.photo_mime
           FROM public.athletes a
           LEFT JOIN public.athlete_private_profiles p
             ON p.athlete_id = a.id
           WHERE a.id = $1`,
          [id(req)]
        );

        if (!r.rows.length) {
          throw fail('Sporcu bulunamadı', 404);
        }

        const { photo_path, photo_mime, ...result } = r.rows[0];

        result.has_photo = !!photo_path;
        result.photo = null;

        if (photo_path) {
          try {
            const f = await storage().download(photo_path);

            if (f.error) throw f.error;

            const bytes = Buffer.from(await f.data.arrayBuffer());

            if (bytes.length > MAX) throw Error('size');

            result.photo = {
              data: bytes.toString('base64'),
              mime: photo_mime,
            };
          } catch (_) {
            result.photo_unavailable = true;
          }
        }

        res.set('Cache-Control', 'private, no-store').json(result);
      } catch (e) {
        error(res, e);
      }
    }
  );

  app.put(
    '/athletes/:id/private-profile',
    girisGerekli,
    async (req, res) => {
      let c;
      let tx = false;
      let commitAttempted = false;
      let p;

      try {
        const athleteId = id(req);

        await coach(pool, req.user.id);

        const a = await pool.query(
          'SELECT id FROM public.athletes WHERE id = $1',
          [athleteId]
        );

        if (!a.rows.length) {
          throw fail('Sporcu bulunamadı', 404);
        }

        p = validate(req.body);
        await upload(p);

        c = await pool.connect();
        await c.query('BEGIN');
        tx = true;

        await coach(c, req.user.id);

        const locked = await c.query(
          `SELECT id FROM public.athletes
           WHERE id = $1 FOR UPDATE`,
          [athleteId]
        );

        if (!locked.rows.length) {
          throw fail('Sporcu bulunamadı', 404);
        }

        const oldPath = await save(
          c, athleteId, p, req.user.id
        );

        commitAttempted = true;
        await c.query('COMMIT');
        tx = false;

        await cleanup(oldPath);

        res.json({ mesaj: 'Sporcu bilgileri güncellendi' });
      } catch (e) {
        if (tx) {
          await c.query('ROLLBACK').catch(() => {});
        }

        if (!commitAttempted) {
          await cleanup(p?.path);
        }

        error(res, e);
      } finally {
        if (c) c.release();
      }
    }
  );

  return { validate, upload, save, cleanup, coach };
};