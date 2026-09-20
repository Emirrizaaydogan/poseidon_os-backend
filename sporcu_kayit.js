module.exports = function sporcuKayitKur(
  app,
  pool,
  bcrypt,
  girisGerekli,
  sadeceAntrenor,
  ozelProfil
) {
  const hata = (mesaj, status = 400) => Object.assign(new Error(mesaj), { status });
  const metin = v => typeof v === 'string' ? v.trim() : '';
  app.post('/athletes/onboard', girisGerekli, sadeceAntrenor, async (req, res) => {
    let c;
let tx = false;
let prepared;
let commitAttempted = false;
    try {
      const b = req.body || {}, s = b.athlete || {}, h = b.athlete_account || {};
      const isim = metin(s.isim), grup = metin(s.grup), tarih = metin(s.dogum_tarihi);
      const email = metin(h.email).toLowerCase();
      if (!isim || !grup) throw hata('Sporcu adı ve grup gerekli');
      const d = new Date(tarih + 'T00:00:00Z');
      if (!/^\d{4}-\d{2}-\d{2}$/.test(tarih) || !Number.isFinite(d.getTime()) ||
          d.toISOString().slice(0, 10) !== tarih || tarih < '1900-01-01' ||
          tarih > new Date().toISOString().slice(0, 10)) throw hata('Geçerli doğum tarihi seç');
      if (!['erkek', 'kiz'].includes(s.cinsiyet)) throw hata('Cinsiyet seç');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw hata('Geçerli sporcu e-postası gir');
      if (typeof h.password !== 'string' || h.password.length < 8 ||
          Buffer.byteLength(h.password, 'utf8') > 72) throw hata('Şifre en az 8 karakter, en fazla 72 UTF-8 baytı olmalı');
      if (b.new_parents?.length || b.existing_parent_ids?.length) throw hata('Güncel sporcu kayıt formunu kullan');
      prepared = ozelProfil.validate(b.private_profile || {});
await ozelProfil.coach(pool, req.user.id);
      const hash = await bcrypt.hash(h.password, 10);
      await ozelProfil.upload(prepared);
      c = await pool.connect(); await c.query('BEGIN'); tx = true;
      const coach = await c.query("SELECT id FROM users WHERE id=$1 AND role='antrenor' FOR SHARE", [req.user.id]);
      if (!coach.rows.length) throw hata('Antrenör yetkisi gerekli', 403);
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [email]);
      const eski = await c.query('SELECT id FROM users WHERE lower(email)=$1', [email]);
      if (eski.rows.length) throw hata('Bu e-posta zaten kayıtlı', 409);
      const a = await c.query(`INSERT INTO athletes(isim,dogum_yili,dogum_tarihi,cinsiyet,grup)
        VALUES($1,$2,$3,$4,$5) RETURNING *`, [isim,d.getUTCFullYear(),tarih,s.cinsiyet,grup]);
      const u = await c.query(`INSERT INTO users(email,password_hash,role,athlete_id)
        VALUES($1,$2,'sporcu',$3) RETURNING id,email,role,athlete_id`, [email,hash,a.rows[0].id]);
      await ozelProfil.save(
  c,
  a.rows[0].id,
  prepared,
  req.user.id
);

commitAttempted = true;
        await c.query('COMMIT'); tx = false;
      res.status(201).json({athlete:a.rows[0], athlete_account:u.rows[0]});
    } catch(e) {
      if (tx) await c.query('ROLLBACK').catch(() => {});
      if (!commitAttempted) {
  await ozelProfil.cleanup(prepared?.path);
}
      res.status(e.code === '23505' ? 409 : e.status || 500).json({mesaj:
        e.code === '23505' ? 'Bu e-posta veya T.C kimlik numarası zaten kayıtlı' : e.status ? e.message : 'Sporcu kaydedilemedi'});
    } finally { if(c) c.release(); }
  });
};
