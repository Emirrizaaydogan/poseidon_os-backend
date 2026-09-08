module.exports = function veliKayitKur(app, pool, bcrypt, girisGerekli, sadeceAntrenor) {
  const fail = (mesaj, status = 400) => Object.assign(new Error(mesaj), {status});
  const idOku = x => { const n = Number(x); if (!Number.isSafeInteger(n) || n <= 0) throw fail('Geçerli sporcu seç'); return n; };
  const cevap = (res,e) => res.status(e.code === '23505' ? 409 : e.status || 500).json({mesaj: e.code === '23505' ? 'E-posta veya seçilen çocuk zaten kullanılıyor. Listeyi yenile.' : e.status ? e.message : 'İşlem tamamlanamadı'});
  app.get('/athletes/register-list', async (req,res) => {
    res.set('Cache-Control','no-store');
    try {
      const r=await pool.query(`SELECT a.id,a.isim,a.dogum_yili,a.grup FROM athletes a
        WHERE NOT EXISTS (SELECT 1 FROM parent_athletes p WHERE p.athlete_id=a.id)
        AND NOT EXISTS (SELECT 1 FROM users u WHERE u.role='veli' AND u.athlete_id=a.id)
        ORDER BY a.isim,a.id`);
      res.json(r.rows);
    } catch(e){cevap(res,e);}
  });
  app.post('/auth/register', async(req,res)=>{
    let c;let tx=false;
    try{
      const b=req.body || {};
      if(b.role !== 'veli') throw fail('Bu ekran yalnızca veli kaydı içindir',403);
      const email=typeof b.email==='string'?b.email.trim().toLowerCase():'';
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw fail('Geçerli e-posta gir');
      if(typeof b.password!=='string'||b.password.length<8||Buffer.byteLength(b.password,'utf8')>72)throw fail('Şifre en az 8 karakter ve en fazla 72 UTF-8 baytı olmalı');
      if(!Array.isArray(b.athlete_ids)||!b.athlete_ids.length||b.athlete_ids.length>10)throw fail('En az bir çocuk seç');
      const ids=[...new Set(b.athlete_ids.map(idOku))].sort((a,b)=>a-b);
      const hash=await bcrypt.hash(b.password,10);
      c=await pool.connect();await c.query('BEGIN');tx=true;
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[email]);
      const eski=await c.query('SELECT id FROM users WHERE lower(email)=$1',[email]);
      if(eski.rows.length)throw fail('Bu e-posta zaten kayıtlı. Giriş yapabilirsin.',409);
      const sporcular=await c.query('SELECT id FROM athletes WHERE id=ANY($1::bigint[]) ORDER BY id FOR UPDATE',[ids]);
      if(sporcular.rows.length!==ids.length)throw fail('Seçilen sporculardan biri artık mevcut değil',409);
      const dolu=await c.query(`SELECT athlete_id FROM parent_athletes WHERE athlete_id=ANY($1::bigint[])
        UNION SELECT athlete_id::bigint FROM users WHERE role='veli' AND athlete_id::bigint=ANY($1::bigint[])`,[ids]);
      if(dolu.rows.length)throw fail('Seçtiğin çocuklardan biri başka bir veliye bağlandı. Listeyi yenileyip tekrar seç.',409);
      const r=await c.query(`INSERT INTO users(email,password_hash,role,athlete_id)
        VALUES($1,$2,'veli',$3) RETURNING id,email,role,athlete_id`,[email,hash,ids[0]]);
      for(const id of ids)await c.query('INSERT INTO parent_athletes(parent_id,athlete_id) VALUES($1,$2)',[r.rows[0].id,id]);
      await c.query('COMMIT');tx=false;res.status(201).json(r.rows[0]);
    }catch(e){if(tx)await c.query('ROLLBACK').catch(()=>{});cevap(res,e);}finally{if(c)c.release();}
  });
  async function cocuklar(userId){
    const r=await pool.query(`SELECT a.id,a.isim,a.dogum_yili,a.grup FROM parent_athletes p
      JOIN athletes a ON a.id=p.athlete_id JOIN users u ON u.id=p.parent_id
      WHERE p.parent_id=$1 AND u.role='veli' ORDER BY a.id`,[userId]);return r.rows;
  }
  app.get('/auth/children',girisGerekli,async(req,res)=>{
    res.set('Cache-Control','no-store');
    try{if(req.user.role!=='veli')throw fail('Veli hesabı gerekli',403);res.json(await cocuklar(req.user.id));}catch(e){cevap(res,e);}
  });
  // Veli için kişisel ekranları seçilen çocukla sınırla.
  for(const path of ['/dues','/attendance','/report-cards']){
    app.get(path,girisGerekli,async(req,res,next)=>{
      if(req.user.role!=='veli')return next();
      try{
        const liste=await cocuklar(req.user.id);
        const secim=req.query.athleteId ?? req.headers['x-athlete-id'] ?? liste[0]?.id;
        const id=idOku(secim);
        if(!liste.some(a=>String(a.id)===String(id)))throw fail('Bu çocuğun bilgilerine erişemezsin',403);
        let sql;const params=[id];
        if(path==='/dues')sql='SELECT * FROM dues WHERE athlete_id=$1 ORDER BY id DESC';
        if(path==='/report-cards')sql=`SELECT rc.*,a.isim AS athlete_isim,a.dogum_yili,a.dogum_tarihi,a.cinsiyet,a.grup
          FROM report_cards rc JOIN athletes a ON a.id=rc.athlete_id WHERE rc.athlete_id=$1 ORDER BY rc.test_date DESC,rc.id DESC`;
        if(path==='/attendance'){
          sql='SELECT t.*,a.isim AS athlete_isim FROM attendance t JOIN athletes a ON a.id=t.athlete_id WHERE t.athlete_id=$1';
          if(req.query.trainingId){params.push(idOku(req.query.trainingId));sql+=' AND t.training_id=$2';}sql+=' ORDER BY t.id';
        }
        res.json((await pool.query(sql,params)).rows);
      }catch(e){cevap(res,e);}
    });
  }
  app.get('/report-cards/:id',girisGerekli,async(req,res,next)=>{
    if(req.user.role!=='veli')return next();
    try{
      const r=await pool.query(`SELECT rc.*,a.isim AS athlete_isim,a.dogum_yili,a.dogum_tarihi,a.cinsiyet,a.grup
        FROM report_cards rc JOIN athletes a ON a.id=rc.athlete_id
        JOIN parent_athletes p ON p.athlete_id=a.id JOIN users u ON u.id=p.parent_id
        WHERE rc.id=$1 AND p.parent_id=$2 AND u.role='veli'`,[idOku(req.params.id),req.user.id]);
      if(!r.rows.length)throw fail('Karne bulunamadı veya erişim yetkin yok',404);res.json(r.rows[0]);
    }catch(e){cevap(res,e);}
  });
  // Antrenör panelinden yeni veli şifresi oluşturma yolunu kapat.
  app.post('/users',girisGerekli,sadeceAntrenor,(req,res,next)=>{
    if(req.body?.role!=='sporcu')return res.status(403).json({mesaj:'Veliler Kayıt Ol ekranından kendileri kaydolmalı'});next();
  });
  // Eski tekli düzeltme ekranı çoklu bağlantıları sessizce silmesin.
  app.patch('/users/:id/link-athlete',girisGerekli,sadeceAntrenor,async(req,res)=>{
    let c;let tx=false;
    try{
      if(!Object.hasOwn(req.body || {},'athlete_id'))throw fail('Sporcu seçimi gerekli');
      const id=req.body.athlete_id===null?null:idOku(req.body.athlete_id);
      c=await pool.connect();await c.query('BEGIN');tx=true;
      const u=await c.query("SELECT id,role FROM users WHERE id=$1 AND role IN ('veli','sporcu') FOR UPDATE",[req.params.id]);
      if(!u.rows.length)throw fail('Hesap bulunamadı',404);
      if(id!==null){const a=await c.query('SELECT id FROM athletes WHERE id=$1 FOR UPDATE',[id]);if(!a.rows.length)throw fail('Sporcu bulunamadı',404);}
      if(u.rows[0].role==='veli'){
        const links=await c.query('SELECT athlete_id FROM parent_athletes WHERE parent_id=$1',[req.params.id]);
        if(links.rows.length>1)throw fail('Birden fazla çocuk bağlı. Tekli eşleştirme ekranından değiştirilemez.');
        if(id!==null){const b=await c.query(`SELECT id FROM users WHERE role='veli' AND athlete_id=$1 AND id<>$2`,[id,req.params.id]);if(b.rows.length)throw fail('Bu çocuk başka bir veliye bağlı',409);}
        await c.query('DELETE FROM parent_athletes WHERE parent_id=$1',[req.params.id]);
        if(id!==null)await c.query('INSERT INTO parent_athletes(parent_id,athlete_id) VALUES($1,$2)',[req.params.id,id]);
      }
      const r=await c.query('UPDATE users SET athlete_id=$1 WHERE id=$2 RETURNING id,email,role,athlete_id',[id,req.params.id]);
      await c.query('COMMIT');tx=false;res.json(r.rows[0]);
    }catch(e){if(tx)await c.query('ROLLBACK').catch(()=>{});cevap(res,e);}finally{if(c)c.release();}
  });
};
