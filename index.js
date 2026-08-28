require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// E-posta gönderimi için SMTP bağlantısı. Bu 4 değeri kendi .env
// dosyanıza eklemeniz gerekiyor: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS.
// (Gmail kullanacaksanız normal şifreniz değil, "Uygulama Şifresi"
// oluşturmanız gerekir — Google hesap ayarlarından.)
const mailGonderici = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_PORT === '465',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sifreSifirlamaKoduGonder(email, kod) {
  await mailGonderici.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Poseidon OS - Şifre Sıfırlama Kodu',
    text: `Şifre sıfırlama kodunuz: ${kod}\nBu kod 15 dakika geçerlidir. Bu isteği siz yapmadıysanız bu e-postayı yok sayabilirsiniz.`,
    html: `
      <div style="font-family: sans-serif;">
        <h2 style="color:#0a1a15;">Poseidon OS</h2>
        <p>Şifre sıfırlama kodunuz:</p>
        <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px;">${kod}</p>
        <p style="color:#666;">Bu kod 15 dakika geçerlidir. Bu isteği siz yapmadıysanız bu e-postayı yok sayabilirsiniz.</p>
      </div>
    `,
  });
}

app.get('/', (req, res) => {
  res.send('Poseidon OS Backend çalışıyor! 🌊');
});

// ---------------- KİMLİK DOĞRULAMA ----------------

// Yeni kullanıcı kaydı (şimdilik herkes kayıt olabiliyor — ileride bunu
// sadece antrenörün davet edebileceği bir sisteme çevirebiliriz)
app.post('/auth/register', async (req, res) => {
  const { email, password, role, athlete_id } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ mesaj: 'E-posta, şifre ve rol zorunludur' });
  }

  try {
    // Şifreyi asla düz metin olarak saklamıyoruz — bcrypt ile "hash"liyoruz.
    // Hash, şifreden geri döndürülemeyen, tek yönlü bir şifreleme işlemi.
    const passwordHash = await bcrypt.hash(password, 10);

    const sonuc = await pool.query(
      'INSERT INTO users (email, password_hash, role, athlete_id) VALUES ($1, $2, $3, $4) RETURNING id, email, role, athlete_id',
      [email, passwordHash, role, athlete_id || null]
    );

    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    if (hata.code === '23505') {
      // Postgres'in "unique constraint" hatası — bu e-posta zaten kayıtlı
      return res.status(409).json({ mesaj: 'Bu e-posta zaten kayıtlı' });
    }
    res.status(500).json({ mesaj: 'Kayıt oluşturulamadı' });
  }
});

// Giriş yapma
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ mesaj: 'E-posta ve şifre zorunludur' });
  }

  try {
    const sonuc = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const kullanici = sonuc.rows[0];

    if (!kullanici) {
      return res.status(401).json({ mesaj: 'E-posta veya şifre hatalı' });
    }

    // Girilen şifreyi, veritabanındaki hash ile karşılaştırıyoruz
    const sifreDogruMu = await bcrypt.compare(password, kullanici.password_hash);
    if (!sifreDogruMu) {
      return res.status(401).json({ mesaj: 'E-posta veya şifre hatalı' });
    }

    // Giriş başarılı — bir "token" oluşturup kullanıcıya veriyoruz.
    // Bu token, kullanıcının kim olduğunu kanıtlayan imzalı bir bilet gibi düşünülebilir.
    const token = jwt.sign(
      { id: kullanici.id, role: kullanici.role },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      id: kullanici.id,
      email: kullanici.email,
      role: kullanici.role,
      athlete_id: kullanici.athlete_id,
    });
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Giriş yapılamadı' });
  }
});

// ---------------- GÜVENLİK KATMANI (MIDDLEWARE) ----------------

// Bu fonksiyon, gelen her isteğin başında "Authorization: Bearer <token>"
// başlığını kontrol ediyor. Token yoksa ya da geçersizse isteği reddediyor.
function girisGerekli(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ mesaj: 'Bu işlem için giriş yapmalısın' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, role } — sonraki fonksiyonlar bunu kullanabilir
    next(); // her şey yolunda, isteğe devam et
  } catch (hata) {
    return res.status(401).json({ mesaj: 'Oturumun geçersiz veya süresi dolmuş, tekrar giriş yap' });
  }
}

// Bu fonksiyon, sadece antrenör rolündeki kullanıcıların geçmesine izin veriyor.
// girisGerekli'den SONRA çalışmalı, çünkü req.user'a ihtiyaç duyuyor.
function sadeceAntrenor(req, res, next) {
  if (req.user.role !== 'antrenor') {
    return res.status(403).json({ mesaj: 'Bu işlem için antrenör yetkisi gerekli' });
  }
  next();
}

// ---------------- SPORCULAR ----------------

app.get('/athletes', girisGerekli, async (req, res) => {
  try {
    const sonuc = await pool.query('SELECT * FROM athletes ORDER BY id ASC');
    res.json(sonuc.rows);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: sporcular getirilemedi' });
  }
});
// ---------------- KAYIT EKRANI SPORCULARI ----------------

// Veli kayıt ekranında çocuk seçebilmek için kullanılır.
// Bu endpoint giriş yapmadan da sadece sporcu ID ve isimlerini döndürür.
app.get('/athletes/register-list', async (req, res) => {
  try {
    const sonuc = await pool.query(
      'SELECT id, isim FROM athletes ORDER BY id ASC'
    );

    res.json(sonuc.rows);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({
      mesaj: 'Kayıt için sporcular getirilemedi',
    });
  }
}); 
app.post('/athletes', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { isim, dogum_yili, grup, en_iyi_derece, en_iyi_derece_stil } = req.body;
  try {
    const sonuc = await pool.query(
      'INSERT INTO athletes (isim, dogum_yili, grup, en_iyi_derece, en_iyi_derece_stil) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [isim, dogum_yili, grup, en_iyi_derece, en_iyi_derece_stil || null]
    );
    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: sporcu eklenemedi' });
  }
});

// Antrenör, mevcut bir sporcunun en iyi derecesini/stilini sonradan
// düzenleyebilir (örn. yeni bir yarış sonrası kayıt güncellenir).
app.put('/athletes/:id', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { id } = req.params;
  const { isim, dogum_yili, grup, en_iyi_derece, en_iyi_derece_stil } = req.body;
  try {
    const sonuc = await pool.query(
      `UPDATE athletes
       SET isim = $1, dogum_yili = $2, grup = $3, en_iyi_derece = $4, en_iyi_derece_stil = $5
       WHERE id = $6 RETURNING *`,
      [isim, dogum_yili, grup, en_iyi_derece, en_iyi_derece_stil || null, id]
    );
    if (sonuc.rows.length === 0) {
      return res.status(404).json({ mesaj: 'Sporcu bulunamadı' });
    }
    res.json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: sporcu güncellenemedi' });
  }
});

app.delete('/athletes/:id', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { id } = req.params;
  try {
    const sonuc = await pool.query('DELETE FROM athletes WHERE id = $1 RETURNING *', [id]);
    if (sonuc.rows.length === 0) {
      return res.status(404).json({ mesaj: 'Sporcu bulunamadı' });
    }
    res.status(204).send();
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: sporcu silinemedi' });
  }
});

// ---------------- ANTRENMANLAR ----------------

app.get('/trainings', girisGerekli, async (req, res) => {
  try {
    const sonuc = await pool.query('SELECT * FROM trainings ORDER BY id ASC');
    res.json(sonuc.rows);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: antrenmanlar getirilemedi' });
  }
});

app.post('/trainings', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { baslik, tarih, havuz, sure, setler } = req.body;
  try {
    const sonuc = await pool.query(
      'INSERT INTO trainings (baslik, tarih, havuz, sure, setler) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [baslik, tarih, havuz, sure, JSON.stringify(setler || [])]
    );
    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: antrenman eklenemedi' });
  }
});

// ---------------- PERFORMANS ----------------

// ?athleteId=5 gibi bir sorguyla o sporcuya ait kayıtları filtreleyebiliyoruz
app.get('/performance', girisGerekli, async (req, res) => {
  const { athleteId } = req.query;
  try {
    let sonuc;
    if (athleteId) {
      sonuc = await pool.query('SELECT * FROM performance WHERE athlete_id = $1 ORDER BY id ASC', [athleteId]);
    } else {
      sonuc = await pool.query('SELECT * FROM performance ORDER BY id ASC');
    }
    res.json(sonuc.rows);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: performans kayıtları getirilemedi' });
  }
});

app.post('/performance', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { athlete_id, stil, mesafe, derece, tarih } = req.body;
  try {
    const sonuc = await pool.query(
      'INSERT INTO performance (athlete_id, stil, mesafe, derece, tarih) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [athlete_id, stil, mesafe, derece, tarih]
    );
    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: performans kaydı eklenemedi' });
  }
});

// ---------------- YOKLAMA ----------------

app.get('/attendance', girisGerekli, async (req, res) => {
  const { trainingId } = req.query;
  try {
    let sonuc;
    if (trainingId) {
      sonuc = await pool.query('SELECT * FROM attendance WHERE training_id = $1 ORDER BY id ASC', [trainingId]);
    } else {
      sonuc = await pool.query('SELECT * FROM attendance ORDER BY id ASC');
    }
    res.json(sonuc.rows);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: yoklama kayıtları getirilemedi' });
  }
});

app.post('/attendance', girisGerekli, async (req, res) => {
  const { training_id } = req.body;
  try {
    const sonuc = await pool.query(
      'INSERT INTO attendance (training_id) VALUES ($1) RETURNING *',
      [training_id]
    );
    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: yoklama eklenemedi' });
  }
});

// ---------------- AİDAT ----------------

app.get('/dues', girisGerekli, async (req, res) => {
  const { athleteId } = req.query;

  try {
    let sonuc;

    // ANTRENÖR
    // Antrenör bütün aidatları görebilir.
    if (req.user.role === 'antrenor') {
      if (athleteId) {
        sonuc = await pool.query(
          `
          SELECT *
          FROM dues
          WHERE athlete_id = $1
          ORDER BY id DESC
          `,
          [athleteId]
        );
      } else {
        sonuc = await pool.query(
          `
          SELECT *
          FROM dues
          ORDER BY id DESC
          `
        );
      }

      return res.json(sonuc.rows);
    }

    // VELİ
    // Veli sadece kendi çocuğunun aidatlarını görebilir.
    if (req.user.role === 'veli') {
      const kullanici = await pool.query(
        `
        SELECT athlete_id
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      const veliSporcuId = kullanici.rows[0]?.athlete_id;

      if (!veliSporcuId) {
        return res.status(403).json({
          mesaj: 'Bu veli hesabına bağlı sporcu bulunamadı'
        });
      }

      // Veli başka bir sporcunun ID'sini göndermeye çalışırsa engelle.
      if (
        athleteId &&
        parseInt(athleteId) !== parseInt(veliSporcuId)
      ) {
        return res.status(403).json({
          mesaj: 'Bu sporcunun aidat bilgilerine erişemezsin'
        });
      }

      sonuc = await pool.query(
        `
        SELECT *
        FROM dues
        WHERE athlete_id = $1
        ORDER BY id DESC
        `,
        [veliSporcuId]
      );

      return res.json(sonuc.rows);
    }

    return res.status(403).json({
      mesaj: 'Aidat bilgilerine erişim yetkin yok'
    });

  } catch (hata) {
    console.error(hata);

    res.status(500).json({
      mesaj: 'Hata: aidat kayıtları getirilemedi'
    });
  }
});
// ---------------- AİDAT SON ÖDEME TARİHİ ----------------

// Antrenör, belirlenen ayın aidatlarının son ödeme tarihini günceller.
app.patch(
  '/dues/deadline',
  girisGerekli,
  sadeceAntrenor,
  async (req, res) => {
    const { tarih, ay } = req.body;

    if (!tarih) {
      return res.status(400).json({
        mesaj: 'Son ödeme tarihi zorunludur',
      });
    }

    if (!ay) {
      return res.status(400).json({
        mesaj: 'Aidat ayı zorunludur',
      });
    }

    try {
      const sonuc = await pool.query(
        `
        UPDATE dues
        SET son_odeme_tarihi = $1
        WHERE ay = $2
        RETURNING *
        `,
        [tarih, ay]
      );

      return res.json({
        mesaj: 'Son ödeme tarihi güncellendi',
        guncellenen_sayi: sonuc.rows.length,
        aidatlar: sonuc.rows,
      });
    } catch (hata) {
      console.error(hata);

      return res.status(500).json({
        mesaj: 'Son ödeme tarihi güncellenemedi',
      });
    }
  }
);
//-------------Aidat Ekleme-----------------
app.post('/dues', girisGerekli, sadeceAntrenor, async (req, res) => {
  const {   athlete_id, ay, tutar, son_odeme_tarihi } = req.body;
  try {
    const sonuc = await pool.query(
      'INSERT INTO dues (athlete_id, ay, tutar, son_odeme_tarihi, odendi) VALUES ($1, $2, $3, $4, false) RETURNING *',
      [athlete_id, ay, tutar, son_odeme_tarihi]
    );
    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: aidat kaydı eklenemedi' });
  }
});
// ---------------- AİDAT SON ÖDEME TARİHİ ----------------

// Antrenör, mevcut ayın aidatlarının son ödeme tarihini belirler.
app.patch('/dues/deadline', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { tarih, ay } = req.body;

  if (!tarih) {
    return res.status(400).json({
      mesaj: 'Son ödeme tarihi zorunludur'
    });
  }

  try {
    const sonuc = await pool.query(
      `
      UPDATE dues
      SET son_odeme_tarihi = $1
      WHERE ay = $2
      RETURNING *
      `,
      [tarih, ay]
    );

    res.json({
      mesaj: 'Son ödeme tarihi güncellendi',
      guncellenen_sayi: sonuc.rows.length,
      aidatlar: sonuc.rows,
    });
  } catch (hata) {
    console.error(hata);

    res.status(500).json({
      mesaj: 'Son ödeme tarihi güncellenemedi'
    });
  }
});
// Aidatı "ödendi" olarak işaretle
app.patch('/dues/:id/pay', girisGerekli, async (req, res) => {
  const { id } = req.params;
  try {
    const sonuc = await pool.query(
      'UPDATE dues SET odendi = true, odeme_tarihi = now() WHERE id = $1 RETURNING *',
      [id]
    );
    res.json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: ödeme işaretlenemedi' });
  }
});

// ---------------- KULLANICI YÖNETİMİ (VELİ / SPORCU HESAPLARI) ----------------

// Antrenör panelinden sisteme kayıtlı veli/sporcu hesaplarını listeler.
// Güvenlik için antrenör hesapları bu listede hiç görünmez/silinemez.
app.get('/users', girisGerekli, sadeceAntrenor, async (req, res) => {
  try {
    const sonuc = await pool.query(`
      SELECT u.id, u.email, u.role, u.athlete_id, a.isim AS athlete_isim
      FROM users u
      LEFT JOIN athletes a ON a.id = u.athlete_id
      WHERE u.role IN ('veli', 'sporcu')
      ORDER BY u.id DESC
    `);
    res.json(sonuc.rows);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: kullanıcılar getirilemedi' });
  }
});

// Antrenör, kayıt ekranını beklemeden doğrudan bir veli/sporcu hesabı açar.
// Aynı anda, o hesabı sistemdeki bir sporcu kaydıyla eşleştirebilir.
app.post('/users', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { email, password, role, athlete_id } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ mesaj: 'E-posta, şifre ve rol zorunludur' });
  }
  if (!['veli', 'sporcu'].includes(role)) {
    return res.status(400).json({ mesaj: 'Sadece veli veya sporcu hesabı eklenebilir' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const sonuc = await pool.query(
      'INSERT INTO users (email, password_hash, role, athlete_id) VALUES ($1, $2, $3, $4) RETURNING id, email, role, athlete_id',
      [email, passwordHash, role, athlete_id || null]
    );
    res.status(201).json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    if (hata.code === '23505') {
      return res.status(409).json({ mesaj: 'Bu e-posta zaten kayıtlı' });
    }
    res.status(500).json({ mesaj: 'Kullanıcı eklenemedi' });
  }
});

// Bir veli/sporcu hesabının hangi sporcu kaydına bağlı olduğunu günceller
// (kayıt sırasında yanlış/eksik eşleştirme yapılmışsa antrenör düzeltebilir).
app.patch('/users/:id/link-athlete', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { id } = req.params;
  const { athlete_id } = req.body;
  try {
    const sonuc = await pool.query(
      `UPDATE users SET athlete_id = $1 WHERE id = $2 AND role IN ('veli','sporcu') RETURNING id, email, role, athlete_id`,
      [athlete_id || null, id]
    );
    if (sonuc.rows.length === 0) {
      return res.status(404).json({ mesaj: 'Kullanıcı bulunamadı' });
    }
    res.json(sonuc.rows[0]);
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: eşleştirme güncellenemedi' });
  }
});

// Antrenör bir veli/sporcu hesabının erişimini kaldırır.
// role IN ('veli','sporcu') şartı, yanlışlıkla bir antrenör hesabının
// silinmesini (kendi hesabı dahil) engelliyor.
app.delete('/users/:id', girisGerekli, sadeceAntrenor, async (req, res) => {
  const { id } = req.params;
  try {
    const sonuc = await pool.query(
      `DELETE FROM users WHERE id = $1 AND role IN ('veli','sporcu') RETURNING *`,
      [id]
    );
    if (sonuc.rows.length === 0) {
      return res.status(404).json({ mesaj: 'Kullanıcı bulunamadı ya da silinemez' });
    }
    res.status(204).send();
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: kullanıcı silinemedi' });
  }
});

// ---------------- ŞİFRE SIFIRLAMA ----------------

// Kullanıcı e-postasını girer, sistemde kayıtlıysa 6 haneli bir kod
// üretilip e-postasına gönderilir. Güvenlik için: e-posta kayıtlı
// olmasa bile aynı başarı mesajı döner (böylece dışarıdan bir
// e-postanın sistemde olup olmadığı anlaşılamaz).
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ mesaj: 'E-posta zorunludur' });
  }

  try {
    const kullaniciSonuc = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (kullaniciSonuc.rows.length > 0) {
      const kullaniciId = kullaniciSonuc.rows[0].id;
      const kod = crypto.randomInt(100000, 999999).toString();
      const sonKullanma = new Date(Date.now() + 15 * 60 * 1000); // 15 dakika

      await pool.query(
        'INSERT INTO password_resets (user_id, token, son_kullanma) VALUES ($1, $2, $3)',
        [kullaniciId, kod, sonKullanma]
      );

      try {
        await sifreSifirlamaKoduGonder(email, kod);
      } catch (mailHatasi) {
        console.error('E-posta gönderilemedi:', mailHatasi);
        // E-posta gönderimi başarısız olursa kullanıcıya bunu açıkça
        // söylüyoruz — aksi halde kod hiç gelmediği halde "gönderildi"
        // denip kullanıcı boşuna beklerdi.
        return res.status(500).json({
          mesaj: 'Kod oluşturuldu ama e-posta gönderilemedi. SMTP ayarlarını kontrol edin.',
        });
      }
    }

    res.json({ mesaj: 'E-posta adresine kayıtlıysa bir sıfırlama kodu gönderildi' });
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: sıfırlama kodu gönderilemedi' });
  }
});

// Kullanıcı e-postasına gelen kodu ve yeni şifresini girer.
app.post('/auth/reset-password', async (req, res) => {
  const { email, kod, yeniSifre } = req.body;
  if (!email || !kod || !yeniSifre) {
    return res.status(400).json({ mesaj: 'E-posta, kod ve yeni şifre zorunludur' });
  }
  if (yeniSifre.length < 6) {
    return res.status(400).json({ mesaj: 'Şifre en az 6 karakter olmalı' });
  }

  try {
    const kullaniciSonuc = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    if (kullaniciSonuc.rows.length === 0) {
      return res.status(400).json({ mesaj: 'Kod geçersiz veya süresi dolmuş' });
    }
    const kullaniciId = kullaniciSonuc.rows[0].id;

    const kodSonuc = await pool.query(
      `SELECT * FROM password_resets
       WHERE user_id = $1 AND token = $2 AND kullanildi = false AND son_kullanma > now()
       ORDER BY id DESC LIMIT 1`,
      [kullaniciId, kod]
    );
    if (kodSonuc.rows.length === 0) {
      return res.status(400).json({ mesaj: 'Kod geçersiz veya süresi dolmuş' });
    }

    const passwordHash = await bcrypt.hash(yeniSifre, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [
      passwordHash,
      kullaniciId,
    ]);
    await pool.query('UPDATE password_resets SET kullanildi = true WHERE id = $1', [
      kodSonuc.rows[0].id,
    ]);

    res.json({ mesaj: 'Şifre başarıyla güncellendi' });
  } catch (hata) {
    console.error(hata);
    res.status(500).json({ mesaj: 'Hata: şifre güncellenemedi' });
  }
});

app.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
});