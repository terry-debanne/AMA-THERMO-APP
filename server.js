// ═══════════════════════════════════════════════════════
// THERMO APP — BACKEND API v2
// Système d'auth fiable : PINs hashés en bcrypt
// ═══════════════════════════════════════════════════════

const express  = require('express');
const Database = require('better-sqlite3');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const helmet   = require('helmet');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thermo_secret_changez_moi_en_prod';

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'thermo.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ═══════════════════════════════════════════════════════
// SCHÉMA BASE DE DONNÉES
// ═══════════════════════════════════════════════════════
db.exec(`
  CREATE TABLE IF NOT EXISTS salaries (
    id         INTEGER PRIMARY KEY,
    nom        TEXT NOT NULL,
    prenom     TEXT,
    role       TEXT NOT NULL DEFAULT 'operateur',
    pin_hash   TEXT NOT NULL,
    actif      INTEGER DEFAULT 1,
    data       TEXT,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS of_data (
    ref        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS devis (
    ref        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS stock (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS saisies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    data       TEXT NOT NULL,
    created_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS planning (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS controles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    data       TEXT NOT NULL,
    created_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS conso_poudre (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    data       TEXT NOT NULL,
    created_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS clients (
    id         INTEGER PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS fournisseurs (
    id         INTEGER PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS connexions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    salarie_id   INTEGER,
    nom          TEXT,
    role         TEXT,
    ip           TEXT,
    user_agent   TEXT,
    connected_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );

  CREATE TABLE IF NOT EXISTS app_data (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT DEFAULT (CURRENT_TIMESTAMP)
  );
`);

// Créer les salariés par défaut si la table est vide
const salCount = db.prepare('SELECT COUNT(*) as n FROM salaries').get().n;
if (salCount === 0) {
  // Pas de salariés par défaut — l'admin créera ses salariés depuis l'app
  console.log('Base de données initialisée (aucun salarié par défaut)');
}

// ═══════════════════════════════════════════════════════
// MIDDLEWARES
// ═══════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '10mb' }));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  const f = path.join(__dirname, 'public', 'index.html');
  fs.existsSync(f) ? res.sendFile(f) : res.send('<h2>Thermo API OK</h2>');
});

// Auth middleware
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide ou expiré' }); }
}

// ═══════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════

// GET /api/salaries-public — liste publique pour la page de connexion (sans auth, sans PIN)
app.get('/api/salaries-public', (req, res) => {
  // 1. Essayer depuis app_data (SALARIES_APP complet sauvegardé par l'app)
  const appData = db.prepare('SELECT value FROM app_data WHERE key = ?').get('SALARIES_APP');
  if (appData) {
    try {
      const salaries = JSON.parse(appData.value);
      if (Array.isArray(salaries) && salaries.length) {
        return res.json(salaries.filter(s => s.actif).map(s => {
          const { pin, pin_hash, ...safe } = s;
          return safe;
        }));
      }
    } catch(e) {}
  }
  // 2. Fallback : table salaries
  const rows = db.prepare('SELECT id, nom, prenom, role, actif, data FROM salaries WHERE actif = 1 ORDER BY id').all();
  res.json(rows.map(r => {
    const base = r.data ? JSON.parse(r.data) : {};
    const { pin, pin_hash, ...safe } = base;
    return { ...safe, id: r.id, nom: r.nom, prenom: r.prenom, role: r.role, actif: true };
  }));
});

// GET /api/salaries-app — récupérer SALARIES_APP complet (avec PINs, authentifié)
app.get('/api/salaries-app', auth, (req, res) => {
  const r = db.prepare('SELECT value FROM app_data WHERE key = ?').get('SALARIES_APP');
  res.json(r ? JSON.parse(r.value) : []);
});

// PUT /api/salaries-app — sauvegarder SALARIES_APP complet (avec PINs, pour sync multi-postes)
app.put('/api/salaries-app', auth, (req, res) => {
  try {
    const salaries = Array.isArray(req.body) ? req.body : [];
    db.prepare('INSERT INTO app_data (key, value, updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at')
      .run('SALARIES_APP', JSON.stringify(salaries));
    res.json({ ok: true });
  } catch(e) {
    console.error('PUT salaries-app error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const pin = String(req.body?.pin || '');
  if (!pin) return res.status(400).json({ error: 'PIN requis' });

  // 1. Chercher dans SALARIES_APP (source principale avec PINs en clair)
  const appData = db.prepare('SELECT value FROM app_data WHERE key = ?').get('SALARIES_APP');
  if (appData) {
    try {
      const salaries = JSON.parse(appData.value);
      for (const s of salaries) {
        if (s.actif && String(s.pin) === pin) {
          const nom = s.prenom ? s.prenom + ' ' + s.nom : s.nom;
          const token = jwt.sign({ id: s.id, role: s.role, nom }, JWT_SECRET, { expiresIn: '24h' });
          const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
          db.prepare('INSERT INTO connexions (salarie_id, nom, role, ip, user_agent) VALUES (?,?,?,?,?)').run(s.id, nom, s.role, ip, req.headers['user-agent'] || '');
          return res.json({ token, role: s.role, nom, id: s.id });
        }
      }
    } catch(e) {}
  }

  // 2. Fallback : table salaries hashée
  const salaries = db.prepare('SELECT * FROM salaries WHERE actif = 1').all();
  for (const s of salaries) {
    if (bcrypt.compareSync(pin, s.pin_hash)) {
      const nom = s.prenom ? s.prenom + ' ' + s.nom : s.nom;
      const token = jwt.sign({ id: s.id, role: s.role, nom }, JWT_SECRET, { expiresIn: '24h' });
      // Log connexion
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      db.prepare('INSERT INTO connexions (salarie_id, nom, role, ip, user_agent) VALUES (?,?,?,?,?)').run(s.id, nom, s.role, ip, req.headers['user-agent'] || '');
      return res.json({ token, role: s.role, nom, id: s.id });
    }
  }
  res.status(401).json({ error: 'PIN incorrect' });
});

// PUT /api/auth/pin/:id — changer le PIN d'un salarié (admin seulement ou soi-même)
app.put('/api/auth/pin/:id', auth, (req, res) => {
  const targetId = parseInt(req.params.id);
  const { pin } = req.body;
  if (!pin || String(pin).length < 4) return res.status(400).json({ error: 'PIN trop court (minimum 4 caractères)' });
  // Seul admin peut changer le PIN d'un autre
  if (req.user.role !== 'admin' && req.user.id !== targetId) return res.status(403).json({ error: 'Non autorisé' });
  db.prepare('UPDATE salaries SET pin_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(bcrypt.hashSync(String(pin), 10), targetId);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// SALARIÉS
// ═══════════════════════════════════════════════════════

app.get('/api/salaries', auth, (req, res) => {
  const rows = db.prepare('SELECT id, nom, prenom, role, actif, data FROM salaries ORDER BY id').all();
  res.json(rows.map(r => {
    const base = r.data ? JSON.parse(r.data) : {};
    return { ...base, id: r.id, nom: r.nom, prenom: r.prenom, role: r.role, actif: r.actif === 1 };
  }));
});

// Upsert un salarié (sans PIN — le PIN se change via /api/auth/pin)
app.put('/api/salaries/:id', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  const id = parseInt(req.params.id);
  const { nom, prenom, role, actif, data } = req.body;
  const exists = db.prepare('SELECT id FROM salaries WHERE id = ?').get(id);
  if (exists) {
    db.prepare('UPDATE salaries SET nom=?, prenom=?, role=?, actif=?, data=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(nom, prenom||'', role||'operateur', actif?1:0, JSON.stringify(req.body), id);
  } else {
    // Nouveau salarié — PIN par défaut = "1234", doit être changé
    const pin_hash = bcrypt.hashSync('1234', 10);
    db.prepare('INSERT INTO salaries (id, nom, prenom, role, actif, pin_hash, data) VALUES (?,?,?,?,?,?,?)').run(id, nom, prenom||'', role||'operateur', actif?1:0, pin_hash, JSON.stringify(req.body));
  }
  res.json({ ok: true });
});

app.delete('/api/salaries/:id', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  db.prepare('DELETE FROM salaries WHERE id = ?').run(parseInt(req.params.id));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// OF
// ═══════════════════════════════════════════════════════

app.get('/api/of', auth, (req, res) => {
  const rows = db.prepare('SELECT ref, data FROM of_data').all();
  const r = {};
  for (const row of rows) r[row.ref] = JSON.parse(row.data);
  res.json(r);
});

app.put('/api/of/:ref', auth, (req, res) => {
  db.prepare('INSERT INTO of_data (ref, data, updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(ref) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at').run(req.params.ref, JSON.stringify(req.body));
  res.json({ ok: true });
});

app.delete('/api/of/:ref', auth, (req, res) => {
  db.prepare('DELETE FROM of_data WHERE ref = ?').run(req.params.ref);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// DEVIS
// ═══════════════════════════════════════════════════════

app.get('/api/devis', auth, (req, res) => {
  res.json(db.prepare('SELECT data FROM devis').all().map(r => JSON.parse(r.data)));
});

app.put('/api/devis/:ref', auth, (req, res) => {
  db.prepare('INSERT INTO devis (ref, data) VALUES (?,?) ON CONFLICT(ref) DO UPDATE SET data=excluded.data').run(req.params.ref, JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// STOCK
// ═══════════════════════════════════════════════════════

app.get('/api/stock', auth, (req, res) => {
  const r = db.prepare('SELECT data FROM stock ORDER BY id DESC LIMIT 1').get();
  res.json(r ? JSON.parse(r.data) : []);
});

app.put('/api/stock', auth, (req, res) => {
  db.prepare('DELETE FROM stock').run();
  db.prepare('INSERT INTO stock (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// SAISIES TEMPS
// ═══════════════════════════════════════════════════════

app.get('/api/saisies', auth, (req, res) => {
  res.json(db.prepare('SELECT data FROM saisies ORDER BY id').all().map(r => JSON.parse(r.data)));
});

app.post('/api/saisies', auth, (req, res) => {
  db.prepare('INSERT INTO saisies (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// PLANNING
// ═══════════════════════════════════════════════════════

app.get('/api/planning', auth, (req, res) => {
  const r = db.prepare('SELECT data FROM planning ORDER BY id DESC LIMIT 1').get();
  res.json(r ? JSON.parse(r.data) : []);
});

app.put('/api/planning', auth, (req, res) => {
  db.prepare('DELETE FROM planning').run();
  db.prepare('INSERT INTO planning (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// CONTRÔLES / CONSO POUDRE
// ═══════════════════════════════════════════════════════

app.get('/api/controles', auth, (req, res) => {
  res.json(db.prepare('SELECT data FROM controles ORDER BY id').all().map(r => JSON.parse(r.data)));
});
app.post('/api/controles', auth, (req, res) => {
  db.prepare('INSERT INTO controles (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

app.get('/api/conso-poudre', auth, (req, res) => {
  res.json(db.prepare('SELECT data FROM conso_poudre ORDER BY id').all().map(r => JSON.parse(r.data)));
});
app.post('/api/conso-poudre', auth, (req, res) => {
  db.prepare('INSERT INTO conso_poudre (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// CLIENTS / FOURNISSEURS
// ═══════════════════════════════════════════════════════

app.get('/api/clients', auth, (req, res) => {
  res.json(db.prepare('SELECT data FROM clients ORDER BY id').all().map(r => JSON.parse(r.data)));
});
app.put('/api/clients', auth, (req, res) => {
  const clients = Array.isArray(req.body) ? req.body : [];
  db.prepare('DELETE FROM clients').run();
  const ins = db.prepare('INSERT INTO clients (id, data) VALUES (?,?)');
  db.transaction(list => { for (const c of list) ins.run(c.id, JSON.stringify(c)); })(clients);
  res.json({ ok: true });
});

app.get('/api/fournisseurs', auth, (req, res) => {
  res.json(db.prepare('SELECT data FROM fournisseurs ORDER BY id').all().map(r => JSON.parse(r.data)));
});
app.put('/api/fournisseurs', auth, (req, res) => {
  const fournisseurs = Array.isArray(req.body) ? req.body : [];
  db.prepare('DELETE FROM fournisseurs').run();
  const ins = db.prepare('INSERT INTO fournisseurs (id, data) VALUES (?,?)');
  db.transaction(list => { for (const f of list) ins.run(f.id, JSON.stringify(f)); })(fournisseurs);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// APP DATA (settings, modèles horaires, etc.)
// ═══════════════════════════════════════════════════════

app.get('/api/app-data/:key', auth, (req, res) => {
  const r = db.prepare('SELECT value FROM app_data WHERE key = ?').get(req.params.key);
  res.json(r ? JSON.parse(r.value) : null);
});

app.put('/api/app-data/:key', auth, (req, res) => {
  db.prepare('INSERT INTO app_data (key, value, updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at').run(req.params.key, JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// CONNEXIONS (journal)
// ═══════════════════════════════════════════════════════

app.get('/api/connexions', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  const { salarie_id, limit } = req.query;
  let q = 'SELECT * FROM connexions';
  const p = [];
  if (salarie_id) { q += ' WHERE salarie_id = ?'; p.push(salarie_id); }
  q += ' ORDER BY id DESC';
  if (limit) { q += ' LIMIT ?'; p.push(parseInt(limit)); }
  res.json(db.prepare(q).all(...p));
});

app.delete('/api/connexions', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  db.prepare('DELETE FROM connexions').run();
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// BACKUP
// ═══════════════════════════════════════════════════════

app.get('/api/backup', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  const ofRows = db.prepare('SELECT ref, data FROM of_data').all();
  const ofObj = {};
  for (const r of ofRows) ofObj[r.ref] = JSON.parse(r.data);
  const backup = {
    exportedAt: new Date().toISOString(),
    OF_DATA:    ofObj,
    DEVIS_DATA: db.prepare('SELECT data FROM devis').all().map(r => JSON.parse(r.data)),
    STOCK_DATA: (() => { const r = db.prepare('SELECT data FROM stock ORDER BY id DESC LIMIT 1').get(); return r ? JSON.parse(r.data) : []; })(),
    SAISIES:    db.prepare('SELECT data FROM saisies').all().map(r => JSON.parse(r.data)),
    PLANNING:   (() => { const r = db.prepare('SELECT data FROM planning ORDER BY id DESC LIMIT 1').get(); return r ? JSON.parse(r.data) : []; })(),
    CONTROLES:  db.prepare('SELECT data FROM controles').all().map(r => JSON.parse(r.data)),
    CONSO:      db.prepare('SELECT data FROM conso_poudre').all().map(r => JSON.parse(r.data)),
  };
  res.setHeader('Content-Disposition', `attachment; filename="thermo-backup-${new Date().toISOString().slice(0,10)}.json"`);
  res.json(backup);
});

// DELETE /api/salaries-app/reset — vider SALARIES_APP (admin seulement)
app.delete('/api/salaries-app/reset', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  db.prepare('DELETE FROM app_data WHERE key = ?').run('SALARIES_APP');
  res.json({ ok: true });
});

// Route diagnostic temporaire
app.get('/api/diag', (req, res) => {
  try {
    const salaries = db.prepare('SELECT id, nom, prenom, role, actif, data FROM salaries ORDER BY id').all();
    const appData = db.prepare('SELECT key FROM app_data').all();
    res.json({ salaries: salaries.map(s => ({id:s.id, nom:s.nom, role:s.role, actif:s.actif, hasPin: !!(s.data && JSON.parse(s.data||'{}').pin)})), appData: appData.map(r=>r.key) });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Nettoyer doublons salariés
app.get('/api/cleanup', (req, res) => {
  if (req.query.key !== 'THERMO2026') return res.status(403).json({error:'Clé incorrecte'});
  try {
    // Garder uniquement l'admin id:1, supprimer tout le reste
    db.prepare('DELETE FROM salaries WHERE id != 1').run();
    db.prepare('DELETE FROM app_data WHERE key = ?').run('SALARIES_APP');
    const rows = db.prepare('SELECT id, nom, role FROM salaries').all();
    res.json({ ok: true, remaining: rows });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.use((req, res) => res.status(404).json({ error: 'Route inconnue' }));

app.listen(PORT, () => {
  console.log(`✅ Thermo API démarrée port ${PORT}`);
  console.log(`📦 BDD: ${DB_PATH}`);
});
