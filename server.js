// ═══════════════════════════════════════════════════════
// THERMO APP — BACKEND API
// Node.js + Express + SQLite (better-sqlite3)
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

// ── Dossier data (Railway monte un volume persistant sur /data) ──
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'thermo.db');
const db = new Database(DB_PATH);

// ═══════════════════════════════════════════════════════
// INIT BASE DE DONNÉES
// ═══════════════════════════════════════════════════════
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS connexions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    salarie_id INTEGER,
    nom        TEXT,
    role       TEXT,
    pin        TEXT,
    ip         TEXT,
    user_agent TEXT,
    connected_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS clients (
    id       INTEGER PRIMARY KEY,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fournisseurs (
    id       INTEGER PRIMARY KEY,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS salaries (
    id       INTEGER PRIMARY KEY,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    role     TEXT NOT NULL UNIQUE,
    pin_hash TEXT NOT NULL,
    nom      TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS of_data (
    ref      TEXT PRIMARY KEY,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS devis (
    ref      TEXT PRIMARY KEY,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS stock (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS saisies (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    data     TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS planning (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    data     TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS controles (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    data     TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS conso_poudre (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    data     TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Créer les utilisateurs par défaut si la table est vide
const userCount = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
if (userCount === 0) {
  const defaultUsers = [
    { role: 'admin',      pin: '1234', nom: 'Administrateur' },
    { role: 'resp_prod',  pin: '2580', nom: 'Responsable Production' },
    { role: 'operateur',  pin: '1111', nom: 'Opérateur' },
  ];
  const insertUser = db.prepare('INSERT INTO users (role, pin_hash, nom) VALUES (?, ?, ?)');
  for (const u of defaultUsers) {
    insertUser.run(u.role, bcrypt.hashSync(u.pin, 10), u.nom);
  }
  console.log('Utilisateurs par défaut créés.');
}

// ═══════════════════════════════════════════════════════
// MIDDLEWARES
// ═══════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: '*', // En prod, remplacer par votre domaine exact
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10mb' }));

// Servir le frontend (thermo-app.html) à la racine
const FRONTEND_PATH = path.join(__dirname, 'public', 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(FRONTEND_PATH)) {
    res.sendFile(FRONTEND_PATH);
  } else {
    res.send('<h2>Thermo API OK — placez votre thermo-app.html dans /public/index.html</h2>');
  }
});
app.use(express.static(path.join(__dirname, 'public')));

// ── Middleware Auth JWT ──
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ═══════════════════════════════════════════════════════
// ROUTES AUTH
// ═══════════════════════════════════════════════════════

// POST /api/auth/login — connexion par PIN
app.post('/api/auth/login', (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'PIN requis' });

  const pinStr = String(pin);

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const ua = req.headers['user-agent'] || '';

  // 1. Chercher dans les salariés (PINs en clair)
  const salRows = db.prepare('SELECT data FROM salaries').all();
  for (const row of salRows) {
    const s = JSON.parse(row.data);
    if (s.actif && String(s.pin) === pinStr) {
      const nom = s.prenom ? s.prenom + ' ' + s.nom : s.nom;
      const token = jwt.sign({ id: s.id, role: s.role, nom }, JWT_SECRET, { expiresIn: '12h' });
      db.prepare('INSERT INTO connexions (salarie_id, nom, role, pin, ip, user_agent) VALUES (?,?,?,?,?,?)').run(s.id, nom, s.role, pinStr, ip, ua);
      return res.json({ token, role: s.role, nom });
    }
  }

  // 2. Fallback : chercher dans les users par défaut (bcrypt)
  const users = db.prepare('SELECT * FROM users').all();
  for (const u of users) {
    if (bcrypt.compareSync(pinStr, u.pin_hash)) {
      const token = jwt.sign({ id: u.id, role: u.role, nom: u.nom }, JWT_SECRET, { expiresIn: '12h' });
      db.prepare('INSERT INTO connexions (salarie_id, nom, role, pin, ip, user_agent) VALUES (?,?,?,?,?,?)').run(u.id, u.nom, u.role, pinStr, ip, ua);
      return res.json({ token, role: u.role, nom: u.nom });
    }
  }

  res.status(401).json({ error: 'PIN incorrect' });
});

// PUT /api/auth/pin — changer son PIN
app.put('/api/auth/pin', authMiddleware, (req, res) => {
  const { newPin } = req.body;
  if (!newPin || String(newPin).length < 4) return res.status(400).json({ error: 'PIN trop court (min 4)' });
  const hash = bcrypt.hashSync(String(newPin), 10);
  db.prepare('UPDATE users SET pin_hash = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTE BOOTSTRAP — sync initiale sans auth (si BDD vide)
// ═══════════════════════════════════════════════════════

app.post('/api/auth/bootstrap', (req, res) => {
  const salaries = Array.isArray(req.body) ? req.body : [];
  if (!salaries.length) return res.status(400).json({ error: 'Aucun salarié' });

  // Vérifier si la table salaries est vide
  const count = db.prepare('SELECT COUNT(*) as n FROM salaries').get().n;
  
  // Toujours accepter le bootstrap pour mettre à jour les PINs
  const upsert = db.prepare(`
    INSERT INTO salaries (id, data, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `);
  const syncAll = db.transaction(list => {
    for (const s of list) upsert.run(s.id, JSON.stringify(s));
  });
  syncAll(salaries);

  // Tenter de login avec le premier salarié actif
  const premier = salaries.find(s => s.actif);
  if (premier) {
    const nom = premier.prenom ? premier.prenom + ' ' + premier.nom : premier.nom;
    const token = jwt.sign({ id: premier.id, role: premier.role, nom }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ ok: true, token, role: premier.role, nom });
  }
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES SALARIÉS
// ═══════════════════════════════════════════════════════

// GET /api/salaries — récupérer tous les salariés
app.get('/api/salaries', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM salaries ORDER BY id ASC').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

// PUT /api/salaries — sync complète (tableau de salariés)
app.put('/api/salaries', authMiddleware, (req, res) => {
  const salaries = Array.isArray(req.body) ? req.body : [];
  const upsert = db.prepare(`
    INSERT INTO salaries (id, data, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `);
  const syncAll = db.transaction((list) => {
    for (const s of list) upsert.run(s.id, JSON.stringify(s));
  });
  syncAll(salaries);
  res.json({ ok: true, count: salaries.length });
});

// ═══════════════════════════════════════════════════════
// ROUTES CONNEXIONS (logs)
// ═══════════════════════════════════════════════════════

app.get('/api/connexions', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin uniquement' });
  const { salarie_id, limit } = req.query;
  let query = 'SELECT * FROM connexions';
  const params = [];
  if (salarie_id) { query += ' WHERE salarie_id = ?'; params.push(salarie_id); }
  query += ' ORDER BY id DESC';
  if (limit) { query += ' LIMIT ?'; params.push(parseInt(limit)); }
  const rows = db.prepare(query).all(...params);
  res.json(rows);
});

app.delete('/api/connexions', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin uniquement' });
  db.prepare('DELETE FROM connexions').run();
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES CLIENTS
// ═══════════════════════════════════════════════════════

app.get('/api/clients', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM clients ORDER BY id ASC').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

app.put('/api/clients', authMiddleware, (req, res) => {
  const clients = Array.isArray(req.body) ? req.body : [];
  db.prepare('DELETE FROM clients').run();
  const insert = db.prepare('INSERT INTO clients (id, data) VALUES (?, ?)');
  const insertAll = db.transaction(list => { for (const c of list) insert.run(c.id, JSON.stringify(c)); });
  insertAll(clients);
  res.json({ ok: true, count: clients.length });
});

// ═══════════════════════════════════════════════════════
// ROUTES FOURNISSEURS
// ═══════════════════════════════════════════════════════

app.get('/api/fournisseurs', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM fournisseurs ORDER BY id ASC').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

app.put('/api/fournisseurs', authMiddleware, (req, res) => {
  const fournisseurs = Array.isArray(req.body) ? req.body : [];
  db.prepare('DELETE FROM fournisseurs').run();
  const insert = db.prepare('INSERT INTO fournisseurs (id, data) VALUES (?, ?)');
  const insertAll = db.transaction(list => { for (const f of list) insert.run(f.id, JSON.stringify(f)); });
  insertAll(fournisseurs);
  res.json({ ok: true, count: fournisseurs.length });
});

// ═══════════════════════════════════════════════════════
// ROUTES OF (Ordres de Fabrication)
// ═══════════════════════════════════════════════════════

app.get('/api/of', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT ref, data FROM of_data').all();
  const result = {};
  for (const r of rows) result[r.ref] = JSON.parse(r.data);
  res.json(result);
});

app.put('/api/of/:ref', authMiddleware, (req, res) => {
  const { ref } = req.params;
  db.prepare(`
    INSERT INTO of_data (ref, data, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(ref) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `).run(ref, JSON.stringify(req.body));
  res.json({ ok: true });
});

app.delete('/api/of/:ref', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM of_data WHERE ref = ?').run(req.params.ref);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES DEVIS
// ═══════════════════════════════════════════════════════

app.get('/api/devis', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM devis').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

app.put('/api/devis/:ref', authMiddleware, (req, res) => {
  const { ref } = req.params;
  db.prepare(`
    INSERT INTO devis (ref, data, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(ref) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `).run(ref, JSON.stringify(req.body));
  res.json({ ok: true });
});

app.delete('/api/devis/:ref', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM devis WHERE ref = ?').run(req.params.ref);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES STOCK
// ═══════════════════════════════════════════════════════

app.get('/api/stock', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT data FROM stock ORDER BY id DESC LIMIT 1').get();
  res.json(row ? JSON.parse(row.data) : []);
});

// Sauvegarde du stock complet (tableau)
app.put('/api/stock', authMiddleware, (req, res) => {
  // On écrase avec une nouvelle entrée (snapshot complet)
  db.prepare('DELETE FROM stock').run();
  db.prepare('INSERT INTO stock (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES SAISIES TEMPS
// ═══════════════════════════════════════════════════════

app.get('/api/saisies', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM saisies ORDER BY id ASC').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

app.post('/api/saisies', authMiddleware, (req, res) => {
  db.prepare('INSERT INTO saisies (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES PLANNING
// ═══════════════════════════════════════════════════════

app.get('/api/planning', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT data FROM planning ORDER BY id DESC LIMIT 1').get();
  res.json(row ? JSON.parse(row.data) : []);
});

app.put('/api/planning', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM planning').run();
  db.prepare('INSERT INTO planning (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES CONTRÔLES ÉPAISSEUR
// ═══════════════════════════════════════════════════════

app.get('/api/controles', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM controles ORDER BY id ASC').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

app.post('/api/controles', authMiddleware, (req, res) => {
  db.prepare('INSERT INTO controles (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTES CONSOMMATION POUDRE
// ═══════════════════════════════════════════════════════

app.get('/api/conso-poudre', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data FROM conso_poudre ORDER BY id ASC').all();
  res.json(rows.map(r => JSON.parse(r.data)));
});

app.post('/api/conso-poudre', authMiddleware, (req, res) => {
  db.prepare('INSERT INTO conso_poudre (data) VALUES (?)').run(JSON.stringify(req.body));
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTE BACKUP COMPLET (export JSON)
// ═══════════════════════════════════════════════════════

app.get('/api/backup', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin uniquement' });

  const of_rows = db.prepare('SELECT ref, data FROM of_data').all();
  const of_obj  = {};
  for (const r of of_rows) of_obj[r.ref] = JSON.parse(r.data);

  const backup = {
    exportedAt: new Date().toISOString(),
    OF_DATA:    of_obj,
    DEVIS_DATA: db.prepare('SELECT data FROM devis').all().map(r => JSON.parse(r.data)),
    STOCK_DATA: (() => { const r = db.prepare('SELECT data FROM stock ORDER BY id DESC LIMIT 1').get(); return r ? JSON.parse(r.data) : []; })(),
    SAISIES:    db.prepare('SELECT data FROM saisies').all().map(r => JSON.parse(r.data)),
    PLANNING:   (() => { const r = db.prepare('SELECT data FROM planning ORDER BY id DESC LIMIT 1').get(); return r ? JSON.parse(r.data) : []; })(),
    CONTROLES:  db.prepare('SELECT data FROM controles').all().map(r => JSON.parse(r.data)),
    CONSO:      db.prepare('SELECT data FROM conso_poudre').all().map(r => JSON.parse(r.data)),
  };

  res.setHeader('Content-Disposition', `attachment; filename="thermo-backup-${new Date().toISOString().slice(0,10)}.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.json(backup);
});

// ── Health check ──
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── 404 catch-all ──
app.use((req, res) => res.status(404).json({ error: 'Route inconnue' }));

// ── Démarrage ──
app.listen(PORT, () => {
  console.log(`✅ Thermo API démarrée sur le port ${PORT}`);
  console.log(`📦 Base de données : ${DB_PATH}`);
});
