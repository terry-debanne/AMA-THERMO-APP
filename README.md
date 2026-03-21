# Thermo Backend — Guide de déploiement Railway

## Contenu du projet

```
thermo-backend/
├── server.js        ← API principale (Express + SQLite)
├── package.json
├── railway.json     ← Config Railway
├── .gitignore
└── public/
    └── index.html   ← ⚠️ Copier ici votre thermo-app.html renommé
```

---

## Étape 1 — Préparer le dossier

1. Créer un dossier `public/` dans ce répertoire
2. Copier votre `thermo-app_9_.html` dedans et le renommer en `index.html`

---

## Étape 2 — Créer un compte GitHub

Aller sur https://github.com et créer un compte gratuit.

Puis créer un nouveau dépôt (repository) public ou privé nommé `thermo-backend`.

---

## Étape 3 — Pousser le code sur GitHub

Ouvrir un terminal dans le dossier `thermo-backend/` et exécuter :

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/VOTRE_USERNAME/thermo-backend.git
git push -u origin main
```

---

## Étape 4 — Déployer sur Railway

1. Aller sur https://railway.app
2. Cliquer **"Start a New Project"**
3. Choisir **"Deploy from GitHub repo"**
4. Sélectionner votre dépôt `thermo-backend`
5. Railway détecte automatiquement Node.js et lance le déploiement

### Ajouter un volume persistant (IMPORTANT — pour ne pas perdre la BDD)

Dans Railway, aller dans votre service → **"Add Volume"** :
- Mount path : `/data`
- Cela garantit que la base SQLite survit aux redémarrages

### Ajouter les variables d'environnement

Dans Railway → Settings → Variables :
```
JWT_SECRET=une_chaine_aleatoire_longue_et_secrete_ici
DATA_DIR=/data
```

---

## Étape 5 — Récupérer votre URL Railway

Dans Railway → Settings → Networking → **"Generate Domain"**

Vous obtenez une URL du type : `https://thermo-backend-production.up.railway.app`

Tester que l'API fonctionne : `https://votre-url.railway.app/api/health`

---

## Étape 6 — Connecter votre domaine personnalisé

### Acheter un domaine (OVH recommandé)
- Aller sur https://www.ovhcloud.com/fr/domains/
- Chercher votre domaine (ex: `ardeche-thermolaquage.fr`)
- Commander (~7€/an pour un .fr)

### Pointer le domaine vers Railway
Dans Railway → Settings → Networking → **"Custom Domain"** :
- Entrer votre domaine : `ardeche-thermolaquage.fr`
- Railway vous donne un enregistrement CNAME à ajouter

Dans OVH → Zone DNS de votre domaine :
- Ajouter un enregistrement **CNAME** :
  - Sous-domaine : `@` ou `www`
  - Cible : l'adresse fournie par Railway
- Attendre 15–30 min (propagation DNS)

---

## Étape 7 — Tester

Ouvrir `https://votre-domaine.fr` → vous devriez voir l'app Thermo.

Se connecter avec les PINs par défaut :
- Admin : `1234`
- Resp. Production : `2580`
- Opérateur : `1111`

⚠️ **Changer les PINs après la première connexion !**

---

## PINs par défaut à changer

| Rôle | PIN par défaut |
|------|---------------|
| Admin | 1234 |
| Resp. Production | 2580 |
| Opérateur | 1111 |

---

## Backup des données

Accéder à `https://votre-domaine.fr/api/backup` (connecté en admin) pour télécharger un export JSON complet de toutes les données.
