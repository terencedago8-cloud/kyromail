# KyroMail

**KyroMail** est une messagerie scolaire interne pour collège, développée avec **Python + Flask**, **SQLite**, **HTML**, **CSS** et **JavaScript**.

Interface en français, moderne et responsive (ordinateur, tablette, téléphone), aux couleurs bleu / blanc / gris clair, avec un logo d'enveloppe.

---

## 1. Fonctionnalités

| Domaine | Détails |
| --- | --- |
| Comptes | Créés **uniquement par un administrateur**, mot de passe haché, activation / désactivation, profil et rôle par utilisateur, déconnexion sécurisée (session effacée). |
| Rôles | Administrateur, Direction, Professeur, Surveillant, Élève. |
| Messagerie | Boîte de réception, messages envoyés, rédaction avec liste des destinataires autorisés, objet + contenu, date et expéditeur affichés, indicateur de non lus, page de lecture, recherche, filtres (tous / non lus / lus), notifications de nouveaux messages, gestion des erreurs et des destinataires inexistants. |
| Administration | Création / modification de comptes, changement de rôle, réinitialisation de mots de passe, activation / désactivation, liste et recherche des utilisateurs, statistiques (nombre de comptes et de messages), **matrice des règles d'accès entre rôles**, **journal des actions administratives**. |
| Sécurité | Requêtes SQL paramétrées, protection CSRF sur chaque POST, validation des données, contrôle d'accès par rôle, mots de passe jamais en clair, secret hors du code source, limiteur de tentatives de connexion. |

---

## 2. Architecture du projet

```
KyroMail/
├── app.py               # Application Flask : routes, sécurité, base de données
├── manage.py            # CLI : init-db, create-admin, list-users, reset-password…
├── requirements.txt     # Dépendances Python (Flask, Werkzeug, waitress)
├── render.yaml          # Blueprint Render (déploiement PaaS)
├── railway.json         # Configuration Railway (déploiement PaaS)
├── README.md
├── .gitignore
├── templates/
│   ├── base.html        # Gabarit commun (barre latérale, notifications, pied de page)
│   ├── landing.html     # Page d'accueil publique
│   ├── login.html       # Connexion
│   ├── inbox.html       # Boîte de réception
│   ├── sent.html        # Messages envoyés
│   ├── compose.html     # Rédaction
│   ├── message.html     # Lecture d'un message
│   ├── admin.html       # Panneau administrateur (4 onglets)
│   ├── profile.html     # Profil utilisateur
│   └── error.html       # Pages d'erreur (400, 403, 404, 413, 500)
├── static/
│   ├── style.css        # Design responsive
│   └── app.js           # Menu mobile, flashes, confirmations, notifications
└── instance/            # Créée automatiquement
    ├── kyromail.sqlite3 # Base de données (ignorée par git)
    └── secret_key       # Clé de session (ignorée par git)
```

### Modèle de données (SQLite en local, PostgreSQL en ligne)

* `users` : id, full_name, email (unique), password_hash, role, active, created_at, updated_at, last_login
* `messages` : id, sender_id, recipient_id, subject, body, sent_at, read_at, deleted_by_sender, deleted_by_recipient
* `access_rules` : from_role, to_role, allowed (matrice 5 × 5)
* `admin_log` : id, admin_id, action, detail, created_at

---

## 3. Installation sous Windows (pas à pas)

### Étape 1 — Installer Python

1. Téléchargez Python 3.11 ou supérieur sur <https://www.python.org/downloads/windows/>.
2. Lancez l'installateur et **cochez « Add python.exe to PATH »**.
3. Vérifiez dans l'invite de commandes (`cmd` ou PowerShell) :

```powershell
python --version
pip --version
```

### Étape 2 — Créer le dossier du projet

```powershell
cd $env:USERPROFILE\Documents
mkdir KyroMail
cd KyroMail
```

*(Copiez-y les fichiers du projet : `app.py`, `manage.py`, `templates/`, `static/`, etc.)*

### Étape 3 — Créer l'environnement virtuel

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Si PowerShell bloque l'exécution de scripts :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

En invite de commandes classique (`cmd.exe`) :

```bat
python -m venv .venv
.venv\Scripts\activate.bat
```

### Étape 4 — Installer les dépendances

```powershell
pip install -r requirements.txt
```

### Étape 5 — Initialiser la base de données

```powershell
python manage.py init-db
```

La base est créée dans `instance\kyromail.sqlite3`, avec la matrice des règles d'accès par défaut.

### Étape 6 — Créer le premier administrateur (de manière sécurisée)

```powershell
python manage.py create-admin
```

Le programme demande le **nom complet**, l'**adresse mail** et le **mot de passe** (saisie masquée, confirmation demandée). Le mot de passe est haché avant enregistrement : il n'est jamais stocké en clair.

Variantes :

```powershell
python manage.py create-admin --name "Marie Dupont" --email marie.dupont@kyromail.local
python manage.py create-admin --name "Admin" --email admin@kyromail.local --password "MotDePasse123"
```

> Ne passez pas le mot de passe en ligne de commande sur un poste partagé : la saisie masquée est préférable.

### Étape 7 — Démarrer le serveur

```powershell
python app.py
```

Le serveur démarre sur <http://127.0.0.1:5000>.

Variables utiles :

| Variable | Rôle | Défaut |
| --- | --- | --- |
| `KYROMAIL_SECRET_KEY` | Clé secrète de session (sinon fichier `instance/secret_key`) | générée automatiquement |
| `KYROMAIL_DATABASE` | Chemin de la base SQLite | `instance/kyromail.sqlite3` |
| `KYROMAIL_DOMAIN` | Domaine **interne** des adresses | `kyromail.local` |
| `KYROMAIL_HTTPS` | `1` = cookie de session sécurisé (derrière HTTPS) | `0` |
| `KYROMAIL_DEBUG` | `1` = mode debug Flask (jamais en production) | `0` |
| `KYROMAIL_HOST` / `KYROMAIL_PORT` | Adresse et port d'écoute | `127.0.0.1` / `5000` |

### Étape 8 — Ouvrir le site

Ouvrez <http://127.0.0.1:5000> dans le navigateur, puis connectez-vous avec le compte administrateur créé à l'étape 6.

---

## 4. Commandes d'administration (CLI)

```powershell
python manage.py init-db                     # (ré)initialise la base
python manage.py init-db --force             # supprime et recrée la base
python manage.py list-users                  # liste des comptes
python manage.py create-admin                # crée un administrateur
python manage.py reset-password --email a@b  # réinitialise un mot de passe
python manage.py set-role --email a@b --role eleve
python manage.py toggle-user --email a@b     # active / désactive un compte
```

Rôles acceptés : `admin`, `direction`, `professeur`, `surveillant`, `eleve`.

---

## 5. Premiers pas dans l'interface

1. Connectez-vous en administrateur.
2. Allez dans **Administration → Utilisateurs** : créez la direction, des professeurs, des surveillants et des élèves.
3. **Administration → Règles d'accès** : ajustez qui peut écrire à qui (par défaut, toutes les combinations sont autorisées).
4. **Administration → Journal** : suivi des créations, modifications, réinitialisations et changements de règles.
5. Utilisez **Rédiger** pour envoyer un message : la liste des destinataires ne propose que les comptes autorisés et actifs.

---

## 6. Adresses internes et branchement d'un domaine réel

### Adresses de démonstration

Par défaut, les comptes reçoivent des adresses du type `marie.dupont@kyromail.local`.
Ces adresses sont **internes à l'application** : elles ne sont **pas** de véritables adresses e-mail Internet, elles ne peuvent ni recevoir ni envoyer de courrier externe. Elles servent uniquement d'identifiant de connexion et d'affichage dans la messagerie.

### Architecture prévue pour un domaine réel

Le code est volontairement découplé :

1. **Domaine** : définissez `KYROMAIL_DOMAIN=moncollege.fr` pour que les adresses générées utilisent votre domaine réel.
2. **Sortie (envoi vers l'extérieur)** : ajoutez un module d'envoi SMTP/API qui, à l'insertion d'un message dans `messages`, transfère une copie au destinataire externe (ex. `smtplib` vers un relais authentifié, ou une API type Postfix / Mailjet / SendGrid / Gmail SMTP).
3. **Entrée (réception)** : prévoir un point d'entrée (route `/inbound` ou script cron) qui récupère le courrier MX de `moncollege.fr`, l'authentifie, crée ou met à jour le compte utilisateur puis insère le message en base avec les mêmes colonnes.
4. **DNS** : enregistrements `MX`, `SPF`, `DKIM`, `DMARC` à configurer chez votre hébergeur.
5. **Alternative simple** : ne garder KyroMail qu'en messagerie **interne** (usage collège uniquement) et utiliser un service existant pour l'externe.

Aucune clé SMTP ni aucun secret n'est présent dans le code : tout passe par des variables d'environnement.

---

## 7. Mise en production dans un collège (checklist)

- [ ] **HTTPS obligatoire** : placez l'application derrière un serveur inverse (Caddy, Nginx, IIS) avec un certificat TLS ; définissez `KYROMAIL_HTTPS=1` pour n'envoyer les cookies de session qu'en HTTPS.
- [ ] **Sessions sécurisées** : cookies `HttpOnly`, `SameSite=Lax`, régénération à la connexion, expiration après 8 heures d'inactivité (`PERMANENT_SESSION_LIFETIME`), déconnexion automatique sur poste partagé.
- [ ] **Serveur WSGI de production** : `waitress-serve --host=127.0.0.1 --port=5000 app:app` (ou gunicorn/uWSGI sous Linux) — jamais le serveur de développement Flask en production.
- [ ] **Sauvegardes** : copie quotidienne de `instance/kyromail.sqlite3` (exemple PowerShell en tâche planifiée) + test régulier de restauration ; conserver les sauvegardes chiffrées.
- [ ] **Politique de conservation** : durée de conservation des messages et des journaux définie par l'établissement, purge automatisée (script SQL planifié) et information des utilisateurs.
- [ ] **Mineurs / confidentialité** : vérifier les obligations légales avant mise en production (RGPD, information des responsables légaux, finalité, minimisation des données, durée de conservation, registre des traitements, droits d'accès et de suppression).
- [ ] **Comptes** : suppression ou désactivation systématique des comptes en fin d'année scolaire, politique de mots de passe, limitation des tentatives de connexion en environnement partagé (reverse proxy ou bibliothèque de rate limiting).
- [ ] **Journalisation** : archivage du `admin_log`, surveillance des actions sensibles.
- [ ] **Dépendances** : mise à jour régulière de Flask/Werkzeug (`pip install -r requirements.txt --upgrade`).

---

## 8. Développement

```powershell
.\.venv\Scripts\Activate.ps1
$env:KYROMAIL_DEBUG = "1"
python app.py
```

Le mode debug n'est à activer **que** sur un poste de développement local.

Tests manuels rapides :

* connexion avec un mauvais mot de passe (message d'erreur + limiteur après 5 essais) ;
* envoi vers un compte désactivé ou inexistant (messages d'erreur explicites) ;
* POST sans jeton CSRF (erreur 400) ;
* accès à `/admin` avec un rôle non administrateur (erreur 403) ;
* création d'un compte sans adresse mail (génération automatique `@kyromail.local`).

---

## 9. Mise en ligne : https://mail.kyromail.fr

Le projet est préparé pour un PaaS (**Render** ou **Railway**) : au premier
démarrage, `bootstrap()` dans `app.py` crée la base (si absente) et, uniquement
si les variables `KYROMAIL_ADMIN_*` sont présentes **et** que la base est vide,
crée le premier administrateur. Aucune commande manuelle n'est nécessaire sur
le serveur.

### 9.1 Envoyer le projet sur GitHub

```powershell
cd $env:USERPROFILE\Documents\KyroMail
git init
git add .
git commit -m "KyroMail - messagerie scolaire"
git branch -M main
git remote add origin https://github.com/VOTRE-COMPTE/kyromail.git
git push -u origin main
```

> `.gitignore` exclut déjà `instance/*` (base de données et clé secrète) :
> aucun secret n'est poussé sur Git.

### 9.2 Déploiement 100 % gratuit : Render (site) + Supabase (base PostgreSQL)

Le plan gratuit de Render ne fournit **pas** de disque persistant : la base
PostgreSQL est donc hébergée chez un fournisseur gratuit (**Supabase**, 500 Mo
inclus — **Neon** fonctionne aussi). L'application accepte les deux bases :
SQLite en local, PostgreSQL dès que `KYROMAIL_DATABASE_URL` est défini.

1. **Base PostgreSQL** : <https://supabase.com> → *Continue with GitHub* →
   créez une organisation (plan **Free**) puis un projet (**Région** : Americas,
   désactivez l'« Enable Data API »). Dans **Project Settings → Database →
   Connection string → URI**, copiez la chaîne de **connexion directe** (port
   `5432`, hébergeant `db.xxxxx.supabase.co`).
2. Sur <https://render.com> → **New → Blueprint** → sélectionnez le dépôt
   GitHub (Render lit `render.yaml` automatiquement ; le blueprint est déjà sur
   le **plan gratuit**).
3. Dans les variables d'environnement proposées, renseignez :
   * `KYROMAIL_DATABASE_URL` = la chaîne copiée à l'étape 1 (port `5432`)
   * `KYROMAIL_ADMIN_EMAIL` = ex. `admin@kyromail.fr`
   * `KYROMAIL_ADMIN_PASSWORD` = mot de passe fort (8 caractères min., lettre +
     chiffre)
   * `KYROMAIL_ADMIN_NAME` = ex. `Administrateur KyroMail`
   (`KYROMAIL_SECRET_KEY` est généré par Render ; `KYROMAIL_HTTPS=1` est déjà
   défini dans le blueprint.)
4. Laissez Render construire et démarrer (`waitress-serve --host=0.0.0.0
   --port=$PORT app:app`). Ouvrez l'URL provisoire
   `https://kyromail-xxxx.onrender.com` : le site doit répondre. Au premier
   démarrage, `bootstrap()` crée la table et le premier administrateur.
5. Connectez-vous avec l'administrateur créé, créez les autres comptes, puis
   **supprimez `KYROMAIL_ADMIN_EMAIL` et `KYROMAIL_ADMIN_PASSWORD`** des
   variables d'environnement (et redéployez) : ces secrets ne doivent plus
   traîner.

> Le site gratuit de Render **s'endormit après 15 minutes** d'inactivité : le
> premier appel suivant met 20 à 60 s à répondre (réveil automatique), puis
> tout est normal.

### 9.3 Ajouter le domaine mail.kyromail.fr

1. Sur Render : **Settings → Custom Domains → Add Custom Domain** → saisissez
   `mail.kyromail.fr`. Render affiche une cible du type
   `kyromail-xxxx-yyyy.onrender.com`.
2. Chez votre registrar (là où `kyromail.fr` est géré) → DNS du domaine
   `kyromail.fr` → ajoutez l'enregistrement :

   | Type  | Nom  | Valeur                          | TTL  |
   | ----- | ---- | ------------------------------- | ---- |
   | CNAME | mail | `kyromail-xxxx-yyyy.onrender.com` | 300 |

3. Attendez la propagation (quelques minutes à 2 h), puis ouvrez
   **https://mail.kyromail.fr** : le certificat HTTPS est émis automatiquement
   (Let's Encrypt) par Render.

### 9.4 Variante Railway (payante, avec disque)

1. <https://railway.app> → **New Project → Deploy from GitHub repo**.
2. **Volumes → Add Volume** : mount path `/data` (nécessite un plan payant).
3. Variables d'environnement :
   `KYROMAIL_DATABASE=/data/kyromail.sqlite3`, `KYROMAIL_HTTPS=1`,
   `KYROMAIL_SECRET_KEY` (généré), `KYROMAIL_ADMIN_*` (premier démarrage).
   *Alternative* : définissez `KYROMAIL_DATABASE_URL` (PostgreSQL managé) et
   laissez SQLite de côté, comme sur Render gratuit.
4. Le `startCommand` de `railway.json` est utilisé automatiquement.
5. **Settings → Networking → Custom Domain** → `mail.kyromail.fr`, puis
   créez le CNAME correspondant chez votre registrar.

### 9.5 À savoir pour un usage réel

* **Sous-domaine** : `mail.kyromail.fr` est utilisé pour le site (webmail).
  Si un jour vous connectez un vrai service de courrier, réservez un autre
  hôte pour les MX (ex. `mx.kyromail.fr`) afin de ne pas confliter.
* **Adresses de compte** : par défaut elles restent sur le domaine interne de
  démonstration. Décommentez `KYROMAIL_DOMAIN=kyromail.fr` dans `render.yaml`
  **uniquement** une fois un service SMTP réel branché : l'interface indique
  alors clairement que ces adresses ne sont pas encore délivrées sur Internet.
* **Sécurité** : HTTPS forcé (`KYROMAIL_HTTPS=1` → cookie de session
  `Secure`), `SECRET_KEY` en variable d'environnement (jamais dans le dépôt),
  sessions expirant après 8 h, mots de passe hachés.
* **Sauvegardes** :
  * *PostgreSQL (Supabase / Neon)* : les sauvegardes automatiques sont incluses
    dans le plan gratuit ; pour une exportation manuelle :
    `pg_dump "$KYROMAIL_DATABASE_URL" --no-owner > sauvegarde.sql`.
  * *SQLite (local / Railway avec disque)* : copie régulière du fichier
    `sqlite3 instance/kyromail.sqlite3 ".backup sauvegarde.sqlite3"`.
  Testez régulièrement une restauration.
* **Confidentialité / mineurs** : avant ouverture aux élèves, validez la
  finalité, la durée de conservation, l'information des responsables légaux et
  l'inscription au registre des traitements (voir § 7).
* **Coûts** : configuration retenue ici = **0 €/mois** (Render gratuit +
  Supabase gratuit, 500 Mo de base). Un palier payant reste possible plus tard :
  Render Starter ≈ 7 $/mois + disque (SQLite persistante), Railway Hobby ≈
  5 $/mois. Un domaine `.fr` coûte ≈ 10 €/an.

---

## 10. Licence / usage

Projet destiné à un usage éducatif et interne au collège. Adaptez les règles d'accès, la politique de conservation et les mesures de conformité à votre établissement avant tout usage réel.
