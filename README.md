# hMailServer Event Handlers (JScript)

*[English](#english) | [Français](#français)*

A set of hMailServer event handlers written in JScript. It filters inbound
connections and auto-bans abusive hosts (geographic filtering, AbuseIPDB
reputation, failed-login, recipient-harvesting and connection-flood protection),
cleans up a few outbound headers, and writes a single, column-aligned log file
per day.

---

## English

### Features

* Country blocking on every port (SMTP, IMAP, POP).
* Geographic restriction on non-SMTP ports: mailbox access (IMAP/POP) is allowed
  only from a configurable list of countries.
* AbuseIPDB reputation check on the submission ports (587/465).
* Auto-ban of unauthenticated / failed logins.
* Recipient-probe (directory harvesting) protection: bans an IP after a number
  of unknown recipients within a sliding window. Uses a small counter file, no
  database. An unauthenticated sender that claims one of your own domains is
  banned at the first unknown recipient.
* Connection-flood auto-ban: bans an IP that opens too many connections within a
  sliding window. Catches brute-force bursts that never complete a login (for
  example repeated pre-STARTTLS AUTH attempts answered with `504`), which do not
  trigger the failed-login handler. Uses a small counter file, no database.
* Outbound `Received` header anonymisation (removes the client IP).
* Fills a missing `Message-Id` and reformats `X-Spam-Report` so it is readable.
* Optional SMTP rejection of messages whose spam score is above a threshold. It
  reads the score your anti-spam layer already added (for example SpamAssassin's
  `X-Spam-Score`, or the `score=` field of `X-Spam-Status`).
* The admin password and the AbuseIPDB key live in a separate secrets file, not
  in the script.
* Daily log with fixed-width, aligned columns, UTF-8 without BOM. One line per
  event.

Each filtering feature can be enabled or disabled, and set to **ban** (a temporary
IP range in hMailServer, so a banned host is dropped before it reaches the script
again) or **reject** (refuse only the current session with a professional SMTP
message, without a persistent ban).

### Requirements

* hMailServer with scripting set to **JScript**. Tested with the official
  **5.7.1** release, build 3116: https://github.com/hmailserver/hmailserver/releases
* **Disconnect.exe** to drop the current session of a banned host. Copy RvdH's
  `Disconnect.exe` to the hMailServer `Events` folder: https://d-fault.nl/files/
* For the country lookup and AbuseIPDB checks, two COM components must be
  registered on the server:
  * `DNSLibrary.DNSResolver` (country lookup)
  * `AbuseIPDBComponent.AbuseIPDBRestClient` (AbuseIPDB)

  These are part of RvdH's community tools (see the d-fault.nl link above). If
  a component is not present, the matching check is skipped, the connection is
  allowed, and the error is written to the log. The rest keeps working.
* An AbuseIPDB API key, if you use the AbuseIPDB check.

Country lookup uses the public reverse-DNS service
`country.junkemailfilter.com`.

### Installation

1. In hMailServer Administrator, go to **Settings → Advanced → Scripts**, set the
   language to **JScript** and enable scripting.
2. Copy `EventHandlers.js` into the `Events` folder (default
   `C:\Program Files\hMailServer\Events`). The file must keep that exact name.
3. Copy `Disconnect.exe` into the same `Events` folder.
4. Create `EventHandlers.secrets.ini` (see below).
5. Open `EventHandlers.js` and edit the settings at the top of the file (see
   below).
6. Back in the Administrator, click **Save**, then **Reload script**.

### EventHandlers.secrets.ini

The admin password and the AbuseIPDB API key are not stored in the script. The
script reads them from a plain-text file whose path is set in `SECRETS_FILE`.
Create it next to `EventHandlers.js` with these two lines and put in your own
values:

```ini
ADMIN_PASSWORD = YOUR_ADMIN_PASSWORD
ABUSEIPDB_KEY = YOUR_ABUSEIPDB_API_KEY
```

* One `KEY = value` per line. Spaces around `=` and at the end of the value are
  ignored. Don't put quotes around the value: they would be kept as part of it.
* Key names are case-sensitive. Lines that don't start with a key, such as `;`
  or `#` comments, are ignored.
* The file is read once, the first time a secret is needed. Click **Reload
  script** after you change it.
* If the file can't be read, or a key is missing, the script writes the error to
  the log and goes on: without `ADMIN_PASSWORD` no ban is created, without
  `ABUSEIPDB_KEY` the AbuseIPDB check is skipped and the connection is allowed.
* Limit access to this file to the account that runs hMailServer and to
  administrators, and keep it out of any backup or repository you share. The
  `.gitignore` of this repository already excludes it.

### Configuration

All settings sit at the top of the file:

* `ADMIN`: admin user name used to create the bans. Its password goes in the
  secrets file.
* `LOGDIR`, `LOGPREFIX`, `DISCONNECT_EXE`, `SECRETS_FILE`: log folder, log file
  prefix, path to `Disconnect.exe` and path to `EventHandlers.secrets.ini`.
* `LOCAL_DOMAINS`: the domains hosted on this server, lowercase and
  pipe-delimited, such as `"|example.com|example.org|"`. Used to spot a sender
  that fakes one of them.
* One object per filtering feature (`GEOBLOCK`, `GEORESTRICT`, `ABUSEIPDB`,
  `UNKNOWNUSER`, `RCPTPROBE`, `CONNFLOOD`, `SPAMREJECT`), each with:
  * `enabled`: turn the feature on or off.
  * `action`: `"ban"` (temporary IP-range ban + disconnect) or `"reject"` (refuse
    only the current session with a professional SMTP message, no ban).
  * `ban`: `{ qty, unit }` duration (unit `d`/`h`/`n`/`s`), used in `"ban"` mode;
    `qty` `0` disconnects without banning.
  * `msg`: the SMTP message returned in `"reject"` mode.
  * plus feature-specific fields: `ABUSEIPDB` has `maxConfidence`, `maxAgeDays`;
    `RCPTPROBE` has `threshold`, `windowMin` and `spoofLocal` (ban at the first
    unknown recipient when the sender claims a domain from `LOCAL_DOMAINS`);
    `CONNFLOOD` has `threshold`, `windowMin`; `SPAMREJECT` has `score`, `header`.
    `SPAMREJECT` is on by default with a score of 20: turn it off if no
    anti-spam layer adds a score header.
* `RECEIVEDANON_ENABLED`, `MESSAGEID_ENABLED`, `SPAMREPORT_ENABLED`: on/off flags
  for the header-transform features.
* `BLOCKED_COUNTRIES`, `ALLOWED_GEO`, `SMTP_PORTS`, `SUBMISSION_PORTS`:
  pipe-delimited lists such as `"|cn|cz|ru|"`.
* `BAN_PRIORITY`, `LOG_SOURCES`, local network exemption (`LOCAL_IP_PREFIX`,
  `LOCALHOST_IP`, `LOCALHOST_IP6`), and the sliding-window counter files:
  recipient-probe (`RCPT_DATA_FILE`, `RCPT_LOCK_FILE`) and connection-flood
  (`CONN_DATA_FILE`, `CONN_LOCK_FILE`), plus `BAN_LOCK_FILE`, `LOCK_TRIES`,
  `LOCK_WAIT_MS` (pause between two lock attempts), `LOCK_STALE_SEC`.
* `RANGE_NAME_MAX` (100) and `LOG_DETAIL_MAX` (300): longest IP-range name and
  longest free-text detail in a log line. Longer text is cut.

> **Connection-flood tuning.** `CONNFLOOD.threshold` connections within
> `CONNFLOOD.windowMin` minutes trigger a ban (defaults: 5 in 1 minute, banned for
> 7 days). The LAN
> and localhost are exempt. Lower the threshold to be more aggressive; raise it if
> a legitimate high-volume relay gets banned. This check runs on every connection,
> so it adds one small file access (under a lock) per connect.

### Order of checks on connect

1. Local network and localhost are skipped.
2. Connection flood: an IP over the connection threshold is banned.
3. Blocked country: rejected on any port.
4. Non-SMTP port from a country outside the allowed list: rejected.
5. Submission port with an IP listed on AbuseIPDB: rejected.

### Logging

The log is written to `LOGDIR\<prefix>_YYYYMMDD.log`, one file per day, in fixed
columns:

```
2026-07-04 00:39:59  AutoBan     111.18.196.17    cn   +7d    Bad Country 143
2026-07-04 05:28:56  AutoBan     85.121.183.244   ro   +1d    Unknown USER 587
2026-07-04 17:39:24  AutoBan     20.12.240.184    us   +1d    AbuseIPDB 587
2026-07-09 11:47:15  AutoBan     193.138.195.94   zz   +1d    Conn flood 587
```

Columns: date and time, source, IP, country, ban duration, detail. Fields are
separated by two or more spaces, so a log line can be split on `/ {2,}/`. The
`source` column is one of `AutoBan`, `Disconnect`, `Reject`, `Spam`, `AbuseIPDB`,
`GeoLookup`, `Debug`, `System`.

### Notes

* Geographic restriction on non-SMTP ports can also lock out a legitimate user
  who reads mail over IMAP/POP from abroad. Keep the ban short, set
  `GEORESTRICT.ban.qty` to `0` to only disconnect, or `GEORESTRICT.action` to
  `"reject"` to avoid a persistent ban.
* Connection-flood protection counts *every* connection, so a legitimate relay
  that opens many short-lived connections could be banned. Raise
  `CONNFLOOD.threshold` or widen `CONNFLOOD.windowMin` if that happens; set
  `CONNFLOOD.enabled` to `false` to turn it off.
* Bans are stored as IP ranges and are removed automatically when they expire.
  Long ban durations on high-volume sources will accumulate more ranges.
* Two simultaneous connections from the same host can both try to create the same
  ban; the duplicate is handled safely and logged once at `Debug` level, not as an
  error.
* Spam-score rejection is on by default and needs an anti-spam layer that adds
  a score header before the message is accepted (SpamAssassin does this).
  Without that header the check never triggers. If you
  also use hMailServer's built-in spam delete threshold, keep only one of the
  two: the built-in threshold deletes silently, while the script returns a 550
  to the sender.
* The script is written for the classic JScript engine used by hMailServer.
  `oMessage.HeaderValue("X") = value` is the correct way to set a header there
  and matches hMailServer's own tests; it is not standard browser JavaScript.

### License

MIT. See `LICENSE`.

---

## Français

Ensemble de gestionnaires d'évènements hMailServer écrits en JScript. Il filtre
les connexions entrantes et bannit automatiquement les hôtes abusifs (filtrage
géographique, réputation AbuseIPDB, protection contre les échecs
d'authentification, la collecte d'adresses et les floods de connexions), nettoie
quelques en-têtes sortants et écrit un seul fichier de log par jour, en colonnes
alignées.

### Fonctionnalités

* Blocage par pays sur tous les ports (SMTP, IMAP, POP).
* Restriction géographique sur les ports non-SMTP : l'accès aux boîtes
  (IMAP/POP) n'est autorisé que depuis une liste de pays configurable.
* Contrôle de réputation AbuseIPDB sur les ports de soumission (587/465).
* Bannissement automatique des connexions non authentifiées.
* Protection contre les sondes de destinataires (collecte d'adresses) : bannit
  une IP après un certain nombre de destinataires inconnus dans une fenêtre
  glissante. Utilise un petit fichier compteur, sans base de données. Un
  expéditeur non authentifié qui se réclame d'un de vos propres domaines est
  banni dès le premier destinataire inconnu.
* Bannissement automatique des floods de connexions : bannit une IP qui ouvre
  trop de connexions dans une fenêtre glissante. Attrape les rafales de force
  brute qui n'aboutissent jamais à une authentification (par exemple les
  tentatives AUTH répétées avant STARTTLS, auxquelles le serveur répond `504`),
  lesquelles ne déclenchent pas le gestionnaire d'échec d'authentification.
  Utilise un petit fichier compteur, sans base de données.
* Anonymisation de l'en-tête `Received` sortant (retire l'IP du client).
* Complète un `Message-Id` manquant et remet en forme `X-Spam-Report` pour le
  rendre lisible.
* Rejet SMTP optionnel des messages dont le score de spam dépasse un seuil. Il
  lit le score déjà ajouté par votre couche anti-spam (par exemple le
  `X-Spam-Score` de SpamAssassin, ou le champ `score=` de `X-Spam-Status`).
* Le mot de passe d'administration et la clé AbuseIPDB sont rangés dans un
  fichier de secrets à part, pas dans le script.
* Log quotidien en colonnes de largeur fixe, UTF-8 sans BOM. Une ligne par
  évènement.

Vous pouvez activer ou désactiver chaque fonction de filtrage, et la régler sur **ban**
(plage d'IP temporaire dans hMailServer : l'hôte banni est coupé avant même
d'atteindre le script à sa tentative suivante) ou **reject** (refus de la seule
session courante avec un message SMTP professionnel, sans ban persistant).

### Prérequis

* hMailServer avec le langage de script réglé sur **JScript**. Testé avec la
  version officielle **5.7.1**, build 3116 :
  https://github.com/hmailserver/hmailserver/releases
* **Disconnect.exe** pour couper la session en cours d'un hôte banni. Copiez le
  `Disconnect.exe` de RvdH dans le dossier `Events` de hMailServer :
  https://d-fault.nl/files/
* Pour la résolution de pays et le contrôle AbuseIPDB, il faut enregistrer deux
  composants COM sur le serveur :
  * `DNSLibrary.DNSResolver` (résolution de pays)
  * `AbuseIPDBComponent.AbuseIPDBRestClient` (AbuseIPDB)

  Ils font partie des outils communautaires de RvdH (voir le lien d-fault.nl
  ci-dessus). Si un composant est absent, le contrôle correspondant est ignoré,
  la connexion est acceptée et l'erreur est écrite dans le log. Le reste
  continue de fonctionner.
* Une clé d'API AbuseIPDB, si vous utilisez le contrôle AbuseIPDB.

La résolution de pays utilise le service DNS inversé public
`country.junkemailfilter.com`.

### Installation

1. Dans hMailServer Administrator, allez dans **Settings → Advanced → Scripts**,
   réglez le langage sur **JScript** et activez les scripts.
2. Copiez `EventHandlers.js` dans le dossier `Events` (par défaut
   `C:\Program Files\hMailServer\Events`). Le fichier doit garder ce nom exact.
3. Copiez `Disconnect.exe` dans ce même dossier `Events`.
4. Créez `EventHandlers.secrets.ini` (voir ci-dessous).
5. Ouvrez `EventHandlers.js` et modifiez les paramètres en tête de fichier (voir
   ci-dessous).
6. De retour dans l'Administrator, cliquez sur **Save**, puis sur
   **Reload script**.

### EventHandlers.secrets.ini

Le mot de passe d'administration et la clé d'API AbuseIPDB ne sont pas écrits
dans le script. Il les lit dans un fichier texte dont `SECRETS_FILE` donne le
chemin. Créez-le à côté de `EventHandlers.js` avec ces deux lignes, en
mettant vos propres valeurs :

```ini
ADMIN_PASSWORD = YOUR_ADMIN_PASSWORD
ABUSEIPDB_KEY = YOUR_ABUSEIPDB_API_KEY
```

* Une ligne `CLE = valeur` par réglage. Les espaces autour du `=` et en fin de
  valeur sont ignorés. Pas de guillemets autour de la valeur : ils en feraient
  partie.
* Les noms de clés respectent la casse. Les lignes qui ne commencent pas par une
  clé, comme les commentaires `;` ou `#`, sont ignorées.
* Le fichier est lu une fois, au premier besoin d'un secret. Cliquez sur
  **Reload script** après l'avoir modifié.
* Si le fichier est illisible ou qu'une clé manque, le script écrit l'erreur dans
  le log et continue : sans `ADMIN_PASSWORD`, aucun ban n'est créé ; sans
  `ABUSEIPDB_KEY`, le contrôle AbuseIPDB est sauté et la connexion acceptée.
* Réservez l'accès à ce fichier au compte qui fait tourner hMailServer et aux
  administrateurs, et gardez-le hors de toute sauvegarde ou de tout dépôt
  partagé. Le `.gitignore` de ce dépôt l'exclut déjà.

### Configuration

Tous les paramètres se trouvent en tête de fichier :

* `ADMIN` : nom de l'administrateur servant à créer les bans. Son mot de passe
  va dans le fichier de secrets.
* `LOGDIR`, `LOGPREFIX`, `DISCONNECT_EXE`, `SECRETS_FILE` : dossier des logs,
  préfixe du fichier, chemin vers `Disconnect.exe` et chemin vers
  `EventHandlers.secrets.ini`.
* `LOCAL_DOMAINS` : les domaines hébergés par ce serveur, en minuscules et
  délimités par des barres, par exemple `"|example.com|example.org|"`. Sert à
  repérer un expéditeur qui en usurpe un.
* Un objet par fonction de filtrage (`GEOBLOCK`, `GEORESTRICT`, `ABUSEIPDB`,
  `UNKNOWNUSER`, `RCPTPROBE`, `CONNFLOOD`, `SPAMREJECT`), chacun avec :
  * `enabled` : active ou désactive la fonction.
  * `action` : `"ban"` (ban temporaire par plage d'IP + déconnexion) ou `"reject"`
    (refus de la seule session courante avec un message SMTP professionnel, sans ban).
  * `ban` : durée `{ qty, unit }` (unité `d`/`h`/`n`/`s`), utilisée en mode `"ban"` ;
    `qty` à `0` déconnecte sans bannir.
  * `msg` : le message SMTP renvoyé en mode `"reject"`.
  * plus des champs propres à la fonction : `ABUSEIPDB` a `maxConfidence`,
    `maxAgeDays` ; `RCPTPROBE` a `threshold`, `windowMin` et `spoofLocal` (ban
    dès le premier destinataire inconnu si l'expéditeur annonce un domaine de
    `LOCAL_DOMAINS`) ; `CONNFLOOD` a `threshold`, `windowMin` ; `SPAMREJECT` a
    `score`, `header`. `SPAMREJECT` fonctionne par défaut, avec un score de 20 :
    désactivez-le si aucune couche anti-spam n'ajoute d'en-tête de score.
* `RECEIVEDANON_ENABLED`, `MESSAGEID_ENABLED`, `SPAMREPORT_ENABLED` : drapeaux
  d'activation des fonctions de transformation d'en-têtes.
* `BLOCKED_COUNTRIES`, `ALLOWED_GEO`, `SMTP_PORTS`, `SUBMISSION_PORTS` : listes
  délimitées par des barres, par exemple `"|cn|cz|ru|"`.
* `BAN_PRIORITY`, `LOG_SOURCES`, exemption du réseau local (`LOCAL_IP_PREFIX`,
  `LOCALHOST_IP`, `LOCALHOST_IP6`) et les fichiers des compteurs à fenêtre
  glissante : sondes de destinataires (`RCPT_DATA_FILE`, `RCPT_LOCK_FILE`) et
  flood de connexions (`CONN_DATA_FILE`, `CONN_LOCK_FILE`), plus
  `BAN_LOCK_FILE`, `LOCK_TRIES`, `LOCK_WAIT_MS` (pause entre deux essais de
  verrou), `LOCK_STALE_SEC`.
* `RANGE_NAME_MAX` (100) et `LOG_DETAIL_MAX` (300) : longueur maximale d'un nom
  de plage d'IP et du détail libre d'une ligne de log. Le texte plus long est
  coupé.

> **Réglage du flood de connexions.** `CONNFLOOD.threshold` connexions dans une
> fenêtre de `CONNFLOOD.windowMin` minutes déclenchent un ban (par défaut : 5 en
> 1 minute, ban de 7 jours). Le LAN et localhost sont exemptés. Baissez le seuil pour être plus
> agressif ; augmentez-le si un relais légitime à fort volume est banni. Ce
> contrôle s'exécute à chaque connexion : il ajoute un petit accès fichier (sous
> verrou) par connexion.

### Ordre des contrôles à la connexion

1. Réseau local et localhost sont ignorés.
2. Flood de connexions : une IP dépassant le seuil de connexions est bannie.
3. Pays bloqué : rejet sur tous les ports.
4. Port non-SMTP depuis un pays hors liste autorisée : rejet.
5. Port de soumission avec une IP listée sur AbuseIPDB : rejet.

### Journalisation

Le log est écrit dans `LOGDIR\<préfixe>_AAAAMMJJ.log`, un fichier par jour, en
colonnes fixes :

```
2026-07-04 00:39:59  AutoBan     111.18.196.17    cn   +7d    Bad Country 143
2026-07-04 05:28:56  AutoBan     85.121.183.244   ro   +1d    Unknown USER 587
2026-07-04 17:39:24  AutoBan     20.12.240.184    us   +1d    AbuseIPDB 587
2026-07-09 11:47:15  AutoBan     193.138.195.94   zz   +1d    Conn flood 587
```

Colonnes : date et heure, source, IP, pays, durée de ban, détail. Au moins
deux espaces séparent les champs, on peut donc découper une ligne sur
`/ {2,}/`. La colonne `source` vaut `AutoBan`, `Disconnect`, `Reject`, `Spam`,
`AbuseIPDB`, `GeoLookup`, `Debug` ou `System`.

### Remarques

* La restriction géographique sur les ports non-SMTP peut aussi bloquer un
  utilisateur légitime qui relève son courrier en IMAP/POP depuis l'étranger.
  Gardez une durée de ban courte, mettez `GEORESTRICT.ban.qty` à `0` pour seulement
  déconnecter, ou `GEORESTRICT.action` à `"reject"` pour éviter un ban persistant.
* La protection contre les floods de connexions compte *toutes* les connexions :
  le script peut bannir un relais légitime qui ouvre beaucoup de connexions
  courtes.
  Augmentez `CONNFLOOD.threshold` ou élargissez `CONNFLOOD.windowMin` le cas
  échéant ; mettez `CONNFLOOD.enabled` à `false` pour la désactiver.
* Les bans sont stockés en plages d'IP et supprimés automatiquement à
  expiration. Des durées longues sur des sources à fort volume accumulent
  davantage de plages.
* Deux connexions simultanées d'un même hôte peuvent tenter de créer le même ban ;
  le doublon est géré proprement et journalisé une fois en `Debug`, pas en erreur.
* Le rejet sur score de spam fonctionne par défaut et suppose une couche
  anti-spam qui ajoute un en-tête de score avant l'acceptation du message
  (SpamAssassin le fait). Sans cet en-tête, le contrôle ne se déclenche jamais.
  Si vous utilisez aussi le seuil de suppression natif de hMailServer, n'en
  gardez qu'un seul : le seuil natif supprime silencieusement,
  le script renvoie un 550 à l'expéditeur.
* Le script vise le moteur JScript classique utilisé par hMailServer.
  `oMessage.HeaderValue("X") = valeur` y est la bonne façon de définir un
  en-tête et correspond aux propres tests de hMailServer ; ce n'est pas du
  JavaScript navigateur standard.

### Licence

MIT. Voir `LICENSE`.
