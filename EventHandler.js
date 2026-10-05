/****************************************************************************
 *  EventHandlers.js  (Microsoft JScript pour hMailServer)
 *  Conversion de EventHandlers.vbs
 *
 *  Activation : hMailServer Admin -> Settings -> Advanced -> Scripts
 *               Langage = JScript, fichier nommé EventHandlers.js.
 *  Secrets    : mot de passe admin et clé AbuseIPDB dans SECRETS_FILE
 *               (lignes "CLE = valeur"), jamais dans ce fichier.
 ****************************************************************************/

/* ==========================  Paramètres  ============================== */
var ADMIN    = "YOUR_ADMIN_USERNAME";
var LOGDIR    = "C:\\path\\to\\your\\logs";
var LOGPREFIX = "events";
var DISCONNECT_EXE = "C:\\path\\to\\Disconnect.exe";

/**
 * Fichier des secrets, lu à la première utilisation. Clés attendues :
 * ADMIN_PASSWORD (mot de passe admin hMailServer), ABUSEIPDB_KEY (clé d'API).
 * @const {string} SECRETS_FILE
 */
var SECRETS_FILE = "C:\\path\\to\\EventHandlers.secrets.ini";

/**
 * Réseau local exempté de tout filtrage.
 * @const {string} LOCAL_IP_PREFIX  préfixe des IP du LAN
 * @const {string} LOCALHOST_IP     adresse de bouclage IPv4
 * @const {string} LOCALHOST_IP6    adresse de bouclage IPv6
 */
var LOCAL_IP_PREFIX = "172.16.";
var LOCALHOST_IP    = "127.0.0.1";
var LOCALHOST_IP6   = "::1";

/**
 * Domaines hébergés par ce serveur, en minuscules, entre barres verticales.
 * Sert à repérer un expéditeur non authentifié qui usurpe un domaine local.
 * @const {string} LOCAL_DOMAINS
 */
var LOCAL_DOMAINS = "|example.com|example.org|";

/**
 * Fonctions de filtrage : chaque fonction peut être désactivée (enabled) et son
 * action choisie - "ban" (crée une plage de sécurité temporaire persistante puis
 * coupe la session) ou "reject" (refuse uniquement la session courante avec un
 * message SMTP, sans ban). Le message n'est renvoyé que par les évènements qui
 * le permettent (connexion, acceptation de message).
 * Unité de ban (DateAdd) : "d"=jour, "h"=heure, "n"=minute, "s"=seconde ; ban.qty=0 => pas de ban.
 * @const {{enabled:boolean,action:string,ban:{qty:number,unit:string},msg:string}} GEOBLOCK  pays interdits (tous ports)
 * @const {object} GEORESTRICT  ports non-SMTP réservés aux pays d'ALLOWED_GEO
 * @const {object} ABUSEIPDB    réputation AbuseIPDB (ports de soumission) ; + maxConfidence, maxAgeDays
 * @const {object} UNKNOWNUSER  connexion non authentifiée (OnClientLogon)
 * @const {object} RCPTPROBE    sondes de destinataires (OnRecipientUnknown) ; + threshold, windowMin,
 *                              spoofLocal (ban au premier essai si l'expéditeur annonce un domaine local)
 * @const {object} CONNFLOOD    rafales de connexions par IP (OnClientConnect) ; + threshold, windowMin
 * @const {object} SPAMREJECT   score de spam élevé (OnAcceptMessage) ; + score, header
 */
var GEOBLOCK    = { enabled: true,  action: "ban",    ban: { qty: 7, unit: "d" },
                    msg: "5.7.1 Connection refused: connections from your location are not accepted by this server." };
var GEORESTRICT = { enabled: true,  action: "ban",    ban: { qty: 1, unit: "d" },
                    msg: "5.7.1 Connection refused: access from your location is not permitted for this service." };
var ABUSEIPDB   = { enabled: true,  action: "ban",    ban: { qty: 1, unit: "d" },
                    maxConfidence: 40, maxAgeDays: 90,
                    msg: "5.7.1 Connection refused: your IP address has an unacceptable reputation (AbuseIPDB). If you believe this is an error, please contact the recipient by other means." };
var UNKNOWNUSER = { enabled: true,  action: "ban",    ban: { qty: 1, unit: "d" },
                    msg: "5.7.1 Access denied: authentication is required." };
var RCPTPROBE   = { enabled: true,  action: "ban",    ban: { qty: 1, unit: "d" },
                    threshold: 3, windowMin: 10, spoofLocal: true,
                    msg: "5.7.1 Access denied: too many invalid recipients." };
var CONNFLOOD   = { enabled: true,  action: "ban",    ban: { qty: 7, unit: "d" },
                    threshold: 5, windowMin: 1,
                    msg: "5.7.1 Access denied: too many connections." };
var SPAMREJECT  = { enabled: true, action: "reject", ban: { qty: 1, unit: "d" },
                    score: 20.0, header: "X-Spam-Score",
                    msg: "5.7.1 Message rejected: the message was classified as spam (score too high)." };

/**
 * Fonctions de transformation d'en-têtes (sans action ban/reject) : simple activation.
 * @const {boolean} RECEIVEDANON_ENABLED  anonymisation de l'en-tête Received sortant
 * @const {boolean} MESSAGEID_ENABLED     complète un Message-Id manquant
 * @const {boolean} SPAMREPORT_ENABLED    rend l'en-tête X-Spam-Report lisible
 */
var RECEIVEDANON_ENABLED = true;
var MESSAGEID_ENABLED    = true;
var SPAMREPORT_ENABLED   = true;

/** @const {number} BAN_PRIORITY  priorité des plages créées (doit dépasser les plages "Internet"). */
var BAN_PRIORITY = 20;

/** @const {number} RANGE_NAME_MAX  longueur maximale d'un nom de plage dans la base hMailServer. */
var RANGE_NAME_MAX = 100;

/** @const {number} LOG_DETAIL_MAX  longueur maximale du texte libre d'une ligne de log. */
var LOG_DETAIL_MAX = 300;

/**
 * Compteurs par IP (fichier + verrou, sans base de données).
 * @const {string} RCPT_DATA_FILE  compteur des destinataires inconnus (dans LOGDIR)
 * @const {string} RCPT_LOCK_FILE  verrou de ce compteur
 * @const {string} CONN_DATA_FILE  compteur des connexions
 * @const {string} CONN_LOCK_FILE  verrou de ce compteur
 * @const {string} BAN_LOCK_FILE   verrou global sérialisant AutoBan
 * @const {number} LOCK_TRIES      nombre d'essais d'acquisition du verrou
 * @const {number} LOCK_WAIT_MS    pause entre deux essais
 * @const {number} LOCK_STALE_SEC  âge (s) au-delà duquel un verrou est considéré orphelin
 */
var RCPT_DATA_FILE = "rcpt_unknown.dat";
var RCPT_LOCK_FILE = "rcpt_unknown.lock";
var CONN_DATA_FILE = "conn_flood.dat";
var CONN_LOCK_FILE = "conn_flood.lock";
var BAN_LOCK_FILE  = "autoban.lock";
var LOCK_TRIES     = 20;
var LOCK_WAIT_MS   = 10;
var LOCK_STALE_SEC = 30;

var BLOCKED_COUNTRIES = "|cn|cz|ru|";
var ALLOWED_GEO       = "|fr|zz|";
var SMTP_PORTS        = "|25|587|465|";
var SUBMISSION_PORTS  = "|587|465|";
var GEO_DNS_SUFFIX    = "country.junkemailfilter.com";

/**
 * Journalisation par source : mettre false pour couper une catégorie de logs.
 * @const {object} LOG_SOURCES  table source -> booléen
 */
var LOG_SOURCES = {
    GeoLookup:  true,
    AutoBan:    true,
    AbuseIPDB:  true,
    Disconnect: true,
    Debug:      true,
    Reject:     true,
    Spam:       true,
    System:     true
};

/**
 * Largeur des colonnes du log (alignement par remplissage d'espaces).
 * @const {number} COL_SOURCE  largeur de la colonne source
 * @const {number} COL_IP      largeur de la colonne IP
 * @const {number} COL_GEO     largeur de la colonne pays
 * @const {number} COL_DUR     largeur de la colonne durée
 */
var COL_SOURCE = 10, COL_IP = 15, COL_GEO = 3, COL_DUR = 5;

/* ==========================  Utilitaires  ============================= */

/**
 * Supprime les espaces en début/fin.
 * @param {*} s  valeur à nettoyer
 * @returns {string}
 */
function Trim(s) {
    return String(s).replace(/^\s+|\s+$/g, "");
}

/**
 * Équivalent JScript de VBScript DateAdd : ajoute une durée à une date.
 * @param {string} interval  "yyyy"=année,"m"=mois,"d"=jour,"h"=heure,"n"=minute,"s"=seconde
 * @param {number} n         quantité à ajouter
 * @param {Date}   d         date de référence
 * @returns {Date}
 */
function DateAdd(interval, n, d) {
    var r = new Date(d.getTime());
    switch (interval) {
        case "yyyy": r.setFullYear(r.getFullYear() + n); break;
        case "m":    r.setMonth(r.getMonth() + n);       break;
        case "d":    r.setDate(r.getDate() + n);         break;
        case "h":    r.setHours(r.getHours() + n);       break;
        case "n":    r.setMinutes(r.getMinutes() + n);   break;
        case "s":    r.setSeconds(r.getSeconds() + n);   break;
    }
    return r;
}

/**
 * Convertit une Date JScript en sérial OLE Automation (VT_DATE ; jours depuis 1899-12-30).
 * @param {Date} d
 * @returns {number}
 */
function toOADate(d) {
    var localMs = d.getTime() - d.getTimezoneOffset() * 60000;
    return localMs / 86400000 + 25569;
}

/**
 * Attente active de quelques millisecondes (aucune fonction de pause dans ce moteur).
 * @param {number} ms
 */
function pause(ms) {
    var end = new Date().getTime() + ms;
    while (new Date().getTime() < end) {}
}

/**
 * Lit une valeur dans SECRETS_FILE (lignes "CLE = valeur", les autres lignes sont ignorées).
 * Le fichier est lu une seule fois par instance du moteur de script.
 * @param {string} key
 * @returns {string} la valeur, ou "" si absente ou fichier illisible
 */
var _secrets = null;
function Secret(key) {
    if (_secrets === null) {
        var found = {};
        try {
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            var f = fso.OpenTextFile(SECRETS_FILE, 1);
            var lines = f.AtEndOfStream ? [] : f.ReadAll().split(/\r?\n/);
            f.Close();
            for (var i = 0; i < lines.length; i++) {
                var m = lines[i].match(/^\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$/);
                if (m) found[m[1]] = m[2];
            }
        } catch (e) {
            Log("System", "", "", "", "secrets file unreadable - " + e.description);
        }
        _secrets = found;
    }
    return _secrets.hasOwnProperty(key) ? _secrets[key] : "";
}

/**
 * Assainit une chaîne pour un log ASCII : échappe tout caractère non imprimable
 * ou non-ASCII, remplace la tabulation par une espace.
 * @param {*} s
 * @returns {string} chaîne ASCII pure
 */
function logSanitize(s) {
    s = String(s);
    var out = "", code, hex;
    for (var i = 0; i < s.length; i++) {
        code = s.charCodeAt(i);
        if (code === 9) {
            out += " ";
        } else if (code < 32 || code > 126) {
            hex = code.toString(16).toUpperCase();
            while (hex.length < 4) hex = "0" + hex;
            out += "\\u" + hex;
        } else {
            out += s.charAt(i);
        }
    }
    return out;
}

/**
 * Complète une chaîne par des espaces à droite jusqu'à la largeur voulue, sans tronquer.
 * @param {*} s
 * @param {number} w
 * @returns {string}
 */
function padRight(s, w) {
    s = String(s);
    while (s.length < w) s += " ";
    return s;
}

/**
 * Extrait un score numérique d'un en-tête de spam : score brut ("15.2") ou
 * format X-Spam-Status ("Yes, score=15.2 required=5.0 ...").
 * @param {*} raw  valeur de l'en-tête
 * @returns {number} le score, ou NaN si absent/illisible
 */
function parseSpamScore(raw) {
    var s = Trim(raw);
    if (s === "") return NaN;
    var m = s.match(/score=(-?\d+(\.\d+)?)/i);
    if (m) return parseFloat(m[1]);
    return parseFloat(s);
}

/**
 * Écrit une ligne de log en colonnes de largeur fixe :
 *   AAAA-MM-JJ HH:MM:SS  SOURCE  IP  PAYS  DUREE  DETAIL
 * Fichier journalier ASCII. Réessaie en cas de verrou concurrent, se replie sur
 * EventLog.Write, ne remonte jamais d'exception.
 * @param {string} source  catégorie (voir LOG_SOURCES)
 * @param {string} ip      IP concernée ("" -> "-")
 * @param {string} geo     code pays ("" -> "-")
 * @param {string} dur     durée de ban ex. "+1d" ("" -> "-")
 * @param {*}      detail  texte libre, tronqué à LOG_DETAIL_MAX caractères
 */
function Log(source, ip, geo, dur, detail) {
    if (LOG_SOURCES[source] === false) return;

    ip     = (ip     === undefined || ip     === "") ? "-" : ip;
    geo    = (geo    === undefined || geo    === "") ? "-" : geo;
    dur    = (dur    === undefined || dur    === "") ? "-" : dur;
    detail = (detail === undefined) ? "" : String(detail);
    if (detail.length > LOG_DETAIL_MAX) detail = detail.substring(0, LOG_DETAIL_MAX) + "...";

    var d = new Date();
    function p2(n) { return (n < 10 ? "0" : "") + n; }
    var day  = d.getFullYear() + p2(d.getMonth() + 1) + p2(d.getDate());
    var ts   = d.getFullYear() + "-" + p2(d.getMonth() + 1) + "-" + p2(d.getDate()) +
               " " + p2(d.getHours()) + ":" + p2(d.getMinutes()) + ":" + p2(d.getSeconds());
    var path = LOGDIR + "\\" + LOGPREFIX + "_" + day + ".log";

    var line = ts + "  " +
               padRight(source, COL_SOURCE) + "  " +
               padRight(logSanitize(ip),  COL_IP)  + "  " +
               padRight(logSanitize(geo), COL_GEO) + "  " +
               padRight(logSanitize(dur), COL_DUR) + "  " +
               logSanitize(detail) + "\r\n";

    try {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        if (!fso.FolderExists(LOGDIR)) { try { fso.CreateFolder(LOGDIR); } catch (eF) {} }

        var ForAppending = 8, done = false;
        for (var attempt = 0; attempt < 5 && !done; attempt++) {
            try {
                var f = fso.OpenTextFile(path, ForAppending, true, 0);
                f.Write(line);
                f.Close();
                done = true;
            } catch (eW) {
                pause(LOCK_WAIT_MS);
            }
        }
        if (!done) EventLog.Write("[Log fallback] " + line);
    } catch (e) {
        try { EventLog.Write("[Log error] " + e.description + " | " + line); } catch (e2) {}
    }
}

/* ====================  Sécurité et filtrage à l'entrée  =============== */

/**
 * Indique si une IP appartient au réseau local exempté (LAN ou bouclage).
 * @param {string} ip
 * @returns {boolean}
 */
function isLocalIP(ip) {
    return ip.substring(0, LOCAL_IP_PREFIX.length) === LOCAL_IP_PREFIX ||
           ip === LOCALHOST_IP || ip === LOCALHOST_IP6;
}

/**
 * Indique si une chaîne est une IPv4 valide.
 * @param {string} ip
 * @returns {boolean}
 */
function isIPv4(ip) {
    return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(String(ip));
}

/**
 * Valide qu'une chaîne est bien une IP (v4/v6) avant tout appel shell.
 * Refuse tout caractère qui permettrait d'injecter une commande.
 * @param {string} ip
 * @returns {boolean}
 */
function isValidIP(ip) {
    var s = String(ip);
    if (isIPv4(s)) return true;
    if (s.indexOf(":") === -1) return false;
    if (/[^0-9A-Fa-f:.]/.test(s)) return false;
    if ((s.match(/::/g) || []).length > 1) return false;
    if (s.replace(/[^:]/g, "").length > 7) return false;
    return true;
}

/**
 * Vérifie la réputation d'une IP via le composant COM AbuseIPDB.
 * Toute erreur (clé absente, composant absent, réseau) est journalisée et traitée
 * en "non listée" pour ne jamais bloquer le courrier légitime.
 * @param {string} strIP
 * @returns {boolean}  true si l'IP doit être bloquée
 */
function ListedInAbuseIPDB(strIP) {
    var key = Secret("ABUSEIPDB_KEY");
    if (key === "") {
        Log("AbuseIPDB", strIP, "", "", "error - ABUSEIPDB_KEY missing in secrets file");
        return false;
    }
    try {
        var client = new ActiveXObject("AbuseIPDBComponent.AbuseIPDBRestClient");
        client.SetApiKey(key);
        client.SetMaxConfidenceScore(ABUSEIPDB.maxConfidence);
        client.SetMaxAgeInDays(ABUSEIPDB.maxAgeDays);
        return client.BlockEndpoint(strIP) ? true : false;
    } catch (e) {
        Log("AbuseIPDB", strIP, "", "", "error - " + e.description);
        return false;
    }
}

/**
 * Résout le code pays d'une IPv4 via junkemailfilter.com (DNS TXT inversé).
 * Toute erreur, et toute adresse non IPv4, rend "zz" (autorisé par ALLOWED_GEO).
 * @param {string} strIP
 * @returns {string}  code pays (2 lettres) ou "zz" si inconnu
 */
function GeoLookup(strIP) {
    var geo = "zz";
    if (!isIPv4(strIP)) return geo;
    try {
        var a = String(strIP).split(".");
        var name = a[3] + "." + a[2] + "." + a[1] + "." + a[0] + "." + GEO_DNS_SUFFIX;
        var resolver = new ActiveXObject("DNSLibrary.DNSResolver");
        var strLookup = resolver.TXT(name);

        if (Trim(strLookup) === "") return geo;

        var group = String(strLookup).split("\r\n");
        for (var i = 0; i < group.length; i++) {
            if (Trim(group[i]) !== "") { geo = Trim(group[i]); break; }
        }
    } catch (e) {
        Log("System", strIP, "", "", "GeoLookup error - " + e.description);
    }
    return Trim(String(geo)).toLowerCase();
}

/**
 * Construit le nom d'une plage de sécurité, borné à RANGE_NAME_MAX caractères.
 * @param {string} tag  catégorie fixe ("Bad Country", "Conn flood"...)
 * @param {string} ip
 * @returns {string}
 */
function rangeName(tag, ip) {
    return ("(" + tag + ") " + ip).substring(0, RANGE_NAME_MAX);
}

/**
 * Indique si une plage de sécurité portant ce nom existe déjà.
 * @param {object} ranges  collection SecurityRanges
 * @param {string} name    nom exact de la plage
 * @returns {boolean}
 */
function rangeExists(ranges, name) {
    try {
        var existing = ranges.ItemByName(name);
        return (existing != null);
    } catch (e) {
        return false;
    }
}

/* ========================  Actions (ban / déconnexion)  ============== */

/**
 * Ajoute une plage de sécurité (ban) à durée limitée si elle n'existe pas.
 * Toute erreur (secret absent, authentification, ajout, sauvegarde) est journalisée sans être propagée.
 * @param {string} sIPAddress
 * @param {string} tag        catégorie fixe, sert au nom de la plage
 * @param {string} detail     motif complet, journalisé
 * @param {number} iDuration  durée
 * @param {string} sType      unité DateAdd ("d","h","n"...)
 * @param {string} [geo]      code pays (journalisation seulement)
 * @returns {boolean}  true si le ban a été créé
 */
function AutoBan(sIPAddress, tag, detail, iDuration, sType, geo) {
    var added = false;
    var fso, gotLock = false;
    var lockPath = LOGDIR + "\\" + BAN_LOCK_FILE;
    try {
        var password = Secret("ADMIN_PASSWORD");
        if (password === "") {
            Log("AutoBan", sIPAddress, geo, "", "error - ADMIN_PASSWORD missing in secrets file");
            return false;
        }

        fso = new ActiveXObject("Scripting.FileSystemObject");
        if (!fso.FolderExists(LOGDIR)) { try { fso.CreateFolder(LOGDIR); } catch (eF) {} }
        gotLock = acquireLock(fso, lockPath, LOCK_TRIES);

        var oApp = new ActiveXObject("hMailServer.Application");
        if (!oApp.Authenticate(ADMIN, password)) {
            Log("AutoBan", sIPAddress, geo, "", "error - admin authentication failed");
            if (gotLock) { releaseLock(fso, lockPath); gotLock = false; }
            return false;
        }

        var ranges = oApp.Settings.SecurityRanges;
        ranges.Refresh();
        var name = rangeName(tag, sIPAddress);

        if (rangeExists(ranges, name)) {
            if (gotLock) { releaseLock(fso, lockPath); gotLock = false; }
            return added;
        }

        try {
            var r = ranges.Add();
            r.Name        = name;
            r.LowerIP     = sIPAddress;
            r.UpperIP     = sIPAddress;
            r.Priority    = BAN_PRIORITY;
            r.AllowSMTPConnections            = false;
            r.AllowPOP3Connections            = false;
            r.AllowIMAPConnections            = false;
            r.AllowDeliveryFromLocalToLocal   = false;
            r.AllowDeliveryFromLocalToRemote  = false;
            r.AllowDeliveryFromRemoteToLocal  = false;
            r.AllowDeliveryFromRemoteToRemote = false;
            r.Expires     = true;
            r.ExpiresTime = toOADate(DateAdd(sType, iDuration, new Date()));
            r.Save();
            added = true;
            Log("AutoBan", sIPAddress, geo, "+" + iDuration + sType, detail);
        } catch (eSave) {
            ranges.Refresh();
            if (rangeExists(ranges, name)) {
                Log("Debug", sIPAddress, geo, "", "ban already exists (concurrent) - " + detail);
            } else {
                Log("AutoBan", sIPAddress, geo, "", "error - " + eSave.description);
            }
        }
    } catch (e) {
        Log("AutoBan", sIPAddress, geo, "", "error - " + e.description);
    }
    if (gotLock) releaseLock(fso, lockPath);
    return added;
}

/**
 * Bannit l'IP selon une config {qty, unit} ; qty<=0 => aucun ban.
 * @param {string} ip
 * @param {string} tag     catégorie fixe (nom de plage)
 * @param {string} detail  motif complet (journal)
 * @param {{qty:number,unit:string}} cfg
 * @param {string} [geo]   code pays (journalisation seulement)
 */
function BanBy(ip, tag, detail, cfg, geo) {
    if (cfg && cfg.qty > 0) AutoBan(ip, tag, detail, cfg.qty, cfg.unit, geo);
}

/**
 * Bannit (selon cfg) puis déconnecte l'IP. La déconnexion n'est journalisée que
 * si aucun ban n'a été posé (qty=0), le ban ayant déjà sa ligne AutoBan.
 * @param {string} ip
 * @param {string} tag
 * @param {string} detail
 * @param {{qty:number,unit:string}} cfg
 * @param {string} [geo]
 */
function BanAndDisconnect(ip, tag, detail, cfg, geo) {
    var willBan = (cfg && cfg.qty > 0);
    BanBy(ip, tag, detail, cfg, geo);
    Disconnect(ip, detail, geo, !willBan);
}

/**
 * Lance Disconnect.exe pour l'IP, sans attendre sa fin, et journalise l'action.
 * L'IP est validée avant l'appel shell.
 * @param {string} sIPAddress
 * @param {string} reason
 * @param {string} [geo]    code pays déjà résolu (évite un GeoLookup redondant)
 * @param {boolean} [doLog] journaliser l'action (défaut true)
 */
function Disconnect(sIPAddress, reason, geo, doLog) {
    if (doLog === undefined) doLog = true;
    if (typeof geo === "undefined") geo = GeoLookup(sIPAddress);

    if (!isValidIP(sIPAddress)) {
        Log("Disconnect", sIPAddress, "", "", "skipped invalid IP");
        return;
    }
    try {
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("\"" + DISCONNECT_EXE + "\" " + sIPAddress, 0, false);
        if (doLog) Log("Disconnect", sIPAddress, geo, "", reason);
    } catch (e) {
        Log("System", sIPAddress, "", "", "Disconnect error - " + e.description);
    }
}

/**
 * Refuse la session ou le message courant au niveau SMTP (code 5xx + message),
 * sans ban, et journalise une ligne.
 * @param {string} ip
 * @param {string} reason     détail journalisé
 * @param {string} geo
 * @param {string} msg        message SMTP renvoyé au client
 * @param {string} logSource  source de log ("Reject", "Spam"...)
 */
function rejectSMTP(ip, reason, geo, msg, logSource) {
    Result.Value = 2;
    Result.Message = msg;
    Log(logSource, ip, geo, "", reason);
}

/**
 * Applique l'action configurée d'une fonction de filtrage :
 *  - "ban"    : plage de sécurité temporaire puis déconnexion ;
 *  - "reject" : refus de la seule session courante (message SMTP si l'évènement le permet), sans ban.
 * @param {{action:string,ban:{qty:number,unit:string},msg:string}} cfg
 * @param {string}  ip
 * @param {string}  tag         catégorie fixe, sert au nom de la plage (ex. "Bad Country")
 * @param {string}  detail      motif complet journalisé (ex. "Bad Country 143")
 * @param {string}  geo
 * @param {boolean} canMessage  true si l'évènement peut renvoyer un message SMTP
 */
function enforce(cfg, ip, tag, detail, geo, canMessage) {
    if (cfg.action === "reject") {
        if (canMessage) { rejectSMTP(ip, detail, geo, cfg.msg, "Reject"); }
        else            { Log("Reject", ip, geo, "", detail); Disconnect(ip, detail, geo, false); }
    } else {
        if (canMessage) Result.Value = 1;
        BanAndDisconnect(ip, tag, detail, cfg.ban, geo);
    }
}

/* ==============  Compteurs par IP (fichier + verrou)  ================= */

/**
 * Acquiert un verrou exclusif par création d'un fichier .lock, avec une courte
 * pause entre deux essais. Supprime un verrou plus vieux que LOCK_STALE_SEC.
 * @param {object} fso       instance FileSystemObject
 * @param {string} lockPath  chemin du fichier verrou
 * @param {number} tries     nombre d'essais
 * @returns {boolean} true si le verrou est obtenu
 */
function acquireLock(fso, lockPath, tries) {
    for (var i = 0; i < tries; i++) {
        try {
            var lf = fso.CreateTextFile(lockPath, false);
            lf.Close();
            return true;
        } catch (e) {
            try {
                var f = fso.GetFile(lockPath);
                var ageSec = (new Date().getTime() - new Date(f.DateLastModified).getTime()) / 1000;
                if (ageSec > LOCK_STALE_SEC) { fso.DeleteFile(lockPath); continue; }
            } catch (e2) {}
            if (i < tries - 1) pause(LOCK_WAIT_MS);
        }
    }
    return false;
}

/**
 * Libère le verrou (suppression du .lock).
 * @param {object} fso
 * @param {string} lockPath
 */
function releaseLock(fso, lockPath) {
    try { if (fso.FileExists(lockPath)) fso.DeleteFile(lockPath); } catch (e) {}
}

/**
 * Lit le fichier compteur -> map ip -> {count, first}, en ignorant les lignes
 * corrompues et les entrées hors fenêtre. Ligne : "ip<TAB>count<TAB>firstEpochSec".
 * @param {object} fso
 * @param {string} path
 * @param {number} now        epoch secondes courant
 * @param {number} windowSec  fenêtre en secondes
 * @returns {object} map ip -> {count, first}
 */
function readCounter(fso, path, now, windowSec) {
    var map = {};
    try {
        if (!fso.FileExists(path)) return map;
        var f = fso.OpenTextFile(path, 1);
        var content = f.AtEndOfStream ? "" : f.ReadAll();
        f.Close();
        var lines = content.split("\r\n");
        for (var i = 0; i < lines.length; i++) {
            var ln = Trim(lines[i]);
            if (ln === "") continue;
            var p = ln.split("\t");
            if (p.length < 3) continue;
            var cnt = parseInt(p[1], 10), first = parseInt(p[2], 10);
            if (isNaN(cnt) || isNaN(first)) continue;
            if ((now - first) > windowSec) continue;
            map[p[0]] = { count: cnt, first: first };
        }
    } catch (e) {}
    return map;
}

/**
 * Réécrit le fichier compteur (ASCII) à partir de la map.
 * @param {object} fso
 * @param {string} path
 * @param {object} map  ip -> {count, first}
 */
function writeCounter(fso, path, map) {
    try {
        var f = fso.CreateTextFile(path, true);
        for (var ip in map) {
            if (map.hasOwnProperty(ip)) {
                f.Write(ip + "\t" + map[ip].count + "\t" + map[ip].first + "\r\n");
            }
        }
        f.Close();
    } catch (e) {}
}

/**
 * Incrémente sous verrou le compteur d'une IP dans un fichier, sur une fenêtre fixe
 * démarrant au premier évènement. L'entrée est retirée quand le seuil est atteint.
 * @param {string} ip
 * @param {string} dataFile   nom du fichier compteur (dans LOGDIR)
 * @param {string} lockFile   nom du fichier verrou (dans LOGDIR)
 * @param {number} windowMin  fenêtre en minutes
 * @param {number} threshold  seuil
 * @param {string} label      nom du compteur pour le journal
 * @returns {boolean} true si le seuil vient d'être atteint
 */
function countHit(ip, dataFile, lockFile, windowMin, threshold, label) {
    var fso, gotLock = false, reached = false;
    var dataPath = LOGDIR + "\\" + dataFile;
    var lockPath = LOGDIR + "\\" + lockFile;
    try {
        fso = new ActiveXObject("Scripting.FileSystemObject");
        if (!fso.FolderExists(LOGDIR)) { try { fso.CreateFolder(LOGDIR); } catch (eF) {} }

        gotLock = acquireLock(fso, lockPath, LOCK_TRIES);
        if (!gotLock) { Log("Debug", ip, "", "", label + " lock busy, skipped"); return false; }

        var now = Math.round(new Date().getTime() / 1000);
        var windowSec = windowMin * 60;
        var map = readCounter(fso, dataPath, now, windowSec);

        var e = map[ip];
        if (e && (now - e.first) <= windowSec) { e.count = e.count + 1; }
        else                                   { e = { count: 1, first: now }; }
        map[ip] = e;

        if (e.count >= threshold) {
            delete map[ip];
            reached = true;
        }
        writeCounter(fso, dataPath, map);
    } catch (eMain) {
        try { Log("System", ip, "", "", label + " error - " + eMain.description); } catch (e2) {}
    } finally {
        if (gotLock) releaseLock(fso, lockPath);
    }
    return reached;
}

/**
 * Compte les destinataires inconnus par IP ; bannit au seuil RCPTPROBE.threshold.
 * @param {string} ip
 */
function RcptUnknownCount(ip) {
    if (!isValidIP(ip)) return;
    if (countHit(ip, RCPT_DATA_FILE, RCPT_LOCK_FILE, RCPTPROBE.windowMin, RCPTPROBE.threshold, "rcpt-counter")) {
        enforce(RCPTPROBE, ip, "Rcpt probe", "Rcpt probe", GeoLookup(ip), false);
    }
}

/**
 * Compte les connexions par IP ; bannit au seuil CONNFLOOD.threshold et refuse
 * la connexion courante.
 * @param {string} ip    adresse IP source
 * @param {string} port  port de connexion (pour le journal)
 * @returns {boolean} true si l'IP vient d'être bannie (l'appelant doit sortir)
 */
function ConnFloodCount(ip, port) {
    if (!isValidIP(ip)) return false;
    if (countHit(ip, CONN_DATA_FILE, CONN_LOCK_FILE, CONNFLOOD.windowMin, CONNFLOOD.threshold, "conn-counter")) {
        enforce(CONNFLOOD, ip, "Conn flood", "Conn flood " + port, GeoLookup(ip), true);
        return true;
    }
    return false;
}

/**
 * Rend le domaine d'une adresse, en minuscules ("" si absent).
 * @param {*} address
 * @returns {string}
 */
function domainOf(address) {
    var s = Trim(address).toLowerCase();
    var at = s.lastIndexOf("@");
    return (at > -1) ? s.substring(at + 1) : "";
}

/* ======================  Déclencheurs hMailServer  ==================== */

/**
 * Ban + déconnexion des connexions non authentifiées. Exclut le LAN et le bouclage.
 * @param {object} oClient  informations client hMailServer
 */
function OnClientLogon(oClient) {
    try {
        if (!UNKNOWNUSER.enabled) return;
        var ip = String(oClient.IPAddress);
        if (isLocalIP(ip)) return;

        if (!oClient.Authenticated) {
            var geo = GeoLookup(ip);
            enforce(UNKNOWNUSER, ip, "Unknown USER",
                    "Unknown USER " + oClient.Port + " - " + oClient.Username, geo, false);
        }
    } catch (e) {
        try { Log("System", "", "", "", "OnClientLogon error - " + e.description); } catch (e2) {}
    }
}

/**
 * Filtrage à la connexion (le LAN et le bouclage sont exemptés) :
 * 0) bannit les IP qui dépassent le seuil de connexions (CONNFLOOD) ;
 * 1) rejette les pays de BLOCKED_COUNTRIES ;
 * 2) sur les ports non-SMTP, n'autorise que les pays d'ALLOWED_GEO ;
 * 3) sur les ports de soumission (587/465), rejette les IP listées sur AbuseIPDB.
 * @param {object} oClient  informations client hMailServer
 */
function OnClientConnect(oClient) {
    try {
        var ip = String(oClient.IPAddress);
        if (isLocalIP(ip)) return;

        var port = String(oClient.Port);

        if (CONNFLOOD.enabled && ConnFloodCount(ip, port)) return;

        var geo  = (GEOBLOCK.enabled || GEORESTRICT.enabled) ? GeoLookup(ip) : "-";

        if (GEOBLOCK.enabled && BLOCKED_COUNTRIES.indexOf("|" + geo + "|") > -1) {
            enforce(GEOBLOCK, ip, "Bad Country", "Bad Country " + port, geo, true);
            return;
        }

        if (GEORESTRICT.enabled && SMTP_PORTS.indexOf("|" + port + "|") === -1) {
            if (ALLOWED_GEO.indexOf("|" + geo + "|") === -1) {
                enforce(GEORESTRICT, ip, "Geo restrict", "Geo restrict " + port, geo, true);
                return;
            }
        }

        if (ABUSEIPDB.enabled && SUBMISSION_PORTS.indexOf("|" + port + "|") > -1) {
            if (ListedInAbuseIPDB(ip)) {
                enforce(ABUSEIPDB, ip, "AbuseIPDB", "AbuseIPDB " + port, geo, true);
                return;
            }
        }
    } catch (e) {
        try { Log("System", "", "", "", "OnClientConnect error - " + e.description); } catch (e2) {}
    }
}

/**
 * Rejette au niveau SMTP les messages dont le score de spam atteint le seuil.
 * @param {object} oClient
 * @param {object} oMessage
 */
function OnAcceptMessage(oClient, oMessage) {
    try {
        if (!SPAMREJECT.enabled) return;

        var score = parseSpamScore(oMessage.HeaderValue(SPAMREJECT.header));
        if (!isNaN(score) && score >= SPAMREJECT.score) {
            var ip = oClient ? String(oClient.IPAddress) : "-";
            if (SPAMREJECT.action === "ban") BanBy(ip, "Spam", "Spam " + score, SPAMREJECT.ban, GeoLookup(ip));
            rejectSMTP(ip, "score=" + score, "", SPAMREJECT.msg + " (" + score + ")", "Spam");
        }
    } catch (e) {
        try { Log("System", "", "", "", "OnAcceptMessage error - " + e.description); } catch (e2) {}
    }
}

/**
 * Anonymise l'en-tête Received du courrier sortant authentifié (ne conserve qu'à partir de "by ").
 * @param {object} oMessage
 */
function OnDeliveryStart(oMessage) {
    try {
        if (!RECEIVEDANON_ENABLED) return;
        var strReceived = oMessage.HeaderValue("Received");
        if (strReceived &&
            (strReceived.indexOf("ESMTPSA") !== -1 || strReceived.indexOf("ESMTPA") !== -1)) {
            var pos = strReceived.indexOf("by ");
            if (pos !== -1) {
                oMessage.HeaderValue("Received") = strReceived.substring(pos);
                oMessage.Save();
            }
        }
    } catch (e) {
        try { Log("System", "", "", "", "OnDeliveryStart error - " + e.description); } catch (e2) {}
    }
}

/**
 * Complète un Message-Id manquant, puis rend l'en-tête X-Spam-Report lisible
 * (une ligne par astérisque). Un seul enregistrement du message.
 * @param {object} oMessage
 */
function OnDeliverMessage(oMessage) {
    try {
        var changed = false;

        if (MESSAGEID_ENABLED && oMessage.HeaderValue("Message-Id") === "") {
            var dom = domainOf(oMessage.FromAddress);
            if (dom !== "") {
                var utils = new ActiveXObject("hMailServer.Utilities");
                var guid = utils.GenerateGUID();
                oMessage.HeaderValue("Message-Id") = "<" + guid.substr(1, 36) + "@" + dom + ">";
                changed = true;
            }
        }

        if (SPAMREPORT_ENABLED) {
            var spam = oMessage.HeaderValue("X-Spam-Report");
            if (spam !== "") {
                var readable = String(spam).replace(/\s*\*/g, "\r\n *");
                if (readable !== spam) {
                    oMessage.HeaderValue("X-Spam-Report") = readable;
                    changed = true;
                }
            }
        }

        if (changed) oMessage.Save();
    } catch (e) {
        try { Log("System", "", "", "", "OnDeliverMessage error - " + e.description); } catch (e2) {}
    }
}

/**
 * Destinataire inconnu pour un client non authentifié hors LAN : ban immédiat si
 * l'expéditeur annonce un domaine local (RCPTPROBE.spoofLocal), sinon comptage
 * par IP et ban au seuil.
 * @param {object} oClient
 * @param {object} oMessage
 */
function OnRecipientUnknown(oClient, oMessage) {
    try {
        if (!RCPTPROBE.enabled) return;
        var ip = String(oClient.IPAddress);
        if (isLocalIP(ip)) return;
        if (oClient.Authenticated) return;

        var from = "";
        try { if (RCPTPROBE.spoofLocal && oMessage) from = Trim(oMessage.FromAddress); } catch (eFrom) {}
        var dom = domainOf(from);
        if (dom !== "" && LOCAL_DOMAINS.indexOf("|" + dom + "|") > -1 && isValidIP(ip)) {
            enforce(RCPTPROBE, ip, "Rcpt spoof", "Rcpt spoof - " + from, GeoLookup(ip), false);
            return;
        }

        RcptUnknownCount(ip);
    } catch (e) {
        try { Log("System", "", "", "", "OnRecipientUnknown error - " + e.description); } catch (e2) {}
    }
}
