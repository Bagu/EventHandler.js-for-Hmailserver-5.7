/*
 * Banc d'essai de EventHandler.js sous Node : le script est chargé dans un
 * contexte isolé où hMailServer, le DNS, AbuseIPDB, le système de fichiers et le
 * shell sont remplacés par des imitations en mémoire.
 *   node tests/test.js                 lance les essais, rend "OK n/n" ou la liste des échecs
 *   node tests/test.js contre-epreuve  casse le script de plusieurs façons et vérifie
 *                                      que chaque casse fait échouer au moins un essai
 */
"use strict";
let fs = require("fs");
let path = require("path");
let vm = require("vm");

let SOURCE = fs.readFileSync(path.join(__dirname, "..", "EventHandler.js"), "utf8");

/**
 * Crée un contexte neuf avec le script chargé.
 * @param {string} code  source du script
 * @param {object} opt   dns: fonction(nom) -> texte TXT ou exception ; abuse: fonction(ip) -> bool
 * @returns {object} { ctx, files, ranges, runs }
 */
function charger(code, opt) {
    opt = opt || {};
    let files = {}, folders = {}, ranges = [], runs = [], http = [];

    function Fichier(p) {
        return {
            Write: function (s) { files[p].data += s; },
            ReadAll: function () { return files[p].data; },
            get AtEndOfStream() { return files[p].data === ""; },
            Close: function () {}
        };
    }
    let fso = {
        FolderExists: function (p) { return !!folders[p]; },
        CreateFolder: function (p) { folders[p] = true; },
        FileExists: function (p) { return Object.hasOwn(files, p); },
        DeleteFile: function (p) { delete files[p]; },
        GetFile: function (p) {
            if (!files[p]) throw { description: "not found" };
            return { DateLastModified: files[p].mtime };
        },
        CreateTextFile: function (p, overwrite) {
            if (files[p] && !overwrite) throw { description: "exists" };
            files[p] = { data: "", mtime: new Date() };
            return Fichier(p);
        },
        OpenTextFile: function (p, mode, create) {
            if (!files[p]) {
                if (!create) throw { description: "File not found" };
                files[p] = { data: "", mtime: new Date() };
            }
            return Fichier(p);
        }
    };
    let securityRanges = {
        Refresh: function () {},
        ItemByName: function (n) {
            for (let i = 0; i < ranges.length; i++) if (ranges[i].Name === n) return ranges[i];
            throw { description: "not found" };
        },
        Add: function () {
            let r = { Save: function () { ranges.push(r); } };
            return r;
        }
    };
    let fabriques = {
        "Scripting.FileSystemObject": function () { return fso; },
        "hMailServer.Application": function () {
            return {
                Authenticate: function (u, p) { return p === "secret"; },
                Settings: { SecurityRanges: securityRanges }
            };
        },
        "WScript.Shell": function () { return { Run: function (cmd) { runs.push(cmd); } }; },
        "MSXML2.ServerXMLHTTP.6.0": function () {
            let r = { status: 0, responseText: "" };
            r.setTimeouts = function () {};
            r.open = function (m, url) { r.url = url; };
            r.send = function () {
                http.push(r.url);
                let rep = (opt.http || function () { return [200, "203.0.113.7"]; })(r.url);
                r.status = rep[0]; r.responseText = rep[1];
            };
            return r;
        },
        "DNSLibrary.DNSResolver": function () {
            return { TXT: opt.dns || function () { return "fr\r\n"; } };
        },
        "AbuseIPDBComponent.AbuseIPDBRestClient": function () {
            return {
                SetApiKey: function () {}, SetMaxConfidenceScore: function () {},
                SetMaxAgeInDays: function () {},
                BlockEndpoint: opt.abuse || function () { return false; }
            };
        }
    };
    let ctx = {
        ActiveXObject: function (nom) {
            if (!fabriques[nom]) throw { description: "unknown COM " + nom };
            return fabriques[nom]();
        },
        EventLog: { Write: function () {} },
        Result: { Value: 0, Message: "" }
    };
    vm.createContext(ctx);
    vm.runInContext(code, ctx);
    files[ctx.SECRETS_FILE] = { data: "ADMIN_PASSWORD = secret\r\nABUSEIPDB_KEY = k\r\n", mtime: new Date() };
    return { ctx: ctx, files: files, ranges: ranges, runs: runs, http: http };
}

/** Lignes du journal d'événements écrites pendant un essai. */
function journal(t) {
    return Object.keys(t.files).filter(function (p) { return /events_\d+\.log$/.test(p); })
        .map(function (p) { return t.files[p].data; }).join("");
}

/** Imitation d'un client hMailServer. */
function client(ip, port, auth, user) {
    return { IPAddress: ip, Port: port, Authenticated: !!auth, Username: user || "" };
}

/** Rend un résolveur DNS qui donne un pays par IP (ordre inversé des octets). */
function dnsPays(table) {
    return function (nom) {
        let a = nom.split(".");
        let ip = a[3] + "." + a[2] + "." + a[1] + "." + a[0];
        if (table[ip] === "ERREUR") throw { description: "timed out" };
        return Object.hasOwn(table, ip) ? table[ip] + "\r\n" : "";
    };
}

let PAYS = { "1.1.1.1": "fr", "2.2.2.2": "us", "3.3.3.3": "cn", "4.4.4.4": "ERREUR", "5.5.5.5": "" };

/* Chaque essai rend true s'il réussit. */
let ESSAIS = {
    "GeoLookup lit le pays": function (code) {
        return charger(code, { dns: dnsPays(PAYS) }).ctx.GeoLookup("1.1.1.1") === "fr";
    },
    "GeoLookup rend zz quand le service ne connaît pas l'IP": function (code) {
        return charger(code, { dns: dnsPays(PAYS) }).ctx.GeoLookup("5.5.5.5") === "zz";
    },
    "GeoLookup rend xx quand le DNS échoue": function (code) {
        return charger(code, { dns: dnsPays(PAYS) }).ctx.GeoLookup("4.4.4.4") === "xx";
    },
    "GeoLookup rend xx pour une IPv6": function (code) {
        return charger(code, { dns: dnsPays(PAYS) }).ctx.GeoLookup("2001:db8::1") === "xx";
    },
    "pays autorisé sur IMAP : rien": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("1.1.1.1", 993));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0;
    },
    "pays bloqué sur SMTP : ban Bad Country": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("3.3.3.3", 25));
        return t.ctx.Result.Value === 1 && t.ranges.length === 1 && t.ranges[0].Name === "(Bad Country) 3.3.3.3";
    },
    "pays non autorisé sur IMAP : ban Geo restrict": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("2.2.2.2", 993));
        return t.ctx.Result.Value === 1 && t.ranges.length === 1 && t.ranges[0].Name === "(Geo restrict) 2.2.2.2";
    },
    "pays non autorisé sur SMTP 25 : accepté": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("2.2.2.2", 25));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0;
    },
    "DNS en échec sur IMAP : refus temporaire sans ban": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("4.4.4.4", 993));
        return t.ctx.Result.Value === 2 && /^4\./.test(t.ctx.Result.Message) &&
               t.ranges.length === 0 && t.runs.length === 0;
    },
    "DNS en échec sur SMTP 25 : accepté": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("4.4.4.4", 25));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0;
    },
    "IPv6 sur IMAP : refus temporaire sans ban": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("2001:db8::1", 993));
        return t.ctx.Result.Value === 2 && t.ranges.length === 0;
    },
    "IPv6 sur SMTP 25 : acceptée": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("2001:db8::1", 25));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0;
    },
    "IP locale : aucun filtre": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientConnect(client("172.16.0.5", 993));
        t.ctx.OnClientConnect(client("127.0.0.1", 993));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0;
    },
    "IP publique du site : aucun filtre, même en rafale": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS), abuse: function () { return true; } });
        t.ctx.LOCAL_PUBLIC_IPS = "|203.0.113.7|";
        for (let i = 0; i < 6; i++) t.ctx.OnClientConnect(client("203.0.113.7", 465));
        t.ctx.OnClientConnect(client("203.0.113.7", 993));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0;
    },
    "IP publique voisine de celle du site : ban Conn flood": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.LOCAL_PUBLIC_IPS = "|203.0.113.70|";
        for (let i = 0; i < 5; i++) t.ctx.OnClientConnect(client("203.0.113.7", 465));
        return t.ranges.length === 1 && t.ranges[0].Name === "(Conn flood) 203.0.113.7";
    },
    "IP publique auto : exemptée, service lu une seule fois": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        for (let i = 0; i < 6; i++) t.ctx.OnClientConnect(client("203.0.113.7", 465));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0 && t.http.length === 1;
    },
    "IP publique auto : une autre IP reste bannie en rafale": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        for (let i = 0; i < 5; i++) t.ctx.OnClientConnect(client("1.1.1.1", 465));
        return t.ranges.length === 1 && t.ranges[0].Name === "(Conn flood) 1.1.1.1";
    },
    "IP publique auto : relue après PUBLIC_IP_TTL_MIN": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        let vieux = Date.now() - (t.ctx.PUBLIC_IP_TTL_MIN + 1) * 60000;
        t.files[t.ctx.LOGDIR + "\\" + t.ctx.PUBLIC_IP_FILE] = { data: "198.51.100.9\t" + vieux, mtime: new Date() };
        t.ctx.OnClientConnect(client("203.0.113.7", 993));
        return t.ctx.Result.Value === 0 && t.ranges.length === 0 && t.http.length === 1;
    },
    "IP publique auto : cache valide, pas d'appel": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        t.files[t.ctx.LOGDIR + "\\" + t.ctx.PUBLIC_IP_FILE] = { data: "198.51.100.9\t" + Date.now(), mtime: new Date() };
        for (let i = 0; i < 6; i++) t.ctx.OnClientConnect(client("198.51.100.9", 465));
        return t.ranges.length === 0 && t.http.length === 0;
    },
    "IP publique auto : service en panne, un seul essai et une ligne au journal": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS), http: function () { throw { description: "timeout" }; } });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        for (let i = 0; i < 3; i++) t.ctx.OnClientConnect(client("203.0.113.7", 993));
        let lignes = journal(t).split("PublicIP error").length - 1;
        return t.ctx.Result.Value === 0 && t.http.length === 1 && lignes === 1;
    },
    "IP publique auto : panne, la dernière IP connue reste exemptée": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS), http: function () { return [503, ""]; } });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        let vieux = Date.now() - (t.ctx.PUBLIC_IP_TTL_MIN + 1) * 60000;
        t.files[t.ctx.LOGDIR + "\\" + t.ctx.PUBLIC_IP_FILE] = { data: "198.51.100.9\t" + vieux, mtime: new Date() };
        for (let i = 0; i < 6; i++) t.ctx.OnClientConnect(client("198.51.100.9", 465));
        return t.ranges.length === 0 && t.http.length === 1;
    },
    "IP publique auto : réponse qui n'est pas une IP, ignorée": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS), http: function () { return [200, "<html>203.0.113.7</html>"]; } });
        t.ctx.LOCAL_PUBLIC_IPS = "|auto|";
        for (let i = 0; i < 5; i++) t.ctx.OnClientConnect(client("203.0.113.7", 465));
        return t.ranges.length === 1 && t.http.length === 1;
    },
    "IP publique explicite : aucun appel au service": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.LOCAL_PUBLIC_IPS = "|203.0.113.7|";
        t.ctx.OnClientConnect(client("1.1.1.1", 993));
        return t.http.length === 0;
    },
    "rafale : 4 connexions SMTP, pas de ban": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        for (let i = 0; i < 4; i++) t.ctx.OnClientConnect(client("1.1.1.1", 25));
        return t.ranges.length === 0;
    },
    "rafale : 5e connexion SMTP, ban Conn flood": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        for (let i = 0; i < 5; i++) { t.ctx.Result.Value = 0; t.ctx.OnClientConnect(client("1.1.1.1", 25)); }
        return t.ctx.Result.Value === 1 && t.ranges.length === 1 && t.ranges[0].Name === "(Conn flood) 1.1.1.1";
    },
    "rafale : les ports 465 et 587 comptent aussi": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        let ports = [465, 587, 465, 587, 465];
        for (let i = 0; i < ports.length; i++) t.ctx.OnClientConnect(client("1.1.1.1", ports[i]));
        return t.ranges.length === 1 && t.ranges[0].Name === "(Conn flood) 1.1.1.1";
    },
    "rafale : 10 connexions IMAP, pas de ban": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        for (let i = 0; i < 10; i++) t.ctx.OnClientConnect(client("1.1.1.1", 993));
        return t.ranges.length === 0;
    },
    "rafale : IMAP ne s'ajoute pas au compte SMTP": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        for (let i = 0; i < 4; i++) t.ctx.OnClientConnect(client("1.1.1.1", 993));
        for (let j = 0; j < 4; j++) t.ctx.OnClientConnect(client("1.1.1.1", 25));
        return t.ranges.length === 0;
    },
    "AbuseIPDB sur 587 : ban": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS), abuse: function () { return true; } });
        t.ctx.OnClientConnect(client("1.1.1.1", 587));
        return t.ranges.length === 1 && t.ranges[0].Name === "(AbuseIPDB) 1.1.1.1";
    },
    "échec d'identification : ban Unknown USER": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.OnClientLogon(client("1.1.1.1", 993, false, "x@example.com"));
        return t.ranges.length === 1 && t.ranges[0].Name === "(Unknown USER) 1.1.1.1";
    },
    "Disconnect lance l'exe entre guillemets": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.Disconnect("1.1.1.1", "r", "fr", false);
        return t.runs.length === 1 && t.runs[0] === "\"" + t.ctx.DISCONNECT_EXE + "\" 1.1.1.1";
    },
    "Disconnect refuse une IP piégée": function (code) {
        let t = charger(code, { dns: dnsPays(PAYS) });
        t.ctx.Disconnect("1.1.1.1 & calc", "r", "fr", false);
        t.ctx.Disconnect("::1|calc", "r", "fr", false);
        return t.runs.length === 0;
    },
    "isValidIP accepte IPv4 et IPv6": function (code) {
        let c = charger(code).ctx;
        return c.isValidIP("8.8.8.8") && c.isValidIP("::1") && c.isValidIP("2001:db8::1") && !c.isValidIP("1.2.3.256");
    }
};

/**
 * Lance tous les essais sur un code.
 * @returns {string[]} noms des essais en échec
 */
function lancer(code) {
    let echecs = [];
    Object.keys(ESSAIS).forEach(function (nom) {
        let ok;
        try { ok = ESSAIS[nom](code) === true; } catch { ok = false; }
        if (!ok) echecs.push(nom);
    });
    return echecs;
}

/* Casses volontaires : chacune doit faire échouer au moins un essai. */
let CASSES = [
    ["GeoLookup rend zz sur erreur", /var GEO_FAILED\s*=\s*"xx"/, 'var GEO_FAILED = "zz"'],
    ["refus temporaire retiré", /if \(geo === GEO_FAILED && /, "if (false && "],
    ["rafale comptée sur tous les ports", /CONNFLOOD\.ports\.indexOf\("\|" \+ port \+ "\|"\) > -1/, "true"],
    ["contrôle de l'IP avant shell retiré", /if \(!isValidIP\(sIPAddress\)\) \{/, "if (false) {"],
    ["pays bloqués ignorés", /BLOCKED_COUNTRIES\.indexOf\("\|" \+ geo \+ "\|"\) > -1/, "false"],
    ["IP publique du site non exemptée", /LOCAL_PUBLIC_IPS\.indexOf\("\|" \+ ip \+ "\|"\) > -1/, "false"],
    ["IP publique du site comparée sans bornes", /LOCAL_PUBLIC_IPS\.indexOf\("\|" \+ ip \+ "\|"\)/, 'LOCAL_PUBLIC_IPS.indexOf("|" + ip)'],
    ["IP publique auto relue à chaque connexion", /if \(now - stamp < PUBLIC_IP_TTL_MIN \* 60000\) return known;/, ""],
    ["IP publique auto acceptée sans contrôle", /http\.status === 200 && isIPv4\(answer\)/, "http.status === 200"],
    ["échec du service non mémorisé", /if \(ip === ""\) ip = known;/, 'if (ip === "") return known;']
];

if (process.argv[2] === "contre-epreuve") {
    let sain = lancer(SOURCE);
    let mauvais = 0;
    if (sain.length) { console.log("TEMOIN EN ECHEC : " + sain.join(" ; ")); mauvais++; }
    CASSES.forEach(function (c) {
        if (!c[1].test(SOURCE)) { console.log("CASSE INTROUVABLE : " + c[0]); mauvais++; return; }
        let n = lancer(SOURCE.replace(c[1], c[2])).length;
        if (n === 0) { console.log("CASSE NON DETECTEE : " + c[0]); mauvais++; }
        else console.log("detectee (" + n + " echec(s)) : " + c[0]);
    });
    console.log(mauvais ? "CONTRE-EPREUVE EN ECHEC" : "CONTRE-EPREUVE OK, temoin sain silencieux");
    process.exit(mauvais ? 1 : 0);
} else {
    let echecs = lancer(SOURCE);
    let total = Object.keys(ESSAIS).length;
    if (echecs.length) {
        console.log("ECHEC " + echecs.length + "/" + total);
        echecs.forEach(function (n) { console.log("  - " + n); });
        process.exit(1);
    }
    console.log("OK " + total + "/" + total);
}
