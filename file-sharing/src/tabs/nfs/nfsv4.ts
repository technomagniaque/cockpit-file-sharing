/**
 * NFSv4.1 : lecture / édition de /etc/nfs.conf, analyse de l'état réel du
 * serveur (/proc/fs/nfsd/versions, idmapping) et des options d'export.
 *
 * Module pur (aucun accès serveur) : testable sans cockpit.
 *
 * Références :
 *  - noyau fs/nfsd/nfsctl.c (write_versions : format « +3 +4 +4.0 +4.1 -4.2 »)
 *  - noyau fs/nfsd/nfs4idmap.c (nfs4_disable_idmapping, défaut vrai : avec
 *    sec=sys les propriétaires circulent en UID / GID numériques)
 *  - noyau include/uapi/linux/nfsd/export.h (NFSEXP_NOACL « réservé », aucune
 *    utilisation dans fs/nfsd : l'option no_acl est sans effet sur knfsd)
 *  - nfs.conf(5) / exports(5) de nfs-utils (clés et défauts cités de mémoire :
 *    le dépôt nfs-utils n'était pas accessible pour vérification)
 */
import type { NFSExport } from "./data-types";

// ------------------------------------------------------------------ nfs.conf

export interface NfsConfField {
  section: string;
  key: string;
  label: string;
  type: "bool" | "int" | "string";
  /** défaut de nfs-utils quand la clé est absente */
  default: string;
  help: string;
}

export const NFS_CONF_FIELDS: NfsConfField[] = [
  { section: "nfsd", key: "vers3", label: "NFSv3", type: "bool", default: "y", help: "Exige rpcbind et mountd (ports 111 / 20048). À désactiver pour un serveur NFSv4 seul." },
  { section: "nfsd", key: "vers4", label: "NFSv4 (toutes versions mineures)", type: "bool", default: "y", help: "Interrupteur global de NFSv4." },
  { section: "nfsd", key: "vers4.0", label: "NFSv4.0", type: "bool", default: "y", help: "Pas de sessions ni de « exactly once » : préférez 4.1." },
  { section: "nfsd", key: "vers4.1", label: "NFSv4.1", type: "bool", default: "y", help: "Sessions, trunking de session (multi-chemin), reprise fiable." },
  { section: "nfsd", key: "vers4.2", label: "NFSv4.2", type: "bool", default: "y", help: "Copie côté serveur, fichiers épars, xattrs utilisateur (RFC 8276), étiquettes de sécurité." },
  { section: "nfsd", key: "threads", label: "Threads nfsd", type: "int", default: "8", help: "Nombre de threads serveur (16 à 64 pour du 10/25 Gb/s)." },
  { section: "nfsd", key: "grace-time", label: "Délai de grâce (s)", type: "int", default: "90", help: "Fenêtre de reprise des verrous / ouvertures après redémarrage." },
  { section: "nfsd", key: "lease-time", label: "Durée de bail NFSv4 (s)", type: "int", default: "90", help: "Durée de vie de l'état client sans renouvellement." },
  { section: "nfsd", key: "rdma", label: "NFS sur RDMA", type: "bool", default: "n", help: "Transport RDMA (svcrdma) : utile avec une carte iWARP / RoCE (ex. QL41112)." },
  { section: "nfsd", key: "rdma-port", label: "Port RDMA", type: "int", default: "20049", help: "Port d'écoute NFS/RDMA." },
  { section: "nfsd", key: "udp", label: "UDP", type: "bool", default: "n", help: "NFSv4 n'utilise jamais UDP." },
  { section: "mountd", key: "manage-gids", label: "manage-gids", type: "bool", default: "n", help: "Le serveur résout lui-même les groupes (contourne la limite de 16 groupes d'AUTH_SYS)." },
  { section: "gssd", key: "use-gss-proxy", label: "gss-proxy", type: "bool", default: "n", help: "Kerberos via gss-proxy (sec=krb5*)." },
];

export function nfsConfBool(v: string | undefined, fallback = false): boolean {
  if (v === undefined) return fallback;
  const s = v.trim().toLowerCase();
  if (["y", "yes", "true", "t", "on", "1"].includes(s)) return true;
  if (["n", "no", "false", "f", "off", "0"].includes(s)) return false;
  return fallback;
}

interface NfsConfLine {
  raw: string;
  section: string;
  key?: string;
  value?: string;
  commented?: boolean;
}

function scan(text: string): NfsConfLine[] {
  let section = "";
  return text.replace(/\r\n?/g, "\n").split("\n").map((raw) => {
    const t = raw.trim();
    const sec = /^\[\s*([^\]]+?)\s*\]/.exec(t);
    if (sec) {
      section = sec[1]!.toLowerCase();
      return { raw, section };
    }
    const kv = /^([#;]\s*)?([A-Za-z0-9._-]+)\s*=\s*(.*?)\s*$/.exec(t);
    if (kv && section) {
      return { raw, section, key: kv[2]!.toLowerCase(), value: kv[3]!.replace(/\s+#.*$/, ""), commented: !!kv[1] };
    }
    return { raw, section };
  });
}

/** Valeur effective d'une clé (la dernière occurrence non commentée gagne). */
export function getNfsConf(text: string, section: string, key: string): string | undefined {
  let found: string | undefined;
  for (const l of scan(text)) {
    if (l.section === section.toLowerCase() && l.key === key.toLowerCase() && !l.commented) found = l.value;
  }
  return found;
}

/**
 * Fixe une clé en préservant les commentaires : remplace la dernière
 * occurrence active, sinon décommente un exemple « # clé=… » de la section,
 * sinon ajoute la clé en fin de section (en créant la section au besoin).
 * value === undefined commente la clé (retour au défaut).
 */
export function setNfsConf(text: string, section: string, key: string, value: string | undefined): string {
  const lines = scan(text);
  const sec = section.toLowerCase();
  const k = key.toLowerCase();
  const out = lines.map((l) => l.raw);
  const active = lines.map((l, i) => ({ l, i })).filter(({ l }) => l.section === sec && l.key === k && !l.commented);
  if (value === undefined) {
    for (const { i } of active) out[i] = `# ${lines[i]!.raw.trim()}`;
    return out.join("\n");
  }
  const line = `${key}=${value}`;
  if (active.length) {
    const last = active[active.length - 1]!.i;
    out[last] = line;
    for (const { i } of active.slice(0, -1)) out[i] = `# ${lines[i]!.raw.trim()}`;
    return out.join("\n");
  }
  const example = lines.findIndex((l) => l.section === sec && l.key === k && l.commented);
  if (example >= 0) {
    out[example] = line;
    return out.join("\n");
  }
  const secIdx = lines.findIndex((l) => !l.key && l.section === sec && /^\s*\[/.test(l.raw));
  if (secIdx < 0) {
    const sep = out.length && out[out.length - 1]!.trim() !== "" ? [""] : [];
    return [...out, ...sep, `[${section}]`, line, ""].join("\n");
  }
  // fin de la section : dernière ligne appartenant à la section
  let end = secIdx;
  for (let i = secIdx + 1; i < lines.length; i++) {
    if (lines[i]!.section !== sec) break;
    if (lines[i]!.raw.trim() !== "") end = i;
  }
  out.splice(end + 1, 0, line);
  return out.join("\n");
}

/** Préréglage « NFSv4.1 seulement » (4.2 optionnelle). */
export function applyV41OnlyPreset(text: string, keepV42: boolean): string {
  let t = text;
  t = setNfsConf(t, "nfsd", "vers3", "n");
  t = setNfsConf(t, "nfsd", "vers4", "y");
  t = setNfsConf(t, "nfsd", "vers4.0", "n");
  t = setNfsConf(t, "nfsd", "vers4.1", "y");
  t = setNfsConf(t, "nfsd", "vers4.2", keepV42 ? "y" : "n");
  t = setNfsConf(t, "nfsd", "udp", "n");
  return t;
}

export interface NfsVersions {
  v3: boolean | undefined;
  v40: boolean | undefined;
  v41: boolean | undefined;
  v42: boolean | undefined;
}

/** Interprète /proc/fs/nfsd/versions, ex. « -3 +4 -4.0 +4.1 +4.2 ». */
export function parseProcVersions(text: string): NfsVersions {
  const r: NfsVersions = { v3: undefined, v40: undefined, v41: undefined, v42: undefined };
  for (const tok of text.trim().split(/\s+/)) {
    const m = /^([+-])(\d)(?:\.(\d))?$/.exec(tok);
    if (!m) continue;
    const on = m[1] === "+";
    if (m[2] === "3") r.v3 = on;
    if (m[2] === "4" && m[3] === "0") r.v40 = on;
    if (m[2] === "4" && m[3] === "1") r.v41 = on;
    if (m[2] === "4" && m[3] === "2") r.v42 = on;
  }
  return r;
}

/** Versions configurées dans nfs.conf (avec les défauts de nfs-utils). */
export function configuredVersions(text: string): NfsVersions {
  const b = (k: string) => nfsConfBool(getNfsConf(text, "nfsd", k), true);
  const v4 = b("vers4");
  return { v3: b("vers3"), v40: v4 && b("vers4.0"), v41: v4 && b("vers4.1"), v42: v4 && b("vers4.2") };
}

// ------------------------------------------------------------------ constats

export type FindingLevel = "info" | "warning" | "danger";

export interface Finding {
  level: FindingLevel;
  title: string;
  detail: string;
  fix?: string;
  ref?: string;
}

export interface ServerState {
  nfsConf: string;
  procVersions?: string;
  idmapdDomain?: string;
  dnsDomain?: string;
  disableIdmapping?: boolean;
  /** contenu de /etc/exports.d/zfs.exports (exports générés par sharenfs) */
  zfsExports?: string;
}

export function analyzeServer(state: ServerState, exports: NFSExport[]): Finding[] {
  const f: Finding[] = [];
  const conf = configuredVersions(state.nfsConf);
  const live = state.procVersions ? parseProcVersions(state.procVersions) : undefined;

  if (!conf.v41) f.push({ level: "danger", title: "NFSv4.1 désactivé dans nfs.conf", detail: "vers4 ou vers4.1 vaut « n ».", fix: "Appliquer le préréglage « NFSv4.1 seulement »." });
  if (conf.v3) f.push({ level: "warning", title: "NFSv3 actif", detail: "NFSv3 exige rpcbind (111) et mountd (20048), sans sessions ni idmapping, et la sécurité AUTH_SYS se fait par hôte.", fix: "vers3=n si aucun client NFSv3 ; inutile pour NFSv4.1." });
  if (conf.v40) f.push({ level: "info", title: "NFSv4.0 actif", detail: "Les clients récents négocient 4.1 / 4.2 ; 4.0 n'a ni sessions ni reprise « exactly once ».", fix: "vers4.0=n pour forcer 4.1+." });
  if (live) {
    const diff = (["v3", "v40", "v41", "v42"] as const).filter((k) => live[k] !== undefined && live[k] !== conf[k]);
    if (diff.length) f.push({ level: "warning", title: "État réel différent de nfs.conf", detail: `Le noyau sert : ${state.procVersions!.trim()}. nfs.conf n'est appliqué qu'au démarrage de nfsd.`, fix: "systemctl restart nfs-server", ref: "fs/nfsd/nfsctl.c write_versions" });
  }

  const secs = new Set<string>();
  for (const e of exports) for (const o of allOptionSets(e)) secs.add(optionValue(o, "sec") ?? "sys");
  const sysOnly = [...secs].every((s) => s.split(":").every((x) => x === "sys"));
  if (state.disableIdmapping !== false && sysOnly) {
    f.push({ level: "info", title: "Propriétaires transmis en UID / GID numériques", detail: "Avec sec=sys, knfsd envoie des identifiants numériques (nfs4_disable_idmapping=Y, défaut). Les UID / GID doivent être identiques sur le serveur et les clients (même annuaire ou mêmes comptes).", ref: "fs/nfsd/nfs4idmap.c encode_name_from_id" });
  }
  if (state.disableIdmapping === false || !sysOnly) {
    if (!state.idmapdDomain) f.push({ level: "warning", title: "Domain absent de /etc/idmapd.conf", detail: "Le domaine NFSv4 par défaut est le domaine DNS de la machine ; un écart avec les clients fait apparaître « nobody ».", fix: "Fixer Domain = <votre domaine> sur le serveur et tous les clients." });
    else if (state.dnsDomain && state.idmapdDomain.toLowerCase() !== state.dnsDomain.toLowerCase()) f.push({ level: "info", title: "Domain idmapd ≠ domaine DNS", detail: `idmapd : ${state.idmapdDomain}, DNS : ${state.dnsDomain}. Correct si c'est voulu, mais tous les clients doivent utiliser ${state.idmapdDomain}.` });
  }
  if (state.zfsExports?.trim()) {
    f.push({ level: "warning", title: "Exports générés par ZFS (sharenfs)", detail: "/etc/exports.d/zfs.exports existe : des datasets ont la propriété sharenfs. Ces exports échappent au plugin et peuvent doubler ceux-ci.", fix: "zfs set sharenfs=off <dataset> pour gérer les exports ici, ou ne pas exporter le même chemin deux fois." });
  }
  f.push({ level: "info", title: "Pare-feu", detail: conf.v3 ? "NFSv3 actif : 2049/tcp + rpcbind 111 + mountd 20048 (+ statd / lockd)." : "NFSv4.1 seul : uniquement 2049/tcp (rpcbind et mountd inutiles pour les clients).", fix: conf.v3 ? undefined : "firewall-cmd --permanent --add-service=nfs && firewall-cmd --reload" + (nfsConfBool(getNfsConf(state.nfsConf, "nfsd", "rdma")) ? " ; RDMA : --add-port=20049/tcp" : "") });
  return f;
}

// ------------------------------------------------------------------ options d'export

export function splitOptions(opts: string): string[] {
  return opts.split(",").map((s) => s.trim()).filter(Boolean);
}

export function optionValue(opts: string[], key: string): string | undefined {
  let v: string | undefined;
  for (const o of opts) if (o.startsWith(key + "=")) v = o.slice(key.length + 1);
  return v;
}

const has = (opts: string[], k: string) => opts.includes(k);

/** Ensembles d'options effectifs par client (options par défaut « -… » puis options du client). */
export function allOptionSets(e: NFSExport): string[][] {
  const def = splitOptions(e.defaultClientSettings);
  if (!e.clients.length) return [def];
  return e.clients.map((c) => [...def, ...splitOptions(c.settings)]);
}

export function analyzeExportV41(e: NFSExport, isZfs = true): Finding[] {
  const f: Finding[] = [];
  const sets = e.clients.length ? e.clients.map((c) => ({ host: c.host, opts: [...splitOptions(e.defaultClientSettings), ...splitOptions(c.settings)] })) : [{ host: "(tous)", opts: splitOptions(e.defaultClientSettings) }];
  const def = splitOptions(e.defaultClientSettings);
  const anyFsid = optionValue(def, "fsid") ?? sets.map((s) => optionValue(s.opts, "fsid")).find(Boolean);
  if (!anyFsid) f.push({ level: isZfs ? "warning" : "info", title: "Pas de fsid explicite", detail: "Sans fsid, knfsd dérive l'identifiant du système de fichiers ; sur ZFS il peut changer après import du pool ou bascule, et les clients voient « stale file handle ».", fix: "Ajouter fsid=<uuid> (le plugin en génère un pour les nouveaux exports)." });
  if (anyFsid === "0" || anyFsid === "root") f.push({ level: "info", title: "fsid=0 (racine NFSv4)", detail: "Sous Linux, la pseudo-racine NFSv4 est construite automatiquement ; fsid=0 n'est utile que pour un ancien schéma de montage." });
  for (const s of sets) {
    const o = s.opts;
    const who = `client ${s.host}`;
    if (has(o, "no_acl")) f.push({ level: "info", title: `no_acl (${who})`, detail: "Le noyau ne lit pas NFSEXP_NOACL : l'option est sans effet sur knfsd ; les ACL POSIX restent traduites en ACL NFSv4.", ref: "include/uapi/linux/nfsd/export.h NFSEXP_NOACL" });
    const sec = optionValue(o, "sec") ?? "sys";
    if (sec.split(":").every((x) => x === "sys") && (s.host === "*" || /\/(0|[0-8])$/.test(s.host))) f.push({ level: "warning", title: `sec=sys ouvert largement (${who})`, detail: "AUTH_SYS fait confiance à l'UID annoncé par le client : toute machine du réseau autorisé peut se faire passer pour n'importe quel utilisateur.", fix: "Restreindre l'hôte (IP / sous-réseau du VLAN de stockage) ou passer à sec=krb5p." });
    if (has(o, "no_root_squash")) f.push({ level: "warning", title: `no_root_squash (${who})`, detail: "root du client = root sur le dataset.", fix: "Garder root_squash sauf pour une machine d'administration." });
    if (has(o, "async")) f.push({ level: "warning", title: `async (${who})`, detail: "Le serveur acquitte les écritures avant qu'elles soient sur disque : perte silencieuse possible en cas de coupure.", fix: "sync (ZFS + SLOG gère bien les écritures synchrones)." });
    if (!has(o, "no_subtree_check") && !has(o, "subtree_check")) f.push({ level: "info", title: `subtree_check implicite ? (${who})`, detail: "nfs-utils récents utilisent no_subtree_check par défaut ; le préciser évite toute ambiguïté.", fix: "Ajouter no_subtree_check." });
    if (isZfs && !has(o, "crossmnt") && !has(o, "nohide")) f.push({ level: "info", title: `Datasets enfants masqués (${who})`, detail: "Sans crossmnt, un dataset ZFS enfant apparaît comme un dossier vide côté client.", fix: "Ajouter crossmnt (ou exporter chaque dataset)." });
    if (has(o, "all_squash") && !optionValue(o, "anonuid")) f.push({ level: "info", title: `all_squash sans anonuid (${who})`, detail: "Tous les accès deviennent nobody (65534).", fix: "Préciser anonuid= / anongid=." });
    if (has(o, "pnfs")) f.push({ level: "warning", title: `pnfs (${who})`, detail: "Les layouts pNFS de knfsd ciblent des blocs / SCSI partagés, pas ZFS.", fix: "Retirer pnfs." });
    if (has(o, "security_label")) f.push({ level: "info", title: `security_label (${who})`, detail: "Étiquettes SELinux : exige NFSv4.2 côté serveur et client." });
    if (has(o, "insecure")) f.push({ level: "info", title: `insecure (${who})`, detail: "Accepte les ports source > 1024 (utile pour certains clients macOS / conteneurs)." });
  }
  return f;
}
