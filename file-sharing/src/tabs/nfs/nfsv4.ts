/**
 * NFSv3 + NFSv4.1 (et NFS sur RDMA) : lecture / édition de /etc/nfs.conf,
 * analyse de l'état réel du serveur (/proc/fs/nfsd/versions, portlist,
 * idmapping, RDMA) et des options d'export.
 *
 * Cible : NFSv3 ET NFSv4.1 actifs sur tous les exports (les versions sont
 * globales au serveur, voir plus bas), avec NFS/RDMA possible.
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
 *
 * Vérifié dans le noyau (7.4-rc et v6.12, identiques sur ces points) :
 *  - versions : fs/nfsd/nfssvc.c nfsd_vers() → nn->nfsd_versions[] par espace de
 *    noms réseau ; aucun drapeau de version par export (NFSEXP_*). Un client
 *    autorisé sur un export peut donc le monter dans toute version active.
 *  - traversée des datasets enfants : fs/nfsd/vfs.c nfsd_cross_mnt traverse pour
 *    un client v4, ou si l'export parent a crossmnt, ou si l'enfant a nohide ;
 *    l'enfant doit dans tous les cas être connu de mountd (export explicite ou
 *    synthétisé par crossmnt). Côté client, seul un client Linux suit le
 *    changement de fsid en v3 ; ESXi, macOS, Windows ne le font pas.
 *  - ACL v3 : programme NFSACL 100227 (fs/nfsd/nfs3acl.c, CONFIG_NFSD_V3_ACL),
 *    ACL POSIX transmises telles quelles, NFS_ACL_MAX_ENTRIES = 1024
 *    (include/linux/nfsacl.h).
 *  - NLM : fs/lockd/svclock.c nlmsvc_lock → vfs_lock_file (verrous POSIX).
 *  - sec=krb5* : contrôlé pour toutes les versions par check_nfsd_access
 *    (fs/nfsd/export.c), donc valable aussi en v3 (rpc.gssd / gss-proxy).
 *  - RDMA : transport « rdma » (net/sunrpc/xprtrdma/svc_rdma_transport.c
 *    svc_rdma_class), ajouté via /proc/fs/nfsd/portlist (fs/nfsd/nfsctl.c
 *    __write_ports_addxprt) ; côté client, proto=rdma prend le port 20049 par
 *    défaut (fs/nfs/fs_context.c NFS_RDMA_PORT) et nconnect reste accepté avec
 *    RDMA (fs/nfs/nfs4client.c).
 *  - ksmbd SMB Direct (fs/smb/server/transport_rdma.c) : depuis cb097b3d
 *    (« set 445 port to smbdirect port by default », bien avant 6.12), un seul
 *    port d'écoute RDMA : 445 (InfiniBand / RoCE), ou 5445 pour tous dès qu'un
 *    RNIC iWARP est présent. Les noyaux qui ont le correctif 214220e7
 *    (Metzmacher, rdma_restrict_node_type) écoutent sur les deux : 445 pour
 *    IB / RoCE et 5445 pour iWARP
 *    (fs/smb/server/transport_rdma.c) : aucun conflit avec NFS/RDMA 20049.
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
  { section: "nfsd", key: "vers3", label: "NFSv3", type: "bool", default: "y", help: "Exige rpcbind (111), statd et lockd, et l'écoute réseau de mountd : fixez leurs ports ci-dessous pour le pare-feu. (rpc.mountd tourne de toute façon, même en v4 seul, pour les upcalls nfsd.export / auth.unix.ip.)" },
  { section: "nfsd", key: "vers4", label: "NFSv4 (toutes versions mineures)", type: "bool", default: "y", help: "Interrupteur global de NFSv4." },
  { section: "nfsd", key: "vers4.0", label: "NFSv4.0", type: "bool", default: "y", help: "Pas de sessions ni de « exactly once » : préférez 4.1." },
  { section: "nfsd", key: "vers4.1", label: "NFSv4.1", type: "bool", default: "y", help: "Sessions, trunking de session (multi-chemin), reprise fiable." },
  { section: "nfsd", key: "vers4.2", label: "NFSv4.2", type: "bool", default: "y", help: "Copie côté serveur, fichiers épars, xattrs utilisateur (RFC 8276), étiquettes de sécurité." },
  { section: "nfsd", key: "threads", label: "Threads nfsd", type: "int", default: "(voir /proc/fs/nfsd/threads)", help: "Nombre de threads serveur (16 à 64 pour du 10/25 Gb/s). rpc.nfsd(8) indique 8 par défaut ; la valeur réelle est lue dans /proc/fs/nfsd/threads." },
  { section: "nfsd", key: "grace-time", label: "Délai de grâce (s)", type: "int", default: "90", help: "Fenêtre de reprise des verrous / ouvertures après redémarrage." },
  { section: "nfsd", key: "lease-time", label: "Durée de bail NFSv4 (s)", type: "int", default: "90", help: "Durée de vie de l'état client sans renouvellement." },
  { section: "nfsd", key: "rdma", label: "NFS sur RDMA", type: "bool", default: "n", help: "Transport RDMA (svcrdma, module rpcrdma) : iWARP ou RoCE (ex. QL41112 en NPAR). Valable pour v3 et v4.1 ; mountd / NLM restent en TCP / UDP." },
  { section: "nfsd", key: "rdma-port", label: "Port RDMA", type: "int", default: "20049", help: "Port NFS/RDMA (défaut des clients avec proto=rdma)." },
  { section: "nfsd", key: "udp", label: "UDP", type: "bool", default: "n", help: "NFSv4 n'utilise jamais UDP." },
  { section: "mountd", key: "port", label: "Port mountd", type: "int", default: "(dynamique)", help: "Requis en NFSv3 (montage) : à fixer (ex. 20048) pour le pare-feu. Inutile à ouvrir en v4 seul, mais mountd doit tourner." },
  { section: "statd", key: "port", label: "Port statd", type: "int", default: "(dynamique)", help: "NFSv3 (NSM) : à fixer (ex. 662)." },
  { section: "statd", key: "outgoing-port", label: "Port sortant statd", type: "int", default: "(dynamique)", help: "Port source des notifications statd (ex. 2020)." },
  { section: "lockd", key: "port", label: "Port lockd TCP", type: "int", default: "(dynamique)", help: "NFSv3 (NLM) : à fixer (ex. 32803)." },
  { section: "lockd", key: "udp-port", label: "Port lockd UDP", type: "int", default: "(dynamique)", help: "NFSv3 (NLM) en UDP (ex. 32769)." },
  { section: "mountd", key: "manage-gids", label: "manage-gids", type: "bool", default: "n", help: "Le serveur résout lui-même les groupes (contourne la limite de 16 groupes d'AUTH_SYS)." },
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
      let val = kv[3]!.replace(/\s*[#;].*$/, "").trim();
      if (/^".*"$/.test(kv[3]!)) val = kv[3]!.slice(1, -1);
      return { raw, section, key: kv[2]!.toLowerCase(), value: val, commented: !!kv[1] };
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
  // fin de la section : dernière ligne clé-valeur appartenant à la section (sans déborder sur les commentaires de la section suivante)
  let end = secIdx;
  for (let i = secIdx + 1; i < lines.length; i++) {
    if (lines[i]!.section !== sec) break;
    if (lines[i]!.key) end = i;
  }
  out.splice(end + 1, 0, line);
  return out.join("\n");
}

/** Ports fixes conventionnels (ceux de la documentation Red Hat) pour NFSv3. */
export const V3_PORTS = { mountd: "20048", statd: "662", statdOutgoing: "2020", lockdTcp: "32803", lockdUdp: "32769" };

/**
 * Préréglage recommandé « NFSv3 + NFSv4.1 » : v3 et v4.1 actifs (4.0 coupé,
 * 4.2 au choix), ports v3 fixes, RDMA en option.
 */
export function applyV3V41Preset(text: string, keepV42: boolean, opts: { fixPorts?: boolean; rdma?: boolean } = {}): string {
  let t = setVersions(text, { v3: true, v40: false, v41: true, v42: keepV42 }).text;
  t = setNfsConf(t, "nfsd", "udp", "n");
  if (opts.fixPorts ?? true) {
    if (!getNfsConf(t, "mountd", "port")) t = setNfsConf(t, "mountd", "port", V3_PORTS.mountd);
    if (!getNfsConf(t, "statd", "port")) t = setNfsConf(t, "statd", "port", V3_PORTS.statd);
    if (!getNfsConf(t, "statd", "outgoing-port")) t = setNfsConf(t, "statd", "outgoing-port", V3_PORTS.statdOutgoing);
    if (!getNfsConf(t, "lockd", "port")) t = setNfsConf(t, "lockd", "port", V3_PORTS.lockdTcp);
    if (!getNfsConf(t, "lockd", "udp-port")) t = setNfsConf(t, "lockd", "udp-port", V3_PORTS.lockdUdp);
  }
  if (opts.rdma !== undefined) t = applyRdma(t, opts.rdma);
  return t;
}

export function applyRdma(text: string, on: boolean, port = "20049"): string {
  let t = setNfsConf(text, "nfsd", "rdma", on ? "y" : "n");
  if (on && !getNfsConf(t, "nfsd", "rdma-port")) t = setNfsConf(t, "nfsd", "rdma-port", port);
  return t;
}

// ------------------------------------------------------------------ interrupteurs de version

export type NfsVersionKey = "v3" | "v40" | "v41" | "v42";

export const NFS_VERSION_INFO: { key: NfsVersionKey; conf: string; label: string; brings: string; clients: string }[] = [
  { key: "v3", conf: "vers3", label: "NFSv3", brings: "Sans état côté serveur, ACL POSIX natives (NFSACL), verrous NLM ; exige rpcbind, mountd, statd, lockd.", clients: "ESXi (NFS 3), Proxmox VE (v3 par défaut), macOS (mount_nfs par défaut en v3), FreeBSD / BSD, appliances, sauvegardes." },
  { key: "v40", conf: "vers4.0", label: "NFSv4.0", brings: "Un seul port (2049), délégations, idmapping ; pas de sessions.", clients: "Clients anciens (Linux < 2.6.38, macOS avec -o vers=4 sans mineure, anciens BSD / Solaris)." },
  { key: "v41", conf: "vers4.1", label: "NFSv4.1", brings: "Sessions et reprise « exactly once », trunking de session (multi-chemin), pNFS.", clients: "Linux (≥ 2.6.38), Proxmox VE (vers=4.1), ESXi 6.0+ (NFS 4.1), Windows (client NFSv4.1 natif), macOS (mount_nfs -o vers=4.1, 10.15+ / Sequoia 15), FreeBSD." },
  { key: "v42", conf: "vers4.2", label: "NFSv4.2", brings: "Copie côté serveur, fichiers épars (SEEK_HOLE, ALLOCATE), xattrs utilisateur (RFC 8276), étiquettes SELinux.", clients: "Linux (≥ 4.2, défaut de mount.nfs récent), FreeBSD 13+ (minorversion=2). Non supporté par ESXi, macOS ni Windows." },
];

/**
 * Écrit les interrupteurs de version dans nfs.conf. Chaque version mineure est
 * explicite et vers4 suit (y si au moins une mineure) : le noyau traite les
 * mineures indépendamment (fs/nfsd/nfssvc.c nfsd_minorversion) et coupe v4
 * quand toutes les mineures sont coupées (nfsd_adjust_nfsd_versions4).
 * Refuse de tout couper : le noyau réactiverait alors TOUTES les versions
 * (fs/nfsd/nfsctl.c __write_versions → nfsd_reset_versions).
 */
export function setVersions(text: string, v: Record<NfsVersionKey, boolean>): { ok: boolean; text: string; error?: string } {
  if (!v.v3 && !v.v40 && !v.v41 && !v.v42) {
    return { ok: false, text, error: "Impossible de tout désactiver : le noyau réactiverait toutes les versions (nfsd_reset_versions)." };
  }
  let t = text;
  const yn = (b: boolean) => (b ? "y" : "n");
  t = setNfsConf(t, "nfsd", "vers3", yn(v.v3));
  t = setNfsConf(t, "nfsd", "vers4", yn(v.v40 || v.v41 || v.v42));
  t = setNfsConf(t, "nfsd", "vers4.0", yn(v.v40));
  t = setNfsConf(t, "nfsd", "vers4.1", yn(v.v41));
  t = setNfsConf(t, "nfsd", "vers4.2", yn(v.v42));
  return { ok: true, text: t };
}

export interface VersionGuardContext {
  nfsConf: string;
  /** exports ZFS ayant des datasets enfants (importants pour v3) */
  hasExports?: boolean;
}

/** Garde-fous sur un jeu d'interrupteurs proposé. */
export function versionGuards(v: Record<NfsVersionKey, boolean>, ctx: VersionGuardContext): Finding[] {
  const f: Finding[] = [];
  if (!v.v3 && !v.v40 && !v.v41 && !v.v42) {
    f.push({ level: "danger", title: "Aucune version active", detail: "Refusé : le noyau réactiverait toutes les versions.", ref: "fs/nfsd/nfsctl.c __write_versions (nfsd_reset_versions)" });
    return f;
  }
  if (!v.v3) f.push({ level: "warning", title: "NFSv3 coupé", detail: "Cible NFSv3 + NFSv4.1 : les clients v3 (ESXi NFS 3, appliances, sauvegardes) ne monteront plus aucun export." });
  if (!v.v41) f.push({ level: "warning", title: "NFSv4.1 coupé", detail: v.v42 ? "NFSv4.2 reste actif (le noyau accepte 4.2 sans 4.1) ; les clients limités à 4.1 (ESXi, Windows) échoueront ou retomberont en v3." : "Plus de sessions ni de trunking ; les clients v4 retombent en 4.0 ou v3." });
  if (v.v42 && !v.v41) f.push({ level: "info", title: "4.2 sans 4.1", detail: "Accepté par le noyau (mineures indépendantes) mais inhabituel : un client « vers=4 » négocie la plus haute commune.", ref: "fs/nfsd/nfssvc.c nfsd_minorversion" });
  if (nfsConfBool(getNfsConf(ctx.nfsConf, "nfsd", "rdma"))) f.push({ level: "info", title: "RDMA indépendant des versions", detail: "Le transport RDMA sert toutes les versions actives (v3, 4.0, 4.1, 4.2) : couper une version ne coupe pas RDMA." });
  f.push({ level: "info", title: "Effet sur les performances", detail: "Couper des versions réduit la surface d'attaque et les négociations, mais le débit dépend surtout de RDMA, du nombre de threads nfsd, de rsize / wsize côté client, de sync / async et de la signature / du chiffrement (krb5i / krb5p)." });
  return f;
}

export function currentVersions(text: string): Record<NfsVersionKey, boolean> {
  const c = configuredVersions(text);
  return { v3: !!c.v3, v40: !!c.v40, v41: !!c.v41, v42: !!c.v42 };
}

/** Réglages NFS qui pèsent réellement sur le débit (groupe « Performances »). */
export const NFS_PERF_KEYS: { section: string; key: string }[] = [
  { section: "nfsd", key: "threads" },
  { section: "nfsd", key: "rdma" },
  { section: "nfsd", key: "rdma-port" },
];

export const NFS_CLIENT_PERF_TIPS = [
  "rsize=1048576,wsize=1048576 (1 Mio, maximum de knfsd) ; le client négocie à la baisse si besoin.",
  "nconnect=4 à 8 sur TCP 10/25 Gb/s (aussi accepté avec proto=rdma).",
  "hard (jamais soft pour des données) ; actimeo / noac seulement si cohérence stricte requise.",
  "Serveur : sync + SLOG ZFS plutôt que async ; threads nfsd 16 à 64.",
];

/** Préréglage « NFSv4.1 seulement » (4.2 optionnelle). */
export function applyV41OnlyPreset(text: string, keepV42: boolean): string {
  let t = setVersions(text, { v3: false, v40: false, v41: true, v42: keepV42 }).text;
  t = setNfsConf(t, "nfsd", "udp", "n");
  return t;
}

export interface NfsVersions {
  v3: boolean | undefined;
  v40: boolean | undefined;
  v41: boolean | undefined;
  v42: boolean | undefined;
}

/**
 * Interprète /proc/fs/nfsd/versions, ex. « -2 +3 +4 +4.1 +4.2 ».
 * Le noyau n'affiche jamais « +4.0 » : 4.0 est implicite dans « +4 » sauf
 * « -4.0 » ; « -4 » coupe toutes les mineures
 * (fs/nfsd/nfsctl.c nfsd_print_version_support).
 */
export function parseProcVersions(text: string): NfsVersions {
  const r: NfsVersions = { v3: undefined, v40: undefined, v41: undefined, v42: undefined };
  let v4: boolean | undefined;
  const minors: Record<string, boolean> = {};
  for (const tok of text.trim().split(/\s+/)) {
    const m = /^([+-])(\d)(?:\.(\d))?$/.exec(tok);
    if (!m) continue;
    const on = m[1] === "+";
    if (m[2] === "3" && m[3] === undefined) r.v3 = on;
    if (m[2] === "4" && m[3] === undefined) v4 = on;
    if (m[2] === "4" && m[3] !== undefined) minors[m[3]] = on;
  }
  if (v4 !== undefined) {
    r.v40 = v4 && minors["0"] !== false;
    r.v41 = v4 && minors["1"] === true;
    r.v42 = v4 && minors["2"] === true;
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

export interface RdmaLink {
  dev: string;
  port: string;
  state: string;
  netdev: string;
}

export interface ServerState {
  nfsConf: string;
  procVersions?: string;
  /** /proc/fs/nfsd/portlist (ex. « tcp 2049\nrdma 20049 ») */
  portlist?: string;
  /** module rpcrdma chargé */
  rpcrdmaLoaded?: boolean;
  /** CONFIG_SUNRPC_XPRT_RDMA du noyau */
  xprtRdmaConfig?: "y" | "m" | "n" | "?";
  rdmaLinks?: RdmaLink[];
  /** type de nœud RDMA par périphérique : « iwarp », « ib-roce » */
  rdmaNodeTypes?: Record<string, "iwarp" | "ib-roce" | "unknown">;
  /** services systemd : nom → actif */
  services?: Record<string, boolean>;
  /** /etc/nfs.conf.d/*.conf (lus après nfs.conf, prioritaires) */
  nfsConfD?: { file: string; text: string }[];
  /** /proc/fs/nfsd/threads */
  liveThreads?: number;
  /** /proc/sys/fs/leases-enable */
  leasesEnable?: boolean;
  idmapdDomain?: string;
  dnsDomain?: string;
  disableIdmapping?: boolean;
  /** contenu de /etc/exports.d/zfs.exports (exports générés par sharenfs) */
  zfsExports?: string;
}

/** nfs.conf effectif : nfs.conf puis /etc/nfs.conf.d/*.conf (la dernière occurrence gagne). */
export function effectiveNfsConf(state: Pick<ServerState, "nfsConf" | "nfsConfD">): string {
  return [state.nfsConf, ...(state.nfsConfD ?? []).map((d) => d.text)].join("\n");
}

/** Clés de nfs.conf surchargées par un fichier de nfs.conf.d. */
export function overriddenKeys(state: Pick<ServerState, "nfsConf" | "nfsConfD">): { section: string; key: string; file: string; value: string }[] {
  const out: { section: string; key: string; file: string; value: string }[] = [];
  for (const d of state.nfsConfD ?? []) {
    for (const l of scan(d.text)) {
      if (!l.key || l.commented) continue;
      out.push({ section: l.section, key: l.key, file: d.file, value: l.value ?? "" });
    }
  }
  return out;
}

export function analyzeServer(state: ServerState, exports: NFSExport[]): Finding[] {
  const f: Finding[] = [];
  const conf = configuredVersions(effectiveNfsConf(state));
  const ov = overriddenKeys(state);
  if (ov.length) f.push({ level: "warning", title: "Réglages surchargés par /etc/nfs.conf.d", detail: ov.map((o) => `[${o.section}] ${o.key}=${o.value} (${o.file})`).join(" ; ") + ". Ces fichiers sont lus après nfs.conf et l'emportent : une modification faite ici dans nfs.conf peut rester sans effet.", fix: "Modifier ou retirer la clé dans le fichier de nfs.conf.d." });
  if (scan(state.nfsConf).some((l) => l.key === "include" && !l.commented)) f.push({ level: "info", title: "Directive include dans nfs.conf", detail: "nfs.conf inclut un autre fichier, non analysé ici : vérifiez qu'il ne redéfinit pas les versions ou les ports." });
  if (state.liveThreads !== undefined) f.push({ level: "info", title: `Threads nfsd : ${state.liveThreads}`, detail: "Valeur réelle (/proc/fs/nfsd/threads). 16 à 64 pour du 10/25 Gb/s ou RDMA." });
  const live = state.procVersions ? parseProcVersions(state.procVersions) : undefined;

  if (!conf.v41) f.push({ level: "danger", title: "NFSv4.1 désactivé dans nfs.conf", detail: "vers4 ou vers4.1 vaut « n ».", fix: "Appliquer le préréglage « NFSv3 + NFSv4.1 »." });
  if (!conf.v3) {
    f.push({ level: "warning", title: "NFSv3 désactivé", detail: "La cible est NFSv3 + NFSv4.1 sur tous les exports : les clients v3 sont refusés.", fix: "Préréglage « NFSv3 + NFSv4.1 » (ou garder « NFSv4.1 seulement » si aucun client v3)." });
  } else {
    f.push({ level: "info", title: "NFSv3 actif sur tous les exports", detail: "Les versions sont globales au serveur (fs/nfsd/nfssvc.c nfsd_vers, aucun drapeau de version par export) : tout client autorisé sur un export peut le monter en v3 comme en v4.1. Restreignez les clients de chaque export, ou utilisez sec=krb5* (valable aussi en v3).", ref: "fs/nfsd/nfssvc.c nfsd_vers ; fs/nfsd/export.c check_nfsd_access" });
    const ports: [string, string, string][] = [["mountd", "port", "mountd"], ["statd", "port", "statd"], ["statd", "outgoing-port", "statd (sortant)"], ["lockd", "port", "lockd TCP"], ["lockd", "udp-port", "lockd UDP"]];
    const eff = effectiveNfsConf(state);
    const missing = ports.filter(([sec, key]) => !getNfsConf(eff, sec, key)).map(([, , l]) => l);
    if (missing.length) f.push({ level: "warning", title: "Ports NFSv3 dynamiques", detail: `Sans port fixe, ${missing.join(", ")} change(nt) à chaque démarrage : impossible à ouvrir proprement au pare-feu.`, fix: `Préréglage « NFSv3 + NFSv4.1 » (mountd ${V3_PORTS.mountd}, statd ${V3_PORTS.statd}/${V3_PORTS.statdOutgoing}, lockd ${V3_PORTS.lockdTcp}/${V3_PORTS.lockdUdp}).` });
    if (state.services) {
      const down = ["rpcbind.socket", "nfs-mountd.service", "rpc-statd.service"].filter((s) => state.services![s] === false);
      if (down.length) f.push({ level: "warning", title: "Services NFSv3 arrêtés", detail: `${down.join(", ")} inactif(s) : montages v3 ou verrous NLM impossibles.`, fix: "systemctl enable --now rpcbind.socket nfs-mountd rpc-statd" });
    }
    f.push({ level: "info", title: "ACL en NFSv3", detail: "Les clients v3 lisent et écrivent les ACL POSIX telles quelles (getfacl / setfacl, protocole NFSACL 100227, 1024 entrées max.), alors que les clients v4.1 voient la traduction en ACL NFSv4 (nfs4_getfacl). Une ACL posée en v4 qui n'est pas représentable en POSIX est refusée ; vue depuis v3 elle reste toujours exacte.", ref: "fs/nfsd/nfs3acl.c ; include/linux/nfsacl.h NFS_ACL_MAX_ENTRIES ; fs/nfsd/nfs4acl.c" });
  }
  if (conf.v40) f.push({ level: "info", title: "NFSv4.0 actif", detail: "Les clients récents négocient 4.1 / 4.2 ; 4.0 n'a ni sessions ni reprise « exactly once ».", fix: "vers4.0=n pour forcer 4.1+." });
  if (live) {
    const diff = (["v3", "v40", "v41", "v42"] as const).filter((k) => live[k] !== undefined && live[k] !== conf[k]);
    if (diff.length) f.push({ level: "warning", title: "État réel différent de nfs.conf", detail: `Le noyau sert : ${state.procVersions!.trim()}. nfs.conf n'est appliqué qu'au démarrage de nfsd.`, fix: "systemctl restart nfs-server", ref: "fs/nfsd/nfsctl.c write_versions" });
  }

  const secs = new Set<string>();
  for (const e of exports) for (const o of allOptionSets(e)) secs.add(optionValue(o, "sec") ?? "sys");
  const sysOnly = [...secs].every((s) => s.split(":").every((x) => x === "sys"));
  if (conf.v3 && sysOnly && state.disableIdmapping === false) {
    f.push({ level: "warning", title: "Propriétaires différents entre v3 et v4.1", detail: "nfs4_disable_idmapping=N : les clients v4.1 reçoivent des noms user@domaine traduits par idmapd, les clients v3 des UID / GID numériques. Un compte absent d'un côté apparaît « nobody » en v4.1 mais avec son numéro en v3.", fix: "Remettre nfs4_disable_idmapping=Y (défaut) côté serveur et clients pour des UID numériques partout avec sec=sys.", ref: "fs/nfsd/nfs4idmap.c nfs4_disable_idmapping" });
  } else if (state.disableIdmapping !== false && sysOnly) {
    f.push({ level: "info", title: "Propriétaires transmis en UID / GID numériques", detail: `Avec sec=sys, knfsd envoie des identifiants numériques en v4.1 (nfs4_disable_idmapping=Y, défaut)${conf.v3 ? ", comme en v3 : les deux versions voient les mêmes propriétaires" : ""}. Les UID / GID doivent être identiques sur le serveur et les clients.`, ref: "fs/nfsd/nfs4idmap.c encode_name_from_id" });
  }
  if (state.disableIdmapping === false || !sysOnly) {
    if (!state.idmapdDomain) f.push({ level: "warning", title: "Domain absent de /etc/idmapd.conf", detail: "Le domaine NFSv4 par défaut est le domaine DNS de la machine ; un écart avec les clients fait apparaître « nobody ».", fix: "Fixer Domain = <votre domaine> sur le serveur et tous les clients." });
    else if (state.dnsDomain && state.idmapdDomain.toLowerCase() !== state.dnsDomain.toLowerCase()) f.push({ level: "info", title: "Domain idmapd ≠ domaine DNS", detail: `idmapd : ${state.idmapdDomain}, DNS : ${state.dnsDomain}. Correct si c'est voulu, mais tous les clients doivent utiliser ${state.idmapdDomain}.` });
  }
  if (state.zfsExports?.trim()) {
    f.push({ level: "warning", title: "Exports générés par ZFS (sharenfs)", detail: "/etc/exports.d/zfs.exports existe : des datasets ont la propriété sharenfs. Ces exports échappent au plugin et peuvent doubler ceux-ci.", fix: "zfs set sharenfs=off <dataset> pour gérer les exports ici, ou ne pas exporter le même chemin deux fois." });
  }
  if (!conf.v3) f.push({ level: "info", title: "mountd en NFSv4 seul", detail: "rpc.mountd doit continuer de tourner (upcalls nfsd.export / auth.unix.ip du noyau) ; seul son port réseau est inutile à ouvrir." });
  f.push(...analyzeRdma({ ...state, nfsConf: effectiveNfsConf(state) }));
  const effc = effectiveNfsConf(state);
  f.push({ level: "info", title: "Pare-feu", detail: firewallSummary(effc).join(" ; "), fix: firewallCommands(effc).join(" && ") });
  return f;
}

/** Ports à ouvrir selon nfs.conf. */
export function firewallPorts(nfsConf: string): { port: string; proto: "tcp" | "udp"; why: string }[] {
  const conf = configuredVersions(nfsConf);
  const out: { port: string; proto: "tcp" | "udp"; why: string }[] = [{ port: "2049", proto: "tcp", why: "nfsd" }];
  if (conf.v3) {
    out.push({ port: "111", proto: "tcp", why: "rpcbind" }, { port: "111", proto: "udp", why: "rpcbind" });
    const add = (sec: string, key: string, proto: "tcp" | "udp", why: string) => {
      const p = getNfsConf(nfsConf, sec, key);
      if (p) out.push({ port: p, proto, why });
    };
    add("mountd", "port", "tcp", "mountd");
    add("mountd", "port", "udp", "mountd");
    add("statd", "port", "tcp", "statd");
    add("statd", "port", "udp", "statd");
    add("lockd", "port", "tcp", "lockd");
    add("lockd", "udp-port", "udp", "lockd");
  }
  if (nfsConfBool(getNfsConf(nfsConf, "nfsd", "rdma"))) {
    out.push({ port: getNfsConf(nfsConf, "nfsd", "rdma-port") ?? "20049", proto: "tcp", why: "NFS/RDMA (iWARP : espace de ports TCP)" });
    out.push({ port: "4791", proto: "udp", why: "RoCEv2 (si RoCE)" });
  }
  return out;
}

export function firewallSummary(nfsConf: string): string[] {
  return firewallPorts(nfsConf).map((p) => `${p.port}/${p.proto} (${p.why})`);
}

export function firewallCommands(nfsConf: string): string[] {
  const conf = configuredVersions(nfsConf);
  const cmds = ["firewall-cmd --permanent --add-service=nfs"];
  if (conf.v3) cmds.push("firewall-cmd --permanent --add-service=rpc-bind");
  for (const p of firewallPorts(nfsConf)) {
    if (["2049", "111"].includes(p.port)) continue;
    cmds.push(`firewall-cmd --permanent --add-port=${p.port}/${p.proto}`);
  }
  cmds.push("firewall-cmd --reload");
  return cmds;
}

// ------------------------------------------------------------------ RDMA

/** /proc/fs/nfsd/portlist : une ligne « transport port » par écouteur. */
export function parsePortlist(text: string | undefined): { transport: string; port: string }[] {
  return (text ?? "").split("\n").map((l) => l.trim().split(/\s+/)).filter((p) => p.length >= 2 && p[0]).map(([transport, port]) => ({ transport: transport!, port: port! }));
}

export function analyzeRdma(state: ServerState): Finding[] {
  const f: Finding[] = [];
  const wanted = nfsConfBool(getNfsConf(state.nfsConf, "nfsd", "rdma"));
  const listeners = parsePortlist(state.portlist).filter((l) => l.transport.startsWith("rdma"));
  const links = state.rdmaLinks ?? [];
  const active = links.filter((l) => /active/i.test(l.state));
  if (!wanted) {
    if (active.length) f.push({ level: "info", title: "Liens RDMA disponibles, NFS/RDMA désactivé", detail: `${active.map((l) => `${l.dev}${l.netdev ? " (" + l.netdev + ")" : ""}`).join(", ")} actif(s). NFSv3 et NFSv4.1 peuvent utiliser RDMA.`, fix: "[nfsd] rdma=y, rdma-port=20049 puis systemctl restart nfs-server" });
    return f;
  }
  if (state.xprtRdmaConfig === "n") f.push({ level: "danger", title: "Noyau sans CONFIG_SUNRPC_XPRT_RDMA", detail: "Le transport RDMA de sunrpc n'est pas compilé : NFS/RDMA impossible avec ce noyau.", ref: "net/sunrpc/Kconfig SUNRPC_XPRT_RDMA" });
  if (state.rpcrdmaLoaded === false) f.push({ level: "warning", title: "Module rpcrdma non chargé", detail: "nfsd ne peut ajouter l'écouteur « rdma » qu'avec le module rpcrdma (svcrdma).", fix: "modprobe rpcrdma ; echo rpcrdma > /etc/modules-load.d/rpcrdma.conf" });
  if (!links.length) f.push({ level: "warning", title: "Aucun lien RDMA détecté", detail: "rdma link show ne liste rien : vérifiez que la partition NPAR passée à la VM a la personnalité RDMA et que le pilote (qedr pour la QL41112) est chargé.", fix: "modprobe qedr ; rdma link show ; ibv_devinfo" });
  else if (!active.length) f.push({ level: "warning", title: "Liens RDMA inactifs", detail: links.map((l) => `${l.dev}/${l.port} ${l.state}`).join(", ") });
  if (state.portlist !== undefined && !listeners.length) f.push({ level: "warning", title: "nfsd n'écoute pas en RDMA", detail: `rdma=y dans nfs.conf mais /proc/fs/nfsd/portlist ne contient pas de ligne « rdma » (${parsePortlist(state.portlist).map((l) => l.transport + " " + l.port).join(", ") || "vide"}).`, fix: "systemctl restart nfs-server (après modprobe rpcrdma) ; ou à chaud : echo 'rdma 20049' > /proc/fs/nfsd/portlist", ref: "fs/nfsd/nfsctl.c __write_ports_addxprt" });
  else if (listeners.length) f.push({ level: "info", title: "NFS/RDMA à l'écoute", detail: listeners.map((l) => `${l.transport} ${l.port}`).join(", ") + ". Valable pour NFSv3 et NFSv4.1 ; mountd, statd et lockd (v3) restent en TCP / UDP." });
  const types = Object.values(state.rdmaNodeTypes ?? {});
  if (types.includes("iwarp")) f.push({ level: "info", title: "iWARP", detail: "En iWARP, l'espace de ports RDMA est celui de TCP : 20049/tcp doit être libre et autorisé (ksmbd SMB Direct utilise 5445 en iWARP : pas de conflit)." });
  if (types.includes("ib-roce")) f.push({ level: "info", title: "RoCE / InfiniBand", detail: "En RoCEv2 le trafic passe par 4791/udp (traité par la carte) ; ksmbd SMB Direct écoute dans l'espace de ports RDMA sur 445 (ou sur 5445 si un RNIC iWARP est aussi présent, sauf noyaux avec le correctif 214220e7 qui écoutent sur les deux), sans conflit avec 20049. RoCE exige un réseau sans perte (PFC / ECN) sur le switch." });
  f.push({ level: "info", title: "Montage côté client", detail: "Linux : mount -t nfs -o vers=4.1,proto=rdma serveur:/chemin /mnt (port 20049 par défaut avec proto=rdma) ; NFSv3 : -o vers=3,proto=rdma. nconnect reste accepté avec RDMA (plusieurs connexions RDMA).", ref: "fs/nfs/fs_context.c NFS_RDMA_PORT ; fs/nfs/nfs4client.c nconnect" });
  return f;
}

/** Commandes de montage client pour un export. */
export function clientMountCommands(server: string, path: string, rdma: boolean): string[] {
  const t = `${server}:${path}`;
  const mnt = "/mnt/" + (path.split("/").filter(Boolean).pop() ?? "nfs");
  const out = [
    `mount -t nfs -o vers=4.1,hard ${t} ${mnt}`,
    `mount -t nfs -o vers=3,hard ${t} ${mnt}`,
  ];
  if (rdma) {
    out.push(`mount -t nfs -o vers=4.1,proto=rdma,port=20049,hard ${t} ${mnt}`);
    out.push(`mount -t nfs -o vers=3,proto=rdma,port=20049,hard ${t} ${mnt}`);
  }
  return out;
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
    if (isZfs && !has(o, "crossmnt") && !has(o, "nohide")) f.push({ level: "info", title: `Datasets enfants masqués (${who})`, detail: "Sans crossmnt, un dataset ZFS enfant apparaît comme un dossier vide côté client v3 (et v4 s'il n'est pas exporté).", fix: "Exporter chaque dataset enfant explicitement (voir constats NFSv3) ; crossmnt en complément pour v4." });
    if (has(o, "all_squash") && !optionValue(o, "anonuid")) f.push({ level: "info", title: `all_squash sans anonuid (${who})`, detail: "Tous les accès deviennent nobody (65534).", fix: "Préciser anonuid= / anongid=." });
    if (has(o, "pnfs")) f.push({ level: "warning", title: `pnfs (${who})`, detail: "Les layouts pNFS de knfsd ciblent des blocs / SCSI partagés, pas ZFS.", fix: "Retirer pnfs." });
    if (has(o, "security_label")) f.push({ level: "info", title: `security_label (${who})`, detail: "Étiquettes SELinux : exige NFSv4.2 côté serveur et client." });
    if (has(o, "insecure")) f.push({ level: "info", title: `insecure (${who})`, detail: "Accepte les ports source > 1024 (utile pour certains clients macOS / conteneurs)." });
  }
  return f;
}

// ------------------------------------------------------------------ NFSv3 : datasets enfants

export interface ZfsChild {
  name: string;
  mountpoint: string;
}

export interface V3ExportAnalysis {
  findings: Finding[];
  /** lignes /etc/exports proposées pour les datasets enfants non exportés */
  suggestedLines: string[];
}

const fallbackUuid = () => {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => {
    const r = (Math.random() * 16) | 0;
    return (ch === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
};

function normDir(p: string): string {
  return ("/" + p).replace(/\/+/g, "/").replace(/\/$/, "") || "/";
}

/**
 * Reconstruit une ligne d'export pour un autre chemin, fsid remplacé.
 * Sans client, exportfs exporte de toute façon à tous les hôtes : la ligne
 * l'écrit explicitement (« * »), et analyzeExportV3 le signale en avertissement.
 */
export function exportLineFor(e: NFSExport, path: string, fsid: string): string {
  const swapFsid = (opts: string) => {
    const list = splitOptions(opts).filter((o) => !o.startsWith("fsid="));
    return list;
  };
  const def = [...swapFsid(e.defaultClientSettings), `fsid=${fsid}`];
  const clients = e.clients.map((c) => {
    const o = swapFsid(c.settings);
    return o.length ? `${c.host}(${o.join(",")})` : c.host;
  });
  const p = /\s/.test(path) ? `"${path}"` : path;
  return [p, `-${def.join(",")}`, ...(clients.length ? [clients.join(" ")] : ["*"])].join(" ");
}

/**
 * NFSv3 sur un export ZFS : chaque dataset enfant monté sous le chemin doit
 * être exporté explicitement, avec son propre fsid, pour être visible des
 * clients v3 non Linux et ne pas dépendre de la synthèse crossmnt de mountd.
 */
export function analyzeExportV3(e: NFSExport, children: ZfsChild[], exportedPaths: string[], uuid: () => string = fallbackUuid): V3ExportAnalysis {
  const findings: Finding[] = [];
  const suggestedLines: string[] = [];
  const root = normDir(e.path);
  const exported = new Set(exportedPaths.filter((p) => p && p.startsWith("/")).map(normDir));
  const seen = new Set<string>();
  const under = children
    .filter((c) => c.mountpoint && c.mountpoint.startsWith("/"))
    .map((c) => ({ ...c, mountpoint: normDir(c.mountpoint) }))
    .filter((c) => {
      if (c.mountpoint === root || !c.mountpoint.startsWith(root === "/" ? "/" : root + "/")) return false;
      if (seen.has(c.mountpoint)) return false;
      seen.add(c.mountpoint);
      return true;
    });
  const missing = under.filter((c) => !exported.has(c.mountpoint));
  if (missing.length) {
    findings.push({
      level: "warning",
      title: `${missing.length} dataset(s) enfant(s) non exporté(s)`,
      detail: `${missing.map((c) => c.name).join(", ")} : un client v3 qui monte ${root} voit ces dossiers vides (ou, client Linux avec crossmnt, un système de fichiers synthétisé par mountd). Chaque dataset doit être un export à part, avec son fsid, monté séparément par les clients v3.`,
      fix: "Ajouter les lignes proposées ci-dessous (mêmes options, fsid unique).",
      ref: "fs/nfsd/vfs.c nfsd_cross_mnt",
    });
    for (const c of missing) suggestedLines.push(exportLineFor(e, c.mountpoint, uuid()));
  } else if (under.length) {
    findings.push({ level: "info", title: "Datasets enfants exportés", detail: `${under.length} dataset(s) enfant(s), tous exportés explicitement.` });
  }
  if (!e.clients.length) {
    findings.push({
      level: "warning",
      title: "Export sans client : ouvert à tous",
      detail: `${root} n'a aucun client défini : exportfs l'exporte alors à tous les hôtes joignables (« * »)${suggestedLines.length ? ", et les lignes proposées ci-dessous aussi" : ""}. Avec AUTH_SYS, n'importe quel hôte du réseau peut monter le partage et se présenter sous n'importe quel UID.`,
      fix: "Ajouter les clients autorisés (ex. 192.168.0.0/24 ou des hôtes nommés) à l'export, puis régénérer les lignes.",
      ref: "exports(5) ; exportfs : « No host name given … suggest *(…) to avoid warning »",
    });
  }
  const sets = allOptionSets(e);
  if (sets.some((o) => has(o, "async"))) findings.push({ level: "warning", title: "async avec NFSv3", detail: "En v3 le client compte sur COMMIT pour la durabilité ; async fait mentir le serveur et une coupure perd des écritures déjà « validées ».", fix: "sync (ZFS + SLOG)." });
  if (sets.some((o) => has(o, "no_root_squash"))) findings.push({ level: "warning", title: "no_root_squash avec NFSv3", detail: "En v3 AUTH_SYS, tout hôte autorisé qui se dit root devient root sur le dataset." });
  if (sets.some((o) => (optionValue(o, "sec") ?? "sys").split(":").includes("sys"))) findings.push({ level: "info", title: "AUTH_SYS en v3", detail: "Identités numériques annoncées par le client. sec=krb5i / krb5p fonctionne aussi en v3 (contrôle commun check_nfsd_access) si rpc.gssd / gss-proxy est configuré.", ref: "fs/nfsd/export.c check_nfsd_access" });
  return { findings, suggestedLines };
}
