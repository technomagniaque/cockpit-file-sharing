/**
 * Conversion d'une configuration Samba (smb.conf et / ou registre « net conf
 * list ») en ksmbd.conf, avec un rapport ligne par ligne.
 *
 * Principes :
 *  - les clés sont reconnues à la manière de Samba (casse et espaces ignorés,
 *    synonymes) puis écrites dans l'orthographe exacte attendue par ksmbd-tools ;
 *  - les valeurs sont normalisées (yes/no, enabled/auto/mandatory/disabled,
 *    SMB2_10…SMB3_11) car ksmbd-tools lit silencieusement toute valeur
 *    inconnue comme « non » / « disabled » ;
 *  - tout ce qui ne peut pas être traduit est signalé, jamais ignoré en silence ;
 *  - les options propres à ksmbd (RDMA, multicanal, interfaces, tailles d'E/S…)
 *    sont ajoutées à partir des options de conversion.
 */
import { cloneDoc, deleteValue, findSection, getValue, parseIni, serializeIni, setValue, type IniDocument, type IniSection } from "./ini";
import { findParam, normalizeKey } from "./ksmbd-params";
import type { NFSExport } from "@/tabs/nfs/data-types";
import { analyzeDualProtocol, overlappingExports } from "@/common/dual-protocol";

export type ReportAction = "kept" | "renamed" | "converted" | "dropped" | "added" | "warning" | "skipped-section";

export interface ReportLine {
  section: string;
  key?: string;
  from?: string;
  to?: string;
  action: ReportAction;
  note: string;
}

export interface ConversionOptions {
  /** RDMA / SMB Direct */
  rdma: {
    enable: boolean;
    /** interfaces RDMA (ex. partitions NPAR qedr) à écouter */
    interfaces: string[];
    /** taille max. des E/S SMB Direct */
    maxIoSize: string;
  };
  multichannel: boolean;
  /** interfaces supplémentaires (TCP) à écouter en plus des interfaces RDMA */
  extraInterfaces: string[];
  bindInterfacesOnly: boolean;
  durableHandles: boolean;
  leases: boolean;
  smb2MaxRead: string;
  smb2MaxWrite: string;
  smb2MaxTrans: string;
  smb2MaxCredits: string;
  maxIpConnections: string;
  signing: "keep" | "auto" | "mandatory" | "disabled";
  encryption: "keep" | "auto" | "mandatory" | "disabled";
  minProtocol: "keep" | "SMB2_10" | "SMB3_00" | "SMB3_02" | "SMB3_11";
  /** ajoute acl_xattr aux partages qui utilisaient des ACL Windows (acl_xattr / nt acl support) */
  keepWindowsAcls: boolean;
  /** convertit fruit:time machine en « time machine = yes » */
  timeMachine: boolean;
  /** retire de read list / write list les entrées absentes de valid users (ksmbd ne consulte pas valid users pour elles) */
  intersectWithValidUsers: boolean;
  /** partages à exclure de la conversion */
  excludeShares: string[];
  /** exports NFS existants : les partages au même chemin reçoivent les constats « double protocole » */
  nfsExports?: NFSExport[];
}

export const defaultConversionOptions = (): ConversionOptions => ({
  rdma: { enable: false, interfaces: [], maxIoSize: "8MB" },
  multichannel: true,
  extraInterfaces: [],
  bindInterfacesOnly: false,
  durableHandles: true,
  leases: true,
  smb2MaxRead: "",
  smb2MaxWrite: "",
  smb2MaxTrans: "",
  smb2MaxCredits: "",
  maxIpConnections: "",
  signing: "keep",
  encryption: "keep",
  minProtocol: "keep",
  keepWindowsAcls: true,
  timeMachine: true,
  intersectWithValidUsers: true,
  excludeShares: [],
});

export interface ConversionResult {
  doc: IniDocument;
  text: string;
  report: ReportLine[];
  /** commandes à exécuter côté serveur (comptes, firewall, modules) */
  followUp: string[];
  /** avertissements bloquants à lire avant d'appliquer */
  blocking: string[];
}

// ------------------------------------------------------------------ tables de correspondance

type Converter = (value: string, ctx: Ctx) => { key: string; value: string; note?: string; action?: ReportAction } | { drop: string } | null;

interface Ctx {
  section: string;
  blocking: string[];
  isGlobal: boolean;
  report: ReportLine[];
  out: IniSection;
  outGlobal: IniSection;
  opts: ConversionOptions;
  src: IniSection;
  srcGlobal: IniSection | undefined;
}

const SAMBA_TRUE = ["yes", "true", "1", "on", "enable", "enabled"];
const SAMBA_FALSE = ["no", "false", "0", "off", "disable", "disabled"];

function sambaBool(v: string): boolean | undefined {
  const s = v.trim().toLowerCase();
  if (SAMBA_TRUE.includes(s)) return true;
  if (SAMBA_FALSE.includes(s)) return false;
  return undefined;
}

const yn = (b: boolean) => (b ? "yes" : "no");

function boolTo(key: string, invert = false): Converter {
  return (v) => {
    const b = sambaBool(v);
    if (b === undefined) return { drop: `valeur booléenne illisible « ${v} »` };
    const value = yn(invert ? !b : b);
    const changed = value !== v.trim().toLowerCase();
    return { key, value, action: changed ? "converted" : undefined, note: changed ? `normalisé (« ${v} » serait mal lu par ksmbd-tools)` : undefined };
  };
}

const same = (key: string): Converter => (v) => ({ key, value: v.trim() });

function protocol(v: string): string | undefined {
  const s = v.trim().toUpperCase().replace(/-/g, "_");
  if (["NT1", "LANMAN1", "LANMAN2", "CORE", "COREPLUS"].includes(s)) return undefined;
  if (s === "SMB2" || s === "SMB2_02" || s === "SMB2_10" || s === "SMB2_22" || s === "SMB2_24") return "SMB2_10";
  if (s === "SMB3" || s === "SMB3_11" || s === "SMB3_10") return "SMB3_11";
  if (s === "SMB3_00") return "SMB3_00";
  if (s === "SMB3_02") return "SMB3_02";
  return undefined;
}

/** Table Samba (enum_smb_signing_vals / enum_smb_encryption_vals) → options ksmbd. */
function tristate(v: string): string | undefined {
  const s = v.trim().toLowerCase();
  if (["yes", "true", "on", "1", "enabled", "auto", "if_required", "desired", "default", "allowed"].includes(s)) return "auto";
  if (["required", "mandatory", "force", "forced", "enforced"].includes(s)) return "mandatory";
  if (["no", "false", "off", "0", "disabled"].includes(s)) return "disabled";
  return undefined;
}
const signingValue = tristate;
const encryptValue = tristate;

function userList(key: string): Converter {
  return (v, ctx) => {
    const notes: string[] = [];
    const out: string[] = [];
    // Samba accepte des entrées entre guillemets contenant des espaces ;
    // ksmbd découpe sur espaces, virgules et tabulations : non représentables.
    const tokens: string[] = [];
    const re = /"([^"]*)"|([^,\s]+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(v))) {
      if (m[1] !== undefined) {
        if (/[\s,]/.test(m[1])) notes.push(`« ${m[1]} » retiré (contient un espace ou une virgule : impossible à exprimer pour ksmbd)`);
        else if (m[1]) tokens.push(m[1]);
      } else tokens.push(m[2]!);
    }
    for (const e of tokens) {
      if (/^[+&]+/.test(e)) {
        out.push("@" + e.replace(/^[+&@]+/, ""));
        notes.push(`${e} → @${e.replace(/^[+&@]+/, "")}`);
      } else if (e.includes("\\") || e.includes("%")) {
        notes.push(`${e} retiré (domaine / substitution non gérés)`);
      } else {
        out.push(e);
      }
    }
    if (!out.length) return { drop: notes.join("; ") || "liste vide" };
    return { key, value: out.join(" "), action: notes.length ? "converted" : undefined, note: notes.length ? notes.join("; ") : undefined };
  };
}

/** hosts allow / hosts deny : clés jamais lues par ksmbd-tools (KSMBD_SHARE_CONF_IS_BROKEN). */
function hostDrop(key: string): Converter {
  return (v, ctx) => {
    const msg = `${key} = ${v} : ksmbd-tools ignore cette clé (KSMBD_SHARE_CONF_IS_BROKEN). LA RESTRICTION D'ACCÈS DISPARAÎT : filtrez au pare-feu (firewalld / nftables) ou limitez l'écoute avec interfaces + bind interfaces only.`;
    ctx.blocking.push(`[${ctx.section}] ${msg}`);
    return { drop: msg };
  };
}

function octal(key: string): Converter {
  return (v) => {
    const s = v.trim();
    if (!/^0?[0-7]{3,4}$/.test(s)) return { drop: `mode octal illisible « ${v} »` };
    return { key, value: s.padStart(4, "0") };
  };
}

/** Clés globales Samba → ksmbd (clé normalisée Samba). */
const GLOBAL_MAP: Record<string, Converter> = {
  workgroup: same("workgroup"),
  serverstring: same("server string"),
  netbiosname: same("netbios name"),
  interfaces: (v) => {
    const kept: string[] = [];
    const dropped: string[] = [];
    for (const raw of v.split(/[,\s]+/).filter(Boolean)) {
      const name = raw.split(";")[0]!;
      // une IP (v4 / v6, avec ou sans /masque) ou un réseau n'est pas un nom de netdev
      if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(name) || name.includes(":") || name.includes("/")) dropped.push(raw);
      else kept.push(name);
    }
    if (!kept.length) return { drop: `aucun nom d'interface (${dropped.join(", ")}) : ksmbd compare des noms de netdev, pas des adresses` };
    return { key: "interfaces", value: kept.join(" "), action: dropped.length ? "converted" : undefined,
      note: dropped.length ? `adresses retirées (ksmbd attend des noms d'interface) : ${dropped.join(", ")}` : undefined };
  },
  bindinterfacesonly: boolTo("bind interfaces only"),
  guestaccount: same("guest account"),
  maptoguest: (v) => {
    const s = v.trim().toLowerCase();
    if (s === "bad user") return { key: "map to guest", value: "bad user" };
    if (s === "never") return { key: "map to guest", value: "never" };
    return { key: "map to guest", value: "never", action: "converted", note: `« ${v} » non géré par ksmbd-tools → never` };
  },
  restrictanonymous: same("restrict anonymous"),
  serverminprotocol: (v) => {
    const p = protocol(v);
    return p ? { key: "server min protocol", value: p, action: p !== v.toUpperCase() ? "converted" : undefined } : { key: "server min protocol", value: "SMB2_10", action: "converted", note: `${v} (SMB1) n'existe pas dans ksmbd → SMB2_10` };
  },
  minprotocol: (v) => GLOBAL_MAP.serverminprotocol!(v, null as unknown as Ctx),
  servermaxprotocol: (v) => {
    const p = protocol(v);
    return p ? { key: "server max protocol", value: p, action: p !== v.toUpperCase() ? "converted" : undefined } : { drop: `dialecte « ${v} » inconnu de ksmbd` };
  },
  maxprotocol: (v) => GLOBAL_MAP.servermaxprotocol!(v, null as unknown as Ctx),
  protocol: (v) => GLOBAL_MAP.servermaxprotocol!(v, null as unknown as Ctx),
  serversigning: (v) => {
    const s = signingValue(v);
    return s ? { key: "server signing", value: s, action: s !== v.toLowerCase() ? "converted" : undefined, note: s !== v.toLowerCase() ? `« ${v} » → ${s}` : undefined } : { drop: `valeur de signature inconnue « ${v} »` };
  },
  serversmbencrypt: (v) => {
    const s = encryptValue(v);
    return s ? { key: "smb3 encryption", value: s, action: "converted", note: `server smb encrypt = ${v} → smb3 encryption = ${s}` } : { drop: `valeur inconnue « ${v} »` };
  },
  smbencrypt: (v, ctx) => GLOBAL_MAP.serversmbencrypt!(v, ctx),
  deadtime: same("deadtime"),
  maxopenfiles: same("max open files"),
  smb2maxread: same("smb2 max read"),
  smb2maxwrite: same("smb2 max write"),
  smb2maxtrans: same("smb2 max trans"),
  smb2maxcredits: same("smb2 max credits"),
  smb2leases: boolTo("smb2 leases"),
  durablehandles: boolTo("durable handles"),
  servermultichannelsupport: boolTo("server multi channel support"),
  smbports: (v) => {
    const ports = v.split(/[,\s]+/).filter(Boolean);
    const p = ports.includes("445") ? "445" : ports[0] ?? "445";
    return { key: "tcp port", value: p, action: "converted", note: ports.length > 1 ? `ksmbd n'écoute que sur un port : ${p} (139/NetBIOS n'existe pas)` : undefined };
  },
  kerberosmethod: (v) => {
    const s = v.trim().toLowerCase();
    if (["system keytab", "dedicated keytab", "secrets and keytab"].includes(s))
      return { key: "kerberos support", value: "yes", action: "converted", note: `kerberos method = ${v} : renseignez kerberos service name et kerberos keytab file` };
    return { drop: `kerberos method = ${v} n'utilise pas de keytab : Kerberos non activé` };
  },
  dedicatedkeytabfile: same("kerberos keytab file"),
  rootdirectory: same("root directory"),
  "fruit:model": same("aapl model"),
  widelinks: (v) => {
    const b = sambaBool(v);
    return b ? { key: "allow insecure wide links", value: "yes", action: "converted", note: "wide links (partage) → allow insecure wide links (global) : vaut pour tous les partages et exige follow symlinks" } : { drop: "wide links = no est le comportement par défaut" };
  },
};

/** Clés globales Samba sans équivalent : motif de l'abandon. */
const GLOBAL_DROP: Record<string, string> = {
  security: "pas de mode ADS / domaine : ksmbd authentifie avec sa propre base (ksmbd.adduser) ou Kerberos",
  realm: "pas de jonction AD (utilisez kerberos service name / keytab si besoin)",
  passdbbackend: "les hachages Samba ne sont pas migrables : recréez les comptes avec ksmbd.adduser",
  include: "les inclusions ne sont pas lues par ksmbd-tools : intégrez le contenu",
  configbackend: "pas de registre dans ksmbd",
  loglevel: "journalisation : ksmbd.control --debug=all|smb|auth|vfs|oplock|ipc|conn|rdma",
  logfile: "ksmbd journalise dans le journal du noyau (dmesg / journalctl -k)",
  maxlogsize: "sans objet",
  printing: "pas d'impression dans ksmbd", printcapname: "pas d'impression", loadprinters: "pas d'impression", disablespoolss: "pas d'impression",
  serverrole: "ksmbd est toujours un serveur autonome",
  winbindenumusers: "pas de winbind", winbindenumgroups: "pas de winbind", winbindusedefaultdomain: "pas de winbind", winbindrefreshtickets: "pas de winbind", winbindofflinelogon: "pas de winbind", templateshell: "pas de winbind", templatehomedir: "pas de winbind",
  usesendfile: "géré par le noyau", aioreadsize: "géré par le noyau", aiowritesize: "géré par le noyau", aiomaxthreads: "géré par le noyau",
  socketoptions: "géré par le noyau",
  obeypamrestrictions: "pas de PAM", unixpasswordsync: "pas de synchronisation de mot de passe", passwdprogram: "pas de synchronisation de mot de passe", passwdchat: "pas de synchronisation de mot de passe", pamtpasswordchange: "pas de PAM",
  usershareallowguests: "pas de partages utilisateur", usersharemaxshares: "pas de partages utilisateur", usersharepath: "pas de partages utilisateur", usershareownersonly: "pas de partages utilisateur",
  ntlmauth: "NTLMv2 seulement dans ksmbd",
  clientminprotocol: "paramètre client Samba", clientmaxprotocol: "paramètre client Samba", clientsigning: "paramètre client Samba", clientsmbencrypt: "paramètre client Samba", clientipcsigning: "paramètre client Samba",
  dnsproxy: "sans objet", wins: "pas de WINS", winssupport: "pas de WINS", winsserver: "pas de WINS", localmaster: "pas de navigation NetBIOS", preferredmaster: "pas de navigation NetBIOS", domainmaster: "pas de navigation NetBIOS", oslevel: "pas de navigation NetBIOS", disablenetbios: "ksmbd n'a pas de NetBIOS",
  mdnsname: "ksmbd ne publie pas en mDNS : configurez Avahi", multicastdnsregister: "ksmbd ne publie pas en mDNS : configurez Avahi",
  "fruit:aapl": "l'extension AAPL est intégrée à ksmbd (time machine / aapl model)",
  "fruit:nfs_aces": "sans objet", "fruit:metadata": "ksmbd stocke les métadonnées en flux (streams_xattr)", "fruit:encoding": "sans objet (catia absent)", "fruit:zero_file_id": "sans objet", "fruit:posix_rename": "sans objet", "fruit:veto_appledouble": "sans objet", "fruit:delete_empty_adfiles": "sans objet", "fruit:wipe_intentionally_left_blank_rfork": "sans objet",
  "fruit:advertise_fullsync": "intégré à « time machine = yes »",
};

/** Clés de partage Samba → ksmbd. */
const SHARE_MAP: Record<string, Converter> = {
  path: same("path"),
  comment: same("comment"),
  browseable: boolTo("browseable"),
  browsable: boolTo("browseable"),
  readonly: boolTo("read only"),
  writable: boolTo("read only", true),
  writeable: boolTo("read only", true),
  writeok: boolTo("read only", true),
  guestok: boolTo("guest ok"),
  public: boolTo("guest ok"),
  guestaccount: same("guest account"),
  validusers: userList("valid users"),
  invalidusers: userList("invalid users"),
  readlist: userList("read list"),
  writelist: userList("write list"),
  adminusers: () => ({ drop: "aucun effet : ksmbd-tools ne lit pas « admin users » (KSMBD_SHARE_CONF_IS_BROKEN)" }),
  hostsallow: hostDrop("hosts allow"),
  allowhosts: hostDrop("hosts allow"),
  hostsdeny: hostDrop("hosts deny"),
  denyhosts: hostDrop("hosts deny"),
  createmask: octal("create mask"),
  createmode: octal("create mask"),
  directorymask: octal("directory mask"),
  directorymode: octal("directory mask"),
  forcecreatemode: octal("force create mode"),
  forcedirectorymode: octal("force directory mode"),
  forceuser: same("force user"),
  forcegroup: (v) => ({ key: "force group", value: v.trim().replace(/^\+/, ""), note: v.trim().startsWith("+") ? "« +groupe » (seulement si membre) n'existe pas : force inconditionnel" : undefined, action: v.trim().startsWith("+") ? "converted" : undefined }),
  inheritowner: (v) => {
    const s = v.trim().toLowerCase();
    if (s === "unix only" || s === "windows and unix") return { key: "inherit owner", value: "yes", action: "converted", note: `« ${v} » → yes (ksmbd ne reprend que l'UID)` };
    return boolTo("inherit owner")(v, null as unknown as Ctx);
  },
  vetofiles: same("veto files"),
  hidedotfiles: boolTo("hide dot files"),
  hideunreadable: boolTo("hide unreadable"),
  followsymlinks: boolTo("follow symlinks"),
  storedosattributes: boolTo("store dos attributes"),
  oplocks: boolTo("oplocks"),
  maxconnections: same("max connections"),
  smbencrypt: (v) => {
    const s = encryptValue(v);
    return s ? { key: "smb3 encryption", value: s, action: "converted", note: `smb encrypt = ${v} → ${s}` } : { drop: `valeur inconnue « ${v} »` };
  },
  serversmbencrypt: (v, ctx) => SHARE_MAP.smbencrypt!(v, ctx),
  crossmnt: boolTo("crossmnt"),
};

const SHARE_DROP: Record<string, string> = {
  inheritpermissions: "pas d'équivalent : utilisez setgid + une ACL par défaut sur le dossier (onglet Permissions de cockpit-zfs)",
  inheritacls: "l'héritage POSIX est natif ; avec acl_xattr, l'héritage NT est automatique",
  ntaclsupport: "remplacé par vfs objects = acl_xattr",
  mapaclinherit: "sans objet",
  aclallowexecutealways: "sans objet",
  acl_xattr: "sans objet",
  "acl_xattr:ignoresystemacls": "non géré",
  "acl_xattr:defaultacls": "non géré",
  dosfilemode: "non géré : seuls les droits POSIX / NT décident",
  dosfiletimes: "sans objet",
  mapreadonly: "non géré", maparchive: "non géré", maphidden: "non géré", mapsystem: "non géré",
  easupport: "les xattrs utilisateur sont toujours exposés",
  strictlocking: "géré par le noyau", strictsync: "géré par le noyau", syncalways: "géré par le noyau", kerneloplocks: "pas d'équivalent : ksmbd ne pose aucun bail noyau, ses oplocks ne sont pas coordonnés avec NFS ou les accès locaux", kernelsharemodes: "pas d'équivalent : les modes de partage ksmbd sont internes (invisibles pour NFS et les accès locaux)", posixlocking: "toujours actif : ksmbd pose des verrous POSIX noyau", level2oplocks: "intégré aux oplocks / baux",
  cscpolicy: "pas de cache côté client configurable",
  guestonly: "non géré : utilisez force user = <compte invité> + guest ok",
  "shadow:snapdir": "pas de « Versions précédentes » (shadow_copy2) dans ksmbd",
  "shadow:sort": "pas de shadow_copy2", "shadow:format": "pas de shadow_copy2", "shadow:localtime": "pas de shadow_copy2", "shadow:snapdirseverywhere": "pas de shadow_copy2",
  "recycle:repository": "pas de corbeille réseau (vfs recycle)", "recycle:keeptree": "pas de corbeille", "recycle:versions": "pas de corbeille", "recycle:touch": "pas de corbeille", "recycle:exclude": "pas de corbeille", "recycle:directory_mode": "pas de corbeille",
  "full_audit:prefix": "pas d'audit (full_audit)", "full_audit:success": "pas d'audit", "full_audit:failure": "pas d'audit", "full_audit:facility": "pas d'audit", "full_audit:priority": "pas d'audit",
  printable: "pas d'impression", printing: "pas d'impression",
  widelinks: "converti en global (allow insecure wide links) si activé",
  casesensitive: "géré par le système de fichiers (casesensitivity ZFS)", defaultcase: "sans objet", preservecase: "sans objet", shortpreservecase: "sans objet", manglednames: "pas de noms 8.3",
  "fruit:resource": "sans objet", "fruit:metadata": "sans objet", "fruit:locking": "sans objet", "fruit:encoding": "sans objet", "fruit:posix_rename": "sans objet", "fruit:veto_appledouble": "sans objet", "fruit:delete_empty_adfiles": "sans objet", "fruit:wipe_intentionally_left_blank_rfork": "sans objet",
  "fruit:time machine max size": "pas de limite Time Machine dans ksmbd : utilisez un quota / refquota ZFS sur le dataset",
  "zfsacl:acesort": "pas de zfsacl", "nfs4:mode": "pas d'ACL NFSv4", "nfs4:acedup": "pas d'ACL NFSv4", "nfs4:chown": "pas d'ACL NFSv4",
  administrativeshare: "sans objet",
  "smbd:async dosmode": "sans objet",
};

const KNOWN_VFS: Record<string, { keep?: string; note: string }> = {
  acl_xattr: { keep: "acl_xattr", note: "conservé" },
  streams_xattr: { keep: "streams_xattr", note: "conservé" },
  fruit: { note: "intégré à ksmbd (AAPL) : métadonnées macOS via streams_xattr, Time Machine via « time machine = yes »" },
  catia: { note: "pas de traduction de caractères : les noms avec : * ? \" < > | créés par macOS restent tels quels" },
  shadow_copy2: { note: "pas de « Versions précédentes » : les snapshots ZFS restent accessibles via .zfs/snapshot" },
  shadow_copy: { note: "pas de « Versions précédentes »" },
  snapper: { note: "pas de « Versions précédentes »" },
  io_uring: { note: "inutile : ksmbd fait ses E/S dans le noyau" },
  recycle: { note: "pas de corbeille réseau" },
  full_audit: { note: "pas d'audit des accès : utilisez auditd sur le chemin" },
  zfsacl: { note: "ACL NFSv4 non gérées : ksmbd utilise ACL POSIX + security.NTACL" },
  nfs4acl_xattr: { note: "ACL NFSv4 non gérées" },
  btrfs: { note: "sans objet" },
  ceph: { note: "CephFS doit être monté par le noyau ; vfs ceph non géré" },
  ceph_new: { note: "idem" },
  glusterfs: { note: "non géré" },
  xattr_tdb: { note: "non géré : les xattrs doivent être natifs" },
  dfs_samba4: { note: "pas de DFS" },
  readonly: { note: "utilisez read only = yes" },
  worm: { note: "non géré" },
  crossrename: { note: "non géré" },
  widelinks: { note: "voir allow insecure wide links" },
  dirsort: { note: "non géré" },
  preopen: { note: "non géré" },
  virusfilter: { note: "non géré" },
  time_audit: { note: "non géré" },
  extd_audit: { note: "non géré" },
  audit: { note: "non géré" },
};

const SKIP_SECTIONS: Record<string, string> = {
  homes: "ksmbd n'a pas de partage [homes] automatique : créez un partage par utilisateur si nécessaire",
  printers: "pas d'impression",
  "print$": "pas d'impression",
  netlogon: "pas de contrôleur de domaine",
  sysvol: "pas de contrôleur de domaine",
};

// ------------------------------------------------------------------ conversion

function add(report: ReportLine[], l: ReportLine) {
  report.push(l);
}

function convertSection(src: IniSection, ctx: Ctx, map: Record<string, Converter>, drops: Record<string, string>, other: Record<string, Converter>) {
  for (const e of src.entries) {
    const nk = normalizeKey(e.key);
    const value = e.value;
    if (/%[A-Za-z$]/.test(value) && !["vetofiles"].includes(nk)) {
      add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "warning", note: "contient une substitution Samba (%U, %S, %H…) que ksmbd ne développe pas" });
    }
    if (nk === "vfsobjects" || nk === "vfsobject") {
      convertVfs(value, ctx);
      continue;
    }
    if (nk === "fruit:timemachine" || (ctx.isGlobal && nk === "maxconnections")) continue; // traités après la section
    if (/[;#]/.test(value) && nk !== "comment") {
      add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "dropped", note: "contient « ; » ou « # » : ksmbd-tools couperait la valeur à cet endroit" });
      continue;
    }
    if (nk === "comment" && /[;#]/.test(value)) {
      const kept = value.slice(0, value.search(/[;#]/)).trim();
      if (kept) setValue(ctx.out, "comment", kept);
      add(ctx.report, { section: ctx.section, key: e.key, from: value, to: kept ? `comment = ${kept}` : undefined, action: "converted", note: "tronqué au premier « ; » ou « # » (ksmbd-tools le couperait de toute façon)" });
      continue;
    }
    const conv = map[nk];
    if (conv) {
      const r = conv(value, ctx);
      if (!r) continue;
      if ("drop" in r) {
        add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "dropped", note: r.drop });
        continue;
      }
      setValue(ctx.out, r.key, r.value);
      const renamed = normalizeKey(r.key) !== nk || e.key !== r.key;
      add(ctx.report, {
        section: ctx.section, key: e.key, from: value, to: `${r.key} = ${r.value}`,
        action: r.action ?? (renamed && normalizeKey(r.key) !== nk ? "renamed" : "kept"),
        note: r.note ?? (normalizeKey(r.key) !== nk ? "synonyme Samba" : ""),
      });
      continue;
    }
    if (drops[nk] !== undefined) {
      if (nk === "widelinks" && !ctx.isGlobal && sambaBool(value)) {
        setValue(ctx.outGlobal, "allow insecure wide links", "yes");
        if (!getValue(ctx.out, "follow symlinks")) setValue(ctx.out, "follow symlinks", "yes");
        add(ctx.report, { section: ctx.section, key: e.key, from: value, to: "[global] allow insecure wide links = yes + follow symlinks = yes", action: "converted", note: "s'applique désormais à tous les partages" });
        continue;
      }
      add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "dropped", note: drops[nk]! });
      continue;
    }
    // paramètre de partage écrit dans [global] (défaut pour tous les partages)
    if (ctx.isGlobal && other[nk]) {
      const r = other[nk]!(value, ctx);
      if (r && !("drop" in r)) {
        setValue(ctx.out, r.key, r.value);
        add(ctx.report, { section: ctx.section, key: e.key, from: value, to: `${r.key} = ${r.value}`, action: r.action ?? "kept", note: [r.note, "paramètre de partage en [global] : défaut pour tous les partages"].filter(Boolean).join("; ") });
      } else if (r && "drop" in r) {
        add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "dropped", note: r.drop });
      }
      continue;
    }
    if (!ctx.isGlobal && GLOBAL_MAP[nk]) {
      add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "dropped", note: "paramètre global dans un partage : ignoré par ksmbd" });
      continue;
    }
    const known = findParam(e.key);
    if (known && normalizeKey(known.key) === nk) {
      setValue(ctx.out, known.key, value.trim());
      add(ctx.report, { section: ctx.section, key: e.key, from: value, to: `${known.key} = ${value.trim()}`, action: "kept", note: "" });
      continue;
    }
    add(ctx.report, { section: ctx.section, key: e.key, from: value, action: "dropped", note: nk.includes(":") ? "option de module VFS Samba sans équivalent" : "paramètre Samba sans équivalent ksmbd" });
  }
}

function convertVfs(value: string, ctx: Ctx) {
  const mods = value.split(/[,\s]+/).filter(Boolean);
  const keep = new Set<string>();
  for (const m of mods) {
    const info = KNOWN_VFS[m];
    if (info?.keep) keep.add(info.keep);
    if (m === "fruit") keep.add("streams_xattr");
    if ((m === "zfsacl" || m === "nfs4acl_xattr") && ctx.opts.keepWindowsAcls) keep.add("acl_xattr");
    add(ctx.report, { section: ctx.section, key: "vfs objects", from: m, to: info?.keep, action: info?.keep ? "kept" : "dropped", note: info?.note ?? "module VFS inconnu de ksmbd" });
  }
  if (keep.size) setValue(ctx.out, "vfs objects", [...keep].join(" "));
}

/** Fusionne smb.conf et le registre (net conf list) : le registre gagne. */
export function mergeSambaSources(smbConf: string, registry?: string): IniDocument {
  const base = parseIni(smbConf);
  if (!registry?.trim()) return base;
  const reg = parseIni(registry);
  const merged = cloneDoc(base);
  for (const s of reg.sections) {
    const target = findSection(merged, s.name) ?? (merged.sections.push({ name: s.name, entries: [] }), merged.sections[merged.sections.length - 1]!);
    for (const e of s.entries) setValue(target, e.key, e.value);
  }
  for (const s of merged.sections) s.entries = s.entries.filter((e) => !(normalizeKey(e.key) === "include" && e.value.trim() === "registry"));
  return merged;
}

/**
 * ksmbd accepte un membre de read list / write list SANS consulter valid users
 * (tree_conn.c) ; Samba garde valid users comme filtre d'entrée. On signale (et
 * optionnellement on retire) les entrées qui contourneraient valid users, ainsi
 * que celles présentes dans les deux listes (ksmbd : lecture seule ; Samba : écriture).
 */
function checkAccessLists(name: string, share: IniSection, global: IniSection, opts: ConversionOptions, report: ReportLine[]) {
  const list = (k: string) => (getValue(share, k) ?? getValue(global, k) ?? "").split(/[\s,]+/).filter(Boolean);
  const valid = list("valid users");
  const read = list("read list");
  const write = list("write list");
  const both = read.filter((e) => write.includes(e));
  if (both.length) {
    add(report, { section: name, key: "read list", action: "warning", note: `${both.join(", ")} dans read list ET write list : ksmbd donne la lecture seule (Samba donnait l'écriture)` });
  }
  if (!valid.length) return;
  for (const k of ["read list", "write list"]) {
    const entries = list(k);
    const outside = entries.filter((e) => !valid.includes(e));
    if (!outside.length) continue;
    const groups = outside.filter((e) => e.startsWith("@"));
    if (opts.intersectWithValidUsers) {
      const kept = entries.filter((e) => valid.includes(e));
      if (kept.length) setValue(share, k, kept.join(" "));
      else deleteValue(share, k);
      add(report, { section: name, key: k, from: entries.join(" "), to: kept.length ? `${k} = ${kept.join(" ")}` : "(retiré)", action: "converted",
        note: `retiré ${outside.join(", ")} : absents de valid users, ils y auraient échappé dans ksmbd` +
          (groups.length ? ` ; les groupes ne sont comparés que littéralement (${groups.join(", ")}) : vérifiez qu'aucun membre légitime n'est perdu` : "") });
    } else {
      add(report, { section: name, key: k, action: "warning",
        note: `${outside.join(", ")} absents de valid users : ksmbd les acceptera quand même (read list / write list sont évaluées avant valid users)` });
    }
  }
}

export function convertSambaToKsmbd(sambaDoc: IniDocument, opts: ConversionOptions = defaultConversionOptions()): ConversionResult {
  const report: ReportLine[] = [];
  const blocking: string[] = [];
  const out: IniDocument = { sections: [], flavor: "ksmbd" };
  const outGlobal: IniSection = { name: "global", entries: [], flavor: "ksmbd" };
  out.sections.push(outGlobal);
  const srcGlobal = findSection(sambaDoc, "global");
  const followUp: string[] = [];

  if (srcGlobal) {
    convertSection(srcGlobal, { section: "global", isGlobal: true, blocking, report, out: outGlobal, outGlobal, opts, src: srcGlobal, srcGlobal }, GLOBAL_MAP, GLOBAL_DROP, SHARE_MAP);
  }
  // bind interfaces only sans interface valide : ksmbd n'écouterait plus nulle part
  if (getValue(outGlobal, "bind interfaces only") === "yes" && !getValue(outGlobal, "interfaces")) {
    deleteValue(outGlobal, "bind interfaces only");
    add(report, { section: "global", key: "bind interfaces only", from: "yes", action: "dropped", note: "aucune interface convertie (adresses IP non reconnues par ksmbd) : ksmbd écoutera sur toutes les interfaces" });
  }
  // max connections de Samba en [global] = défaut PAR PARTAGE ; dans ksmbd ce serait un plafond serveur
  const globalMaxConn = getValue(srcGlobal, "max connections")?.trim();
  if (globalMaxConn) {
    add(report, { section: "global", key: "max connections", from: globalMaxConn, to: "recopié dans chaque partage", action: "converted", note: "en [global] Samba c'est le défaut de chaque partage ; en [global] ksmbd ce serait un plafond pour tout le serveur" });
  }

  const timeMachineShares: string[] = [];
  for (const s of sambaDoc.sections) {
    const lname = s.name.toLowerCase();
    if (lname === "global") continue;
    if (SKIP_SECTIONS[lname]) {
      add(report, { section: s.name, action: "skipped-section", note: SKIP_SECTIONS[lname]! });
      continue;
    }
    if (opts.excludeShares.map((x) => x.toLowerCase()).includes(lname)) {
      add(report, { section: s.name, action: "skipped-section", note: "exclu par l'utilisateur" });
      continue;
    }
    if (sambaBool(getValue(s, "printable") ?? "no")) {
      add(report, { section: s.name, action: "skipped-section", note: "partage d'imprimante" });
      continue;
    }
    if (sambaBool(getValue(s, "available") ?? "yes") === false) {
      add(report, { section: s.name, action: "skipped-section", note: "available = no dans Samba" });
      continue;
    }
    const outShare: IniSection = { name: s.name, entries: [], flavor: "ksmbd" };
    const ctx: Ctx = { section: s.name, isGlobal: false, blocking, report, out: outShare, outGlobal, opts, src: s, srcGlobal };
    convertSection(s, ctx, SHARE_MAP, SHARE_DROP, {});
    if (globalMaxConn && !getValue(outShare, "max connections") && /^\d+$/.test(globalMaxConn)) {
      setValue(outShare, "max connections", globalMaxConn);
    }
    // Samba suit les liens symboliques par défaut, ksmbd non
    if (getValue(s, "follow symlinks") === undefined && getValue(srcGlobal, "follow symlinks") === undefined && !getValue(outShare, "follow symlinks")) {
      add(report, { section: s.name, key: "follow symlinks", action: "warning", note: "non défini : Samba suit les liens symboliques par défaut, ksmbd non (follow symlinks = no). Ajoutez « follow symlinks = yes » si le partage en contient." });
    }
    checkAccessLists(s.name, outShare, outGlobal, opts, report);

    // Time Machine (fruit:time machine)
    const tm = getValue(s, "fruit:time machine") ?? getValue(srcGlobal, "fruit:time machine");
    if (tm !== undefined && sambaBool(tm)) {
      if (opts.timeMachine) {
        setValue(outShare, "time machine", "yes");
        const vfs = new Set((getValue(outShare, "vfs objects") ?? "").split(/\s+/).filter(Boolean));
        vfs.add("streams_xattr");
        setValue(outShare, "vfs objects", [...vfs].join(" "));
        timeMachineShares.push(s.name);
        add(report, { section: s.name, key: "fruit:time machine", from: tm, to: "time machine = yes (+ streams_xattr)", action: "converted", note: "exige Linux 7.3+ côté ksmbd ; durable handles et smb2 leases forcés à yes" });
      } else {
        add(report, { section: s.name, key: "fruit:time machine", from: tm, action: "dropped", note: "Time Machine désactivé dans les options de conversion" });
      }
    }
    // ACL Windows : partages qui avaient des ACL NT sans acl_xattr explicite
    if (opts.keepWindowsAcls) {
      const ntAcl = sambaBool(getValue(s, "nt acl support") ?? getValue(srcGlobal, "nt acl support") ?? "yes");
      const vfsSrc = (getValue(s, "vfs objects") ?? getValue(srcGlobal, "vfs objects") ?? "").split(/[,\s]+/);
      if (ntAcl !== false && vfsSrc.includes("acl_xattr") && !(getValue(outShare, "vfs objects") ?? "").includes("acl_xattr")) {
        const vfs = new Set((getValue(outShare, "vfs objects") ?? "").split(/\s+/).filter(Boolean));
        vfs.add("acl_xattr");
        setValue(outShare, "vfs objects", [...vfs].join(" "));
        add(report, { section: s.name, key: "vfs objects", to: "acl_xattr", action: "added", note: "hérité de [global] côté Samba" });
      }
    }
    if (!getValue(outShare, "path")) {
      add(report, { section: s.name, action: "warning", note: "aucun path : ksmbd refusera ce partage" });
    }
    // Avertissement umask : groupe en écriture attendu ?
    const cm = parseInt(getValue(outShare, "create mask") ?? getValue(outGlobal, "create mask") ?? "0744", 8);
    const fcm = parseInt(getValue(outShare, "force create mode") ?? "0", 8);
    if ((cm | fcm) & 0o020) {
      add(report, { section: s.name, key: "create mask", action: "warning", note: "écriture groupe demandée : l'umask des workers ksmbd (0022 sur les noyaux récents, vérifiez avec « grep Umask /proc/$(pgrep -x kthreadd)/status ») est appliqué si le dossier parent n'a pas d'ACL POSIX par défaut (toujours en acltype=off). Posez une ACL par défaut (setfacl -d -m g::rwx) sur la racine du partage." });
    }
    out.sections.push(outShare);
  }

  // ---------------------------------------------------------------- options propres à ksmbd
  const setG = (key: string, value: string, note: string) => {
    const before = getValue(outGlobal, key);
    setValue(outGlobal, key, value);
    add(report, { section: "global", key, from: before, to: `${key} = ${value}`, action: "added", note });
  };

  if (opts.multichannel || opts.rdma.enable) setG("server multi channel support", "yes", opts.rdma.enable ? "requis : Windows n'emploie SMB Direct que via le multicanal" : "multicanal SMB3");
  if (opts.rdma.enable) {
    setG("smbd max io size", opts.rdma.maxIoSize || "8MB", "taille des E/S RDMA");
    followUp.push(
      "# RDMA : vérifier que le noyau a SMB Direct",
      "grep -E 'CONFIG_SMB_SERVER(_SMBDIRECT)?=' /boot/config-$(uname -r)",
      "rdma link show            # le port doit être ACTIVE (qedr pour la QL41112)",
      "ibv_devinfo               # paquet rdma-core / libibverbs-utils",
      "# iWARP (QL41112 en mode iWARP) : SMB Direct écoute sur 5445/tcp ; RoCE / IB : 445",
      "firewall-cmd --permanent --add-port=5445/tcp && firewall-cmd --reload",
    );
  }
  const ifaces = [...new Set([...opts.rdma.interfaces, ...opts.extraInterfaces].filter(Boolean))];
  if (ifaces.length) {
    setG("interfaces", ifaces.join(" "), "interfaces TCP + RDMA écoutées");
    setG("bind interfaces only", "yes", "n'écouter que ces interfaces");
  } else if (opts.bindInterfacesOnly && getValue(outGlobal, "interfaces")) {
    setG("bind interfaces only", "yes", "n'écouter que les interfaces converties");
  }
  if (opts.durableHandles || timeMachineShares.length) setG("durable handles", "yes", timeMachineShares.length ? "requis pour Time Machine" : "reprise après micro-coupure");
  if (opts.leases || timeMachineShares.length) setG("smb2 leases", "yes", timeMachineShares.length ? "requis pour Time Machine" : "baux SMB2.1+");
  if (opts.smb2MaxRead) setG("smb2 max read", opts.smb2MaxRead, "taille des lectures TCP");
  if (opts.smb2MaxWrite) setG("smb2 max write", opts.smb2MaxWrite, "taille des écritures TCP");
  if (opts.smb2MaxTrans) setG("smb2 max trans", opts.smb2MaxTrans, "taille des transactions");
  if (opts.smb2MaxCredits) setG("smb2 max credits", opts.smb2MaxCredits, "crédits par connexion");
  if (opts.maxIpConnections) setG("max ip connections", opts.maxIpConnections, "le multicanal ouvre plusieurs connexions par client");
  else if ((opts.multichannel || opts.rdma.enable) && !getValue(outGlobal, "max ip connections")) {
    add(report, { section: "global", key: "max ip connections", action: "warning", note: "32 par défaut : suffisant en général, augmentez si beaucoup de canaux par client" });
  }
  if (opts.signing !== "keep") setG("server signing", opts.signing, "choisi à la conversion");
  if (opts.encryption !== "keep") setG("smb3 encryption", opts.encryption, "choisi à la conversion");
  if (opts.minProtocol !== "keep") setG("server min protocol", opts.minProtocol, "choisi à la conversion");
  if (opts.rdma.enable && (getValue(outGlobal, "server signing") === "mandatory" || getValue(outGlobal, "smb3 encryption") === "mandatory")) {
    add(report, { section: "global", action: "warning", note: "signature / chiffrement obligatoires : le RDMA reste fonctionnel mais le CPU redevient le goulot (pas de déchargement)" });
  }
  if (timeMachineShares.length) {
    followUp.push(
      "# Time Machine : ksmbd n'annonce pas en mDNS, créer /etc/avahi/services/ksmbd.service",
      `# avec _smb._tcp (port 445) et _adisk._tcp (dk0=adVN=${timeMachineShares[0]},adVF=0x82)`,
    );
  }

  // comptes de connexion (force user n'en a pas besoin : seulement un compte Unix)
  const users = new Set<string>();
  const forced = new Set<string>();
  for (const s of out.sections) {
    for (const k of ["valid users", "write list", "read list"]) {
      for (const u of (getValue(s, k) ?? "").split(/\s+/).filter((x) => x && !x.startsWith("@"))) users.add(u);
    }
    const fu = getValue(s, "force user");
    if (fu) forced.add(fu);
  }
  followUp.unshift(
    "# Comptes : les mots de passe Samba ne sont pas migrables",
    ...[...users].map((u) => `ksmbd.adduser -a ${u}`),
    "# Pour chaque membre des groupes @… utilisés : ksmbd.adduser -a <compte>",
    ...(forced.size ? [`# force user (${[...forced].join(", ")}) : doit seulement exister comme compte Unix (getent passwd), pas de ksmbd.adduser`] : []),
    "systemctl disable --now smb nmb 2>/dev/null; systemctl disable --now smbd nmbd 2>/dev/null",
    "# démarrage complet : les paramètres [global] ne sont lus qu'au démarrage de ksmbd.mountd (pas par --reload)",
    "systemctl enable ksmbd && systemctl restart ksmbd",
  );

  // cohabitation avec des exports NFS existants
  if (opts.nfsExports?.length) {
    for (const sec of out.sections) {
      if (sec.name.toLowerCase() === "global") continue;
      const path = getValue(sec, "path") ?? "";
      for (const { export: e } of overlappingExports(path, opts.nfsExports)) {
        const src = findSection(sambaDoc, sec.name);
        const ko = getValue(src, "kernel oplocks") ?? getValue(srcGlobal, "kernel oplocks");
        const ksm = getValue(src, "kernel share modes") ?? getValue(srcGlobal, "kernel share modes");
        add(report, {
          section: sec.name, action: "warning",
          note: `chemin exporté aussi en NFS (${e.path}). Samba${ko !== undefined ? ` (kernel oplocks = ${ko})` : ""}${ksm !== undefined ? ` (kernel share modes = ${ksm})` : ""} pouvait coordonner ses oplocks et modes de partage avec le noyau ; ksmbd n'a aucun équivalent.`,
        });
        for (const f of analyzeDualProtocol({ doc: out, share: sec.name, nfsExport: e })) {
          if (f.level === "info") continue;
          add(report, { section: sec.name, action: "warning", note: `NFS ${e.path} — ${f.title} : ${f.detail}${f.fix ? ` → ${f.fix}` : ""}` });
          if (f.level === "danger") blocking.push(`[${sec.name}] ${f.title} (export NFS ${e.path}) : ${f.fix ?? f.detail}`);
        }
      }
    }
  }

  const text = serializeIni(out, [
    "ksmbd.conf généré par cockpit-file-sharing (conversion depuis Samba)",
    `le ${new Date().toISOString().slice(0, 10)} — voir ksmbd.conf(5)`,
  ]);
  return { doc: out, text, report, followUp, blocking };
}
