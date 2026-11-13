/**
 * Catalogue des paramètres ksmbd.conf, établi d'après ksmbd.conf(5) et le
 * code de ksmbd-tools (tools/config_parser.c, tools/management/share.c).
 *
 * Particularités du parseur ksmbd-tools à connaître :
 *  - clés : insensibles à la casse mais les espaces comptent (« readonly »
 *    n'est pas « read only », contrairement à Samba) ; pas d'alias Samba
 *    comme « create mode », « public » ou « browsable ».
 *  - booléens : comparaison par PRÉFIXE avec « yes », « true », « 1 » ou
 *    « enable » (« enabled » est donc vrai) ; « on » vaut FAUX.
 *  - options à 4 états (server signing, smb3 encryption) : préfixe
 *    « enabled », « auto » ou « mandatory » ; toute autre valeur (« yes »,
 *    « required »…) est lue comme « disabled » sans avertissement.
 *  - tailles : suffixes K, M, G, T, P, E (puissances de 1024).
 *  - les paramètres de partage placés dans [global] servent de valeurs par
 *    défaut à tous les partages.
 */

export type KsmbdParamType = "bool" | "string" | "list" | "octal" | "int" | "size" | "enum" | "opt";
export type KsmbdScope = "global" | "share" | "both";

export type KsmbdCategory =
  | "identity"
  | "network"
  | "security"
  | "performance"
  | "rdma"
  | "guest"
  | "limits"
  | "macos"
  | "access"
  | "unix"
  | "behaviour";

export const categoryLabels: Record<KsmbdCategory, string> = {
  identity: "Identité du serveur",
  network: "Réseau et interfaces",
  security: "Protocole, signature et chiffrement",
  performance: "Performances SMB2/3",
  rdma: "RDMA (SMB Direct) et multicanal",
  guest: "Invités et authentification",
  limits: "Limites de sessions et connexions",
  macos: "macOS et Time Machine",
  access: "Listes d'accès (empilement à la connexion)",
  unix: "Permissions Unix des nouveaux fichiers",
  behaviour: "Comportement du partage",
};

export interface KsmbdParam {
  key: string;
  scope: KsmbdScope;
  type: KsmbdParamType;
  default: string;
  category: KsmbdCategory;
  description: string;
  values?: string[];
  /** false pour les clés lues par ksmbd-tools mais absentes du manuel */
  documented?: boolean;
  /** synonymes acceptés par ksmbd-tools */
  aliases?: string[];
  warning?: string;
  /** défaut différent quand le paramètre est placé dans un partage */
  shareDefault?: string;
  /** clé reconnue mais jamais lue par ksmbd-tools (motif) */
  ignored?: string;
}

/** Clés désactivées dans ksmbd-tools : KSMBD_SHARE_CONF_IS_BROKEN (include/management/share.h). */
export const BROKEN_KEYS = ["admin users", "hosts allow", "hosts deny"];
const BROKEN_REASON = "ignoré par ksmbd-tools (KSMBD_SHARE_CONF_IS_BROKEN) : la clé n'est jamais lue, ni dans un partage ni dans [global]";

export const OPT_VALUES = ["enabled", "auto", "mandatory", "disabled"];

export const ksmbdParams: KsmbdParam[] = [
  // ---------------------------------------------------------------- identité
  { key: "workgroup", scope: "global", type: "string", default: "WORKGROUP", category: "identity", description: "Groupe de travail annoncé." },
  { key: "server string", scope: "global", type: "string", default: "SMB SERVER", category: "identity", description: "Description du serveur." },
  { key: "netbios name", scope: "global", type: "string", default: "KSMBD SERVER", category: "identity", description: "Nom NetBIOS (ksmbd ne fait pas de service de noms : utilisez wsdd2 / Avahi pour la découverte)." },
  { key: "root directory", scope: "global", type: "string", default: "", category: "identity", description: "Racine (chroot) pour les chemins des partages." },

  // ---------------------------------------------------------------- réseau
  { key: "interfaces", scope: "global", type: "list", default: "", category: "network", description: "Interfaces écoutées quand « bind interfaces only = yes ». Indispensable pour cibler les partitions NPAR / ports RDMA." },
  { key: "bind interfaces only", scope: "global", type: "bool", default: "no", category: "network", description: "N'écouter que sur les interfaces listées." },
  { key: "tcp port", scope: "global", type: "int", default: "445", category: "network", description: "Port TCP SMB. SMB Direct utilise 445 (InfiniBand / RoCE) ou 5445 (iWARP), non configurable ici." },
  { key: "deadtime", scope: "global", type: "int", default: "0", category: "network", description: "Minutes d'inactivité avant de fermer une connexion sans fichier ouvert (0 = jamais)." },
  { key: "ipc timeout", scope: "global", type: "int", default: "0", category: "network", description: "Secondes d'attente d'une réponse de ksmbd.mountd (0 = défaut noyau)." },

  // ---------------------------------------------------------------- sécurité
  { key: "server min protocol", scope: "global", type: "enum", default: "SMB2_10", values: ["SMB2_10", "SMB3_00", "SMB3_02", "SMB3_11"], category: "security", description: "Dialecte minimal. SMB1 n'existe pas dans ksmbd." },
  { key: "server max protocol", scope: "global", type: "enum", default: "SMB3_11", values: ["SMB2_10", "SMB3_00", "SMB3_02", "SMB3_11"], category: "security", description: "Dialecte maximal." },
  { key: "server signing", scope: "global", type: "opt", default: "auto", values: OPT_VALUES, category: "security", description: "Signature SMB. « mandatory » l'exige.", warning: "Toute valeur autre que enabled / auto / mandatory équivaut à disabled." },
  { key: "smb3 encryption", scope: "both", type: "opt", default: "auto", values: OPT_VALUES, category: "security", description: "Chiffrement SMB3. En global, « mandatory » l'impose partout et « disabled » le refuse. Dans un partage, « mandatory » l'exige pour ce partage et « disabled » signifie seulement « non exigé » (les clients peuvent quand même chiffrer).", warning: "« yes » ou « required » sont lus comme disabled." },
  { key: "kerberos support", scope: "global", type: "bool", default: "no", category: "security", description: "Authentification Kerberos (pas de jonction AD complète : pas de winbind ni d'idmap)." },
  { key: "kerberos service name", scope: "global", type: "string", default: "", category: "security", description: "Principal de service Kerberos." },
  { key: "kerberos keytab file", scope: "global", type: "string", default: "", category: "security", description: "Keytab Kerberos." },
  { key: "restrict anonymous", scope: "global", type: "enum", default: "0", values: ["0", "1", "2"], category: "security", description: "1 ou 2 : refuse les sessions invité sur les partages sans « guest ok » et sur IPC$. Toute autre valeur vaut 0." },

  // ---------------------------------------------------------------- performances
  { key: "smb2 max read", scope: "global", type: "size", default: "4MB", category: "performance", description: "Taille max. d'une lecture SMB2 (TCP)." },
  { key: "smb2 max write", scope: "global", type: "size", default: "4MB", category: "performance", description: "Taille max. d'une écriture SMB2 (TCP)." },
  { key: "smb2 max trans", scope: "global", type: "size", default: "1MB", category: "performance", description: "Taille max. d'une transaction (ioctl, query)." },
  { key: "smb2 max credits", scope: "global", type: "int", default: "8192", category: "performance", description: "Crédits accordés par connexion (requêtes en vol)." },
  { key: "smb2 leases", scope: "global", type: "bool", default: "yes", category: "performance", description: "Baux SMB2.1+ (cache client). Requis pour Time Machine." },
  { key: "durable handles", scope: "global", type: "bool", default: "no", category: "performance", description: "Poignées durables : reprise après micro-coupure réseau. Requis pour Time Machine." },
  { key: "share:fake_fscaps", scope: "global", type: "int", default: "64", category: "performance", description: "Capacités FS annoncées (64 = fichiers épars)." },
  { key: "oplocks", scope: "share", type: "bool", default: "yes", category: "performance", description: "Verrous opportunistes (cache client)." },

  // ---------------------------------------------------------------- RDMA / multicanal
  { key: "server multi channel support", scope: "global", type: "bool", default: "no", category: "rdma", description: "Multicanal SMB3 : plusieurs connexions (NIC, partitions NPAR ou RDMA) par session. Windows n'utilise SMB Direct qu'avec le multicanal." },
  { key: "smbd max io size", scope: "global", type: "size", default: "8MB", category: "rdma", description: "Taille max. d'une lecture / écriture SMB Direct (RDMA)." },

  // ---------------------------------------------------------------- invités
  { key: "guest account", scope: "both", type: "string", default: "nobody", category: "guest", description: "Compte Unix utilisé pour les invités (dans un partage : surcharge locale)." },
  { key: "map to guest", scope: "global", type: "enum", default: "never", values: ["never", "bad user"], category: "guest", description: "« bad user » : un utilisateur inconnu devient invité. « bad password » est désactivé dans ksmbd-tools." },
  { key: "guest ok", scope: "share", type: "bool", default: "no", category: "guest", description: "Connexion sans mot de passe sous le compte invité." },

  // ---------------------------------------------------------------- limites
  { key: "max active sessions", scope: "global", type: "int", default: "1024", category: "limits", description: "Sessions simultanées max." },
  { key: "max sessions per connection", scope: "global", type: "int", default: "64", category: "limits", description: "Sessions max. par connexion TCP." },
  { key: "max connections", scope: "both", type: "int", default: "256", shareDefault: "128", category: "limits", description: "En [global] : plafond de connexions pour TOUT le serveur (défaut 256), non propagé aux partages. Dans un partage : plafond de ce partage (défaut 128)." },
  { key: "max ip connections", scope: "global", type: "int", default: "32", category: "limits", description: "Connexions max. par adresse IP. Le multicanal en ouvre plusieurs par client." },
  { key: "max open files", scope: "global", type: "int", default: "10000", category: "limits", description: "Fichiers ouverts max." },

  // ---------------------------------------------------------------- macOS
  { key: "aapl model", scope: "global", type: "string", default: "Xserve", category: "macos", description: "Modèle annoncé via l'extension AAPL (icône du Finder). Utile seulement avec « time machine = yes »." },
  { key: "time machine", scope: "share", type: "bool", default: "no", category: "macos", description: "Annonce le partage comme cible Time Machine (AAPL). Exige streams_xattr, durable handles et smb2 leases." },

  // ---------------------------------------------------------------- accès
  { key: "valid users", scope: "share", type: "list", default: "", category: "access", description: "Utilisateurs autorisés (@groupe accepté). Vide = tous." },
  { key: "invalid users", scope: "share", type: "list", default: "", category: "access", description: "Utilisateurs refusés. Prioritaire sur read list, write list et valid users." },
  { key: "read list", scope: "share", type: "list", default: "", category: "access", description: "Accès lecture seule. Prioritaire sur write list et read only = no. ATTENTION : un membre est accepté sans que valid users soit consulté." },
  { key: "write list", scope: "share", type: "list", default: "", category: "access", description: "Accès lecture-écriture. Prioritaire sur read only = yes. ATTENTION : un membre est accepté sans que valid users soit consulté." },
  { key: "admin users", scope: "share", type: "list", default: "", category: "access", documented: false, ignored: BROKEN_REASON, description: "Sans effet : ksmbd-tools ne lit pas cette clé." },
  { key: "hosts allow", scope: "share", type: "list", default: "", category: "access", documented: false, ignored: BROKEN_REASON, description: "Sans effet : ksmbd-tools ne lit pas cette clé. Filtrez au pare-feu ou avec bind interfaces only." },
  { key: "hosts deny", scope: "share", type: "list", default: "", category: "access", documented: false, ignored: BROKEN_REASON, description: "Sans effet : ksmbd-tools ne lit pas cette clé. Filtrez au pare-feu." },
  { key: "read only", scope: "share", type: "bool", default: "yes", category: "access", description: "Partage en lecture seule. Prioritaire sur writable / writeable / write ok." },
  { key: "writable", scope: "share", type: "bool", default: "", category: "access", description: "Inverse de read only. Ignoré si read only est défini (même hérité de [global]) ; lu avant writeable et write ok." },
  { key: "writeable", scope: "share", type: "bool", default: "", category: "access", description: "Synonyme de writable, lu seulement si ni read only ni writable ne sont définis." },
  { key: "write ok", scope: "share", type: "bool", default: "", category: "access", description: "Synonyme de writable, lu en dernier." },

  // ---------------------------------------------------------------- unix
  { key: "create mask", scope: "share", type: "octal", default: "0744", category: "unix", description: "ET binaire appliqué au mode demandé pour un nouveau fichier." },
  { key: "directory mask", scope: "share", type: "octal", default: "0755", category: "unix", description: "ET binaire appliqué au mode demandé pour un nouveau dossier. Le bit setgid (2000) est retiré par vfs_mkdir : il ne vient que d'un parent setgid." },
  { key: "force create mode", scope: "share", type: "octal", default: "0000", category: "unix", description: "OU binaire appliqué après create mask." },
  { key: "force directory mode", scope: "share", type: "octal", default: "0000", category: "unix", description: "OU binaire appliqué après directory mask (setgid retiré par le noyau, voir directory mask)." },
  { key: "force user", scope: "share", type: "string", default: "", category: "unix", description: "UID effectif de toutes les opérations. Doit exister comme compte Unix (pas besoin de ksmbd.adduser). Les groupes secondaires de l'utilisateur connecté restent actifs (différent de Samba)." },
  { key: "force group", scope: "share", type: "string", default: "", category: "unix", description: "GID effectif. Avec force user seul, le groupe primaire de ce compte est utilisé." },
  { key: "inherit owner", scope: "share", type: "bool", default: "no", category: "unix", description: "Le nouvel objet reçoit l'UID du dossier parent (seulement l'UID : le groupe suit setgid / force group)." },
  { key: "vfs objects", scope: "share", type: "list", default: "", values: ["acl_xattr", "streams_xattr"], category: "unix", description: "acl_xattr : ACL NT dans security.NTACL, vérifiée EN PLUS des droits POSIX. streams_xattr : flux nommés (ADS, métadonnées macOS) en xattrs." },
  { key: "store dos attributes", scope: "share", type: "bool", default: "yes", category: "unix", description: "Attributs DOS dans user.DOSATTRIB." },

  // ---------------------------------------------------------------- comportement
  { key: "path", scope: "share", type: "string", default: "", category: "behaviour", description: "Chemin du partage." },
  { key: "comment", scope: "share", type: "string", default: "", category: "behaviour", description: "Description du partage." },
  { key: "browseable", scope: "share", type: "bool", default: "yes", category: "behaviour", description: "Visible dans la liste des partages." },
  { key: "hide dot files", scope: "share", type: "bool", default: "yes", category: "behaviour", description: "Les fichiers commençant par un point reçoivent l'attribut caché." },
  { key: "hide unreadable", scope: "share", type: "bool", default: "no", category: "behaviour", description: "Masque les entrées que l'utilisateur ne peut pas lire." },
  { key: "veto files", scope: "share", type: "string", default: "", category: "behaviour", description: "Noms interdits, format /motif1/motif2/." },
  { key: "follow symlinks", scope: "share", type: "bool", default: "no", category: "behaviour", description: "Suivre les liens symboliques (restreints au partage)." },
  { key: "allow insecure wide links", scope: "global", type: "bool", default: "no", category: "behaviour", description: "Laisse les liens créés par l'administrateur sortir du partage (lecture seule, exige follow symlinks)." },
  { key: "crossmnt", scope: "share", type: "bool", default: "yes", category: "behaviour", description: "Traverser les points de montage (datasets ZFS enfants) sous le partage." },
  { key: "btrfs quota map", scope: "share", type: "string", default: "", category: "behaviour", description: "Correspondance qgroup btrfs pour le quota annoncé (sans objet sur ZFS)." },
];

/** Normalise une clé comme Samba (casse et espaces ignorés) : sert à reconnaître
 *  les clés d'un smb.conf ; ksmbd, lui, exige l'orthographe exacte (casse libre). */
export function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[\s_]+/g, "");
}

const byNormalized = new Map<string, KsmbdParam>();
for (const p of ksmbdParams) {
  byNormalized.set(normalizeKey(p.key), p);
  for (const a of p.aliases ?? []) byNormalized.set(normalizeKey(a), p);
}

/** Recherche tolérante façon Samba (casse, espaces, « _ » ignorés) : pour lire un smb.conf. */
export function findParam(key: string): KsmbdParam | undefined {
  return byNormalized.get(normalizeKey(key));
}

const byExact = new Map<string, KsmbdParam>(ksmbdParams.map((p) => [p.key.toLowerCase(), p]));

/** Recherche exacte façon ksmbd-tools (casse ignorée seulement). */
export function findParamExact(key: string): KsmbdParam | undefined {
  return byExact.get(key.trim().toLowerCase());
}

export function defaultFor(p: KsmbdParam, scope: "global" | "share"): string {
  return scope === "share" && p.shareDefault !== undefined ? p.shareDefault : p.default;
}

export function paramsFor(scope: "global" | "share"): KsmbdParam[] {
  return ksmbdParams.filter((p) => p.scope === scope || p.scope === "both");
}

/** cp_key_cmp() : g_ascii_strncasecmp(valeur, attendu, strlen(attendu)) → préfixe. */
const keyCmp = (v: string, expected: string) => v.toLowerCase().startsWith(expected);

/** Lecture d'un booléen exactement comme cp_get_group_kv_bool(). */
export function ksmbdBool(value: string | undefined): boolean {
  const v = (value ?? "").trim();
  return keyCmp(v, "yes") || keyCmp(v, "1") || keyCmp(v, "true") || keyCmp(v, "enable");
}

/** Lecture d'une option à 4 états comme cp_get_group_kv_config_opt(). */
export function ksmbdOpt(value: string | undefined): "enabled" | "auto" | "mandatory" | "disabled" {
  const v = (value ?? "").trim();
  if (keyCmp(v, "enabled")) return "enabled";
  if (keyCmp(v, "auto")) return "auto";
  if (keyCmp(v, "mandatory")) return "mandatory";
  return "disabled";
}

/** Taille avec suffixes (cp_memparse). */
export function ksmbdSize(value: string): number {
  const m = /^\s*(0x[0-9a-f]+|\d+)\s*([kmgtpe])?/i.exec(value);
  if (!m) return 0;
  let n = Number(m[1]);
  const order = "kmgtpe";
  if (m[2]) n *= 1024 ** (order.indexOf(m[2].toLowerCase()) + 1);
  return n;
}

/** Découpe une liste comme ksmbd-tools (virgules, espaces ou tabulations). */
export function ksmbdList(value: string | undefined): string[] {
  return (value ?? "")
    .split(/[,\s\t]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
