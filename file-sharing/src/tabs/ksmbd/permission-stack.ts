/**
 * Modèle de l'empilement des permissions de ksmbd, reproduit d'après :
 *  - ksmbd-tools  tools/management/tree_conn.c   (tcm_handle_tree_connect)
 *  - ksmbd-tools  tools/management/share.c       (listes d'utilisateurs / d'hôtes)
 *  - noyau        fs/smb/server/smb2pdu.c         (smb2_creat, smb2_open)
 *  - noyau        fs/smb/server/smb_common.c      (ksmbd_override_fsids)
 *  - noyau        fs/namei.c / fs/posix_acl.c     (umask, ACL par défaut)
 *
 * Trois niveaux s'empilent :
 *  1. la connexion au partage (tree connect) : refus, lecture seule ou écriture
 *  2. l'identité effective des opérations (force user / force group, groupes)
 *  3. le contrôle d'accès fichier : ACL NT (acl_xattr) ET droits POSIX
 * plus le calcul du mode et des ACL des objets créés.
 */
import { findSection, getValue, type IniDocument, type IniSection } from "./ini";
import { BROKEN_KEYS, defaultFor, findParamExact, ksmbdBool, ksmbdList, paramsFor } from "./ksmbd-params";

// ------------------------------------------------------------------ configuration effective

export type EffectiveShare = Record<string, { value: string; origin: "share" | "global" | "default" }>;

/** Clés de partage que steal_global_share_conf_kv() ne propage pas depuis [global] (KSMBD_SHARE_CONF_IS_GLOBAL). */
const NOT_INHERITED = ["guest account", "max connections"];
/** Clés sans valeur par défaut dans KSMBD_SHARE_DEFCONF (« ; yes » est un commentaire). */
const NO_DEFAULT = ["read only", "writable", "writeable", "write ok"];

/**
 * Valeur effective de chaque paramètre de partage, clé par clé comme
 * steal_global_share_conf_kv() : section du partage, sinon [global] (les
 * paramètres de partage dans [global] servent de défaut), sinon défaut de
 * ksmbd-tools. Les synonymes writable / writeable / write ok sont hérités
 * séparément. Les clés désactivées (hosts allow/deny, admin users) ne sont
 * jamais retenues.
 */
export function effectiveShare(doc: IniDocument, shareName: string): EffectiveShare {
  const share = findSection(doc, shareName);
  const global = findSection(doc, "global");
  const out: EffectiveShare = {};
  for (const p of paramsFor("share")) {
    if (BROKEN_KEYS.includes(p.key)) {
      out[p.key] = { value: "", origin: "default" };
      continue;
    }
    const fromShare = nonEmpty(share, p.key);
    const fromGlobal = NOT_INHERITED.includes(p.key) ? undefined : nonEmpty(global, p.key);
    if (fromShare !== undefined) out[p.key] = { value: fromShare, origin: "share" };
    else if (fromGlobal !== undefined) out[p.key] = { value: fromGlobal, origin: "global" };
    else out[p.key] = { value: NO_DEFAULT.includes(p.key) ? "" : defaultFor(p, "share"), origin: "default" };
  }
  return out;
}

/** Clés désactivées présentes dans le partage ou dans [global]. */
export function brokenKeysPresent(doc: IniDocument, shareName: string): { key: string; value: string; where: string }[] {
  const out: { key: string; value: string; where: string }[] = [];
  for (const [name, where] of [[shareName, "partage"], ["global", "[global]"]] as const) {
    const sec = findSection(doc, name);
    for (const k of BROKEN_KEYS) {
      const v = nonEmpty(sec, k);
      if (v !== undefined) out.push({ key: k, value: v, where });
    }
  }
  return out;
}

/**
 * Lecture du mode d'écriture comme share.c : read only s'il est défini, sinon
 * le premier défini parmi writable, writeable, write ok (dans cet ordre).
 * Sans aucun, le partage est en lecture seule (seul WRITABLE compte côté noyau).
 */
export function writeMode(eff: EffectiveShare): { writable: boolean; key: string; value: string } {
  for (const k of ["read only", "writable", "writeable", "write ok"]) {
    const v = eff[k]?.value;
    if (v) return { writable: k === "read only" ? !ksmbdBool(v) : ksmbdBool(v), key: k, value: v };
  }
  return { writable: false, key: "read only", value: "(non défini : lecture seule)" };
}

function nonEmpty(section: IniSection | undefined, key: string): string | undefined {
  const v = getValue(section, key);
  if (v === undefined) return undefined;
  const t = v.trim();
  return t !== "" && !/^[;#]/.test(t) ? t : undefined;
}

function firstNonEmpty(section: IniSection | undefined, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = nonEmpty(section, k);
    if (v !== undefined) return v;
  }
  return undefined;
}

export function globalValue(doc: IniDocument, key: string): string {
  const v = firstNonEmpty(findSection(doc, "global"), [key]);
  return v ?? findParamExact(key)?.default ?? "";
}

// ------------------------------------------------------------------ base d'utilisateurs

export interface UserDb {
  /** comptes présents dans ksmbdpwd.db (ksmbd.adduser) */
  ksmbdUsers: string[];
  /** comptes Unix : nom → uid / gid primaire */
  unixUsers: Record<string, { uid: number; gid: number }>;
  /** groupes Unix : nom → gid / membres secondaires */
  groups: Record<string, { gid: number; members: string[] }>;
}

export interface ListResolution {
  defined: boolean;
  members: string[];
  ignored: { entry: string; reason: string }[];
}

/**
 * Résout une liste comme add_users_map() : « @groupe » est développé avec les
 * comptes dont c'est le groupe primaire puis les membres secondaires ; seuls
 * les comptes présents dans la base ksmbd sont retenus. Le développement a
 * lieu au chargement de la configuration : un nouveau membre exige un reload.
 */
export function resolveUserList(value: string | undefined, db: UserDb): ListResolution {
  const raw = value?.trim() ?? "";
  if (!raw || /^[;#]/.test(raw)) return { defined: false, members: [], ignored: [] };
  const members = new Set<string>();
  const ignored: ListResolution["ignored"] = [];
  const ksmbd = new Set(db.ksmbdUsers);
  for (const entry of ksmbdList(raw)) {
    if (entry.startsWith("@")) {
      const g = db.groups[entry.slice(1)];
      if (!g) {
        ignored.push({ entry, reason: "groupe Unix inexistant" });
        continue;
      }
      const candidates = [
        ...Object.entries(db.unixUsers).filter(([, u]) => u.gid === g.gid).map(([n]) => n),
        ...g.members,
      ];
      const kept = candidates.filter((n) => ksmbd.has(n));
      for (const n of kept) members.add(n);
      const dropped = candidates.filter((n) => !ksmbd.has(n));
      if (dropped.length) ignored.push({ entry, reason: `membres sans compte ksmbd : ${[...new Set(dropped)].join(", ")}` });
      if (!kept.length) ignored.push({ entry, reason: "aucun membre avec compte ksmbd" });
    } else if (entry.startsWith("+") || entry.startsWith("&")) {
      ignored.push({ entry, reason: "syntaxe Samba non reconnue par ksmbd (utilisez @groupe)" });
    } else if (entry.includes("\\")) {
      ignored.push({ entry, reason: "compte de domaine : ksmbd n'a pas de winbind" });
    } else if (!ksmbd.has(entry)) {
      ignored.push({ entry, reason: "pas de compte ksmbd (ksmbd.adduser)" });
    } else {
      members.add(entry);
    }
  }
  return { defined: true, members: [...members], ignored };
}

// ------------------------------------------------------------------ connexion au partage

export type StepEffect = "pass" | "deny" | "ro" | "rw" | "bind" | "info" | "ignored";

export interface StackStep {
  label: string;
  param?: string;
  value?: string;
  effect: StepEffect;
  detail: string;
}

export interface ConnectContext {
  account: string;
  peerAddr: string;
  /** session invité / anonyme (utilisateur inconnu avec map to guest = bad user, ou null session) */
  guestSession?: boolean;
  /** mot de passe refusé */
  badPassword?: boolean;
}

export interface ConnectResult {
  status: "deny" | "ro" | "rw";
  guest: boolean;
  effectiveAccount: string | null;
  steps: StackStep[];
  warnings: string[];
}

export function evaluateTreeConnect(doc: IniDocument, shareName: string, ctx: ConnectContext, db: UserDb): ConnectResult {
  const eff = effectiveShare(doc, shareName);
  const steps: StackStep[] = [];
  const warnings: string[] = [];
  const v = (k: string) => eff[k]?.value ?? "";
  const res = (status: ConnectResult["status"], extra: Partial<ConnectResult> = {}): ConnectResult => ({
    status, guest: false, effectiveAccount: ctx.account, steps, warnings, ...extra,
  });

  if (!findSection(doc, shareName)) {
    steps.push({ label: "Partage", effect: "deny", detail: `Partage « ${shareName} » inexistant` });
    return res("deny", { effectiveAccount: null });
  }

  // 0. mot de passe
  const mapToGuest = globalValue(doc, "map to guest").toLowerCase();
  if (ctx.badPassword && !mapToGuest.startsWith("bad user")) {
    steps.push({ label: "Mot de passe", param: "map to guest", value: mapToGuest, effect: "deny", detail: "Mot de passe refusé et map to guest = never" });
    return res("deny");
  }

  // 1. drapeaux du partage
  const wm = writeMode(eff);
  const writable = wm.writable;
  steps.push({ label: "Mode du partage", param: wm.key, value: wm.value, effect: writable ? "rw" : "ro", detail: `Départ : ${writable ? "lecture-écriture" : "lecture seule"} (ordre : read only, puis writable, writeable, write ok ; chacun peut être hérité de [global])` });

  // 2. clés désactivées dans ksmbd-tools : aucun effet
  for (const b of brokenKeysPresent(doc, shareName)) {
    steps.push({ label: b.key, param: b.key, value: b.value, effect: "ignored", detail: `Ignoré par ksmbd-tools (KSMBD_SHARE_CONF_IS_BROKEN), défini dans ${b.where}` });
    warnings.push(b.key === "admin users"
      ? `admin users (${b.where}) n'a aucun effet dans ksmbd-tools.`
      : `${b.key} (${b.where}) n'a aucun effet dans ksmbd-tools : la restriction par adresse n'existe pas, filtrez au pare-feu ou avec bind interfaces only.`);
  }

  // 3. invités
  const guestOk = ksmbdBool(v("guest ok"));
  const ra = globalValue(doc, "restrict anonymous").trim();
  const restrictAnon = ra === "1" || ra === "2" ? Number(ra) : 0;
  if (ctx.guestSession) {
    if (restrictAnon >= 1 && !guestOk) {
      steps.push({ label: "Session anonyme", param: "restrict anonymous", value: String(restrictAnon), effect: "deny", detail: "Session invité refusée (restrict anonymous ≥ 1)" });
      return res("deny");
    }
    if (!guestOk) {
      steps.push({ label: "Invité", param: "guest ok", value: v("guest ok"), effect: "deny", detail: "Session invité et guest ok = no" });
      return res("deny");
    }
    const guestAccount = eff["guest account"]?.origin === "share" ? v("guest account") : globalValue(doc, "guest account");
    steps.push({ label: "Invité", param: "guest ok", value: "yes", effect: "bind", detail: `Connecté comme invité (${guestAccount}) ; les listes d'utilisateurs ne sont pas consultées` });
    if (!db.ksmbdUsers.includes(guestAccount) && !db.unixUsers[guestAccount]) warnings.push(`Compte invité « ${guestAccount} » introuvable.`);
    return res(writable ? "rw" : "ro", { guest: true, effectiveAccount: guestAccount });
  }

  // 4. l'utilisateur doit exister dans la base ksmbd
  if (!db.ksmbdUsers.includes(ctx.account)) {
    steps.push({ label: "Compte", effect: "deny", detail: `« ${ctx.account} » absent de ksmbdpwd.db (ksmbd.adduser -a ${ctx.account})` });
    return res("deny");
  }

  const lists: [string, string][] = [
    ["invalid users", "Utilisateurs refusés"],
    ["read list", "Liste lecture seule"],
    ["write list", "Liste écriture"],
    ["valid users", "Utilisateurs autorisés"],
  ];
  const resolved: Record<string, ListResolution> = {};
  for (const [key] of lists) {
    resolved[key] = resolveUserList(v(key), db);
    for (const ig of resolved[key]!.ignored) warnings.push(`${key} : ${ig.entry} ignoré (${ig.reason}).`);
    if (resolved[key]!.defined && !resolved[key]!.members.length && key === "valid users")
      warnings.push("valid users est défini mais ne contient aucun compte ksmbd valide : TOUT LE MONDE est refusé.");
  }
  const inList = (k: string) => resolved[k]!.members.includes(ctx.account);
  const show = (k: string) => v(k) || undefined;

  // 6. invalid users
  if (resolved["invalid users"]!.defined) {
    if (inList("invalid users")) {
      steps.push({ label: "Utilisateurs refusés", param: "invalid users", value: show("invalid users"), effect: "deny", detail: "Membre : refus" });
      return res("deny");
    }
    steps.push({ label: "Utilisateurs refusés", param: "invalid users", value: show("invalid users"), effect: "pass", detail: "Non membre" });
  }

  // 7. read list : lecture seule et fin de l'évaluation (valid users n'est PAS consulté)
  if (resolved["read list"]!.defined) {
    if (inList("read list")) {
      steps.push({ label: "Liste lecture seule", param: "read list", value: show("read list"), effect: "ro", detail: "Membre : lecture seule, accepté sans consulter write list ni valid users" });
      if (resolved["valid users"]!.defined && !inList("valid users"))
        warnings.push("Ce compte n'est pas dans valid users mais read list l'accepte quand même (ordre d'évaluation de ksmbd).");
      return res("ro");
    }
    steps.push({ label: "Liste lecture seule", param: "read list", value: show("read list"), effect: "pass", detail: "Non membre" });
  }

  // 8. write list : écriture et fin de l'évaluation
  if (resolved["write list"]!.defined) {
    if (inList("write list")) {
      steps.push({ label: "Liste écriture", param: "write list", value: show("write list"), effect: "rw", detail: "Membre : lecture-écriture, accepté sans consulter valid users" });
      if (resolved["valid users"]!.defined && !inList("valid users"))
        warnings.push("Ce compte n'est pas dans valid users mais write list l'accepte quand même (ordre d'évaluation de ksmbd).");
      return res("rw");
    }
    steps.push({ label: "Liste écriture", param: "write list", value: show("write list"), effect: "pass", detail: "Non membre" });
  }

  // 9. valid users
  if (resolved["valid users"]!.defined) {
    if (!inList("valid users")) {
      steps.push({ label: "Utilisateurs autorisés", param: "valid users", value: show("valid users"), effect: "deny", detail: "Non membre : refus" });
      return res("deny");
    }
    steps.push({ label: "Utilisateurs autorisés", param: "valid users", value: show("valid users"), effect: "pass", detail: "Membre" });
  }

  steps.push({ label: "Résultat", effect: "bind", detail: `Connexion acceptée en ${writable ? "lecture-écriture" : "lecture seule"} (mode du partage)` });
  return res(writable ? "rw" : "ro");
}

// ------------------------------------------------------------------ identité effective

export interface EffectiveIdentity {
  uid: string;
  gid: string;
  supplementary: string[];
  steps: StackStep[];
}

export function effectiveIdentity(doc: IniDocument, shareName: string, account: string, db: UserDb): EffectiveIdentity {
  const eff = effectiveShare(doc, shareName);
  const steps: StackStep[] = [];
  const unix = db.unixUsers[account];
  const primary = unix ? Object.entries(db.groups).find(([, g]) => g.gid === unix.gid)?.[0] ?? String(unix.gid) : "?";
  let uid = account;
  let gid = primary;
  const fu = eff["force user"]?.value ?? "";
  const fg = eff["force group"]?.value ?? "";
  steps.push({ label: "Identité de connexion", effect: "info", detail: `${account} (groupe primaire ${primary})` });
  if (fu) {
    uid = fu;
    const fuUnix = db.unixUsers[fu];
    if (!fg && fuUnix) gid = Object.entries(db.groups).find(([, g]) => g.gid === fuUnix.gid)?.[0] ?? String(fuUnix.gid);
    steps.push({ label: "force user", param: "force user", value: fu, effect: "info", detail: `UID effectif = ${fu}${!fg ? `, GID = groupe primaire de ${fu} (${gid})` : ""}` });
  }
  if (fg) {
    gid = fg;
    steps.push({ label: "force group", param: "force group", value: fg, effect: "info", detail: `GID effectif = ${fg}` });
  }
  const supplementary = Object.entries(db.groups).filter(([, g]) => g.members.includes(account)).map(([n]) => n);
  steps.push({ label: "Groupes secondaires", effect: "info", detail: supplementary.length ? `${supplementary.join(", ")} (ceux de ${account}, conservés même avec force user)` : "aucun" });
  return { uid, gid, supplementary, steps };
}

// ------------------------------------------------------------------ création d'objets

export interface CreateContext {
  kind: "file" | "dir";
  /** mode transmis par un client Linux (extensions POSIX SMB 3.1.1) ; absent = tous les bits */
  posixMode?: number;
  /** acltype=posixacl sur le dataset */
  posixAclFs: boolean;
  /** le dossier parent a une ACL POSIX par défaut */
  parentHasDefaultAcl: boolean;
  /** le dossier parent a une ACL NT avec des ACE héritables (acl_xattr) */
  parentHasInheritableNtAcl?: boolean;
  parentSetgid?: boolean;
  parentOwner?: string;
  parentGroup?: string;
  /**
   * umask des workers ksmbd (kworker sur init_fs). 0022 sur les noyaux récents ;
   * à lire sur le serveur : grep Umask /proc/$(pgrep -x kthreadd)/status
   */
  umask: number;
  /** le client envoie un descripteur de sécurité à la création (Explorateur avec ACL explicites) */
  clientSendsSecurityDescriptor?: boolean;
}

export interface CreateResult {
  /** bits du mode tels que calculés par le noyau à la création */
  mode: number;
  /** mode affiché par stat / ls quand une ACL avec masque est posée (bits groupe = masque) */
  statMode: number;
  /** droits effectifs par classe, si différents de statMode */
  effective?: string;
  owner: string;
  group: string;
  acl: string;
  steps: StackStep[];
  warnings: string[];
}

const oct = (n: number) => n.toString(8).padStart(4, "0");
const rwx = (bits: number) => `${bits & 4 ? "r" : "-"}${bits & 2 ? "w" : "-"}${bits & 1 ? "x" : "-"}`;

export function computeCreate(doc: IniDocument, shareName: string, account: string, db: UserDb, ctx: CreateContext): CreateResult {
  const eff = effectiveShare(doc, shareName);
  const steps: StackStep[] = [];
  const warnings: string[] = [];
  const isDir = ctx.kind === "dir";
  const maskKey = isDir ? "directory mask" : "create mask";
  const forceKey = isDir ? "force directory mode" : "force create mode";
  const mask = parseInt(eff[maskKey]!.value, 8) || 0;
  const force = parseInt(eff[forceKey]!.value, 8) || 0;
  const umask = ctx.umask;

  const requested = ctx.posixMode ?? 0o7777;
  steps.push({ label: "Mode demandé", effect: "info", detail: ctx.posixMode !== undefined ? `${oct(requested)} (client Linux, extensions POSIX)` : "tous les bits (client Windows / macOS : pas de mode POSIX)" });

  let mode = requested & mask;
  steps.push({ label: maskKey, param: maskKey, value: eff[maskKey]!.value, effect: "info", detail: `ET → ${oct(mode)} (${eff[maskKey]!.origin === "default" ? "valeur par défaut" : eff[maskKey]!.origin})` });
  mode |= force;
  steps.push({ label: forceKey, param: forceKey, value: eff[forceKey]!.value, effect: "info", detail: `OU → ${oct(mode)}` });

  if (isDir) {
    const before = mode;
    mode &= 0o1777; // vfs_mkdir : S_IRWXUGO | S_ISVTX
    if (before !== mode) {
      steps.push({ label: "vfs_mkdir", effect: "info", detail: `masque S_IRWXUGO|S_ISVTX : ${oct(before)} → ${oct(mode)} (le setgid demandé est perdu ; seul un parent setgid le transmet)` });
    }
  } else if (mode & 0o2000) {
    steps.push({ label: "setgid sur fichier", effect: "info", detail: "Retiré par le noyau si l'appelant n'est pas membre du groupe du fichier (mode_strip_sgid)" });
  }

  const ident = effectiveIdentity(doc, shareName, account, db);
  let owner = ident.uid;
  let group = ident.gid;

  let acl = "aucune";
  let initAcl = false;
  if (ctx.posixAclFs && ctx.parentHasDefaultAcl) {
    acl = "copie de l'ACL par défaut du parent (bornée par le mode calculé)";
    steps.push({ label: "ACL par défaut du parent", effect: "info", detail: `Le noyau copie l'ACL par défaut : l'umask est ignoré, chaque classe est bornée par ${oct(mode)}${isDir ? " ; le dossier hérite aussi de l'ACL par défaut" : ""}. Le mode final dépend du contenu de cette ACL.` });
  } else {
    const before = mode;
    mode &= ~umask;
    steps.push({ label: "umask des workers ksmbd", effect: "info", detail: `umask ${oct(umask)} appliqué (${ctx.posixAclFs ? "pas d'ACL par défaut sur le parent" : "acltype=off"}) : ${oct(before)} → ${oct(mode)}` });
    if (before & ~mode & 0o020) {
      warnings.push(`L'umask ${oct(umask)} des workers ksmbd retire l'écriture groupe : create mask / force create mode ne suffisent pas. ` +
        (ctx.posixAclFs ? "Posez une ACL par défaut sur la racine du partage (setfacl -d -m g::rwx …)." : "En acltype=off c'est inévitable avec ksmbd : passez le dataset en posixacl avec une ACL par défaut."));
    }
  }

  if (ctx.parentSetgid) {
    group = ctx.parentGroup ?? group;
    steps.push({ label: "setgid du parent", effect: "info", detail: `Groupe hérité du dossier parent (${group})${isDir ? ", et le nouveau dossier reçoit le bit setgid" : ""}` });
    if (isDir) mode |= 0o2000;
  }

  if (ksmbdBool(eff["inherit owner"]?.value)) {
    owner = ctx.parentOwner ?? "(propriétaire du parent)";
    steps.push({ label: "inherit owner", param: "inherit owner", value: "yes", effect: "info", detail: `UID repris du parent (${owner}) ; le groupe n'est pas changé. Fait par i_uid_write() sans notify_change : persistance non garantie sur tous les systèmes de fichiers.` });
  }

  const vfs = ksmbdList(eff["vfs objects"]?.value);
  const aclXattr = vfs.includes("acl_xattr");
  if (ctx.clientSendsSecurityDescriptor) {
    steps.push({ label: "Descripteur du client", effect: "info", detail: "Le descripteur envoyé par le client est appliqué (propriétaire, DACL → ACL POSIX, et security.NTACL si acl_xattr)" });
    acl = "selon le descripteur du client";
  } else if (aclXattr && ctx.parentHasInheritableNtAcl) {
    steps.push({ label: "Héritage NT (acl_xattr)", effect: "info", detail: "Les ACE héritables du security.NTACL parent sont propagées dans security.NTACL du nouvel objet" });
    acl = "ACL NT héritée du parent";
  } else {
    if (ctx.posixAclFs && !ctx.parentHasDefaultAcl) {
      initAcl = true;
      const u = (mode >> 6) & 7, g = (mode >> 3) & 7, o = mode & 7;
      acl = `user::${rwx(u)}, user:${owner}:${rwx(u)}, group::${rwx(g)}, group:${group}:${rwx(g)}, mask::rwx, other::${rwx(o)}` + (isDir ? " (+ la même en ACL par défaut)" : "");
      steps.push({ label: "ACL initiale (ksmbd_vfs_set_init_posix_acl)", effect: "info", detail: `ksmbd pose ${acl}. Le masque rwx est recopié dans les bits groupe du mode : stat affiche g=rwx et « + », mais les droits effectifs du groupe propriétaire restent ${rwx(g)} ; un chmod g+… ne modifiera que le masque.` });
    }
    if (aclXattr) {
      steps.push({ label: "security.NTACL", effect: "info", detail: "ksmbd écrit une ACL NT construite à partir des droits POSIX" });
    }
  }

  const statMode = initAcl ? (mode & ~0o070) | 0o070 : mode;
  const effective = initAcl ? `u=${rwx((mode >> 6) & 7)} g=${rwx((mode >> 3) & 7)} o=${rwx(mode & 7)}` : undefined;
  return { mode, statMode, effective, owner, group, acl, steps, warnings };
}

// ------------------------------------------------------------------ accès à un fichier existant

export function accessLayers(doc: IniDocument, shareName: string): StackStep[] {
  const eff = effectiveShare(doc, shareName);
  const vfs = ksmbdList(eff["vfs objects"]?.value);
  const steps: StackStep[] = [
    { label: "1. Connexion au partage", effect: "info", detail: "Résultat lecture seule → toute ouverture en écriture, suppression ou changement d'attribut est refusée, quels que soient les droits du fichier." },
    { label: "2. Identité effective", effect: "info", detail: "fsuid / fsgid = utilisateur (ou force user / force group) + groupes secondaires de l'utilisateur ; root seulement si l'UID effectif est 0." },
  ];
  if (vfs.includes("acl_xattr")) {
    steps.push({ label: "3. ACL NT (acl_xattr)", param: "vfs objects", value: eff["vfs objects"]!.value, effect: "info", detail: "Si security.NTACL existe, la DACL Windows est vérifiée (smb_check_perm_dacl) ; elle doit accorder l'accès demandé." });
  } else {
    steps.push({ label: "3. ACL NT", effect: "info", detail: "acl_xattr absent : pas de DACL stockée, l'ACL affichée à Windows est synthétisée depuis le mode / l'ACL POSIX." });
  }
  steps.push({ label: "4. Droits POSIX", effect: "info", detail: "Le noyau vérifie mode + ACL POSIX (masque compris) avec l'identité effective. Les couches 3 et 4 doivent toutes deux accorder l'accès." });
  if (ksmbdBool(eff["hide unreadable"]?.value)) steps.push({ label: "Listage", param: "hide unreadable", value: "yes", effect: "info", detail: "Les entrées illisibles sont masquées." });
  if (eff["veto files"]?.value) steps.push({ label: "Noms interdits", param: "veto files", value: eff["veto files"]!.value, effect: "info", detail: "Ces noms ne peuvent être ni ouverts ni créés." });
  return steps;
}
