/**
 * Cohabitation d'un partage SMB ksmbd et d'un export NFSv4.1 sur le même
 * chemin (ou des chemins imbriqués).
 *
 * Conclusions tirées du code noyau (Linux 7.4-rc) :
 *
 *  - Oplocks / baux SMB : gérés en interne par ksmbd (fs/smb/server/oplock.c) ;
 *    aucun appel à vfs_setlease / kernel_setlease dans fs/smb/server. Une
 *    ouverture ou une écriture NFS ne casse donc JAMAIS le cache d'un client
 *    SMB → incohérence de données possible. « oplocks = no » sur le partage
 *    empêche l'octroi des oplocks ET des baux : smb2pdu.c smb2_open teste
 *    KSMBD_SHARE_FLAG_OPLOCKS et n'appelle alors pas smb_grant_oplock.
 *  - Poignées durables (« durable handles = yes » dans [global]) : dans
 *    smb2_open, parse_durable_handle_context s'exécute AVANT le test de
 *    KSMBD_SHARE_FLAG_OPLOCKS et ne regarde que la requête du client
 *    (SMB2_OPLOCK_LEVEL_BATCH ou bail avec SMB2_LEASE_HANDLE_CACHING_LE), puis
 *    smb2_open pose fp->is_durable = 1 même sans smb_grant_oplock (opinfo ==
 *    NULL). À la reconnexion, smb2_check_durable_oplock renvoie 0 dès que
 *    opinfo_get(fp) == NULL : oplocks = no n'empêche donc ni l'octroi ni la
 *    reconnexion d'une poignée durable, qui garde le fichier ouvert 60 à 300 s
 *    après coupure (modes de partage et verrous POSIX compris).
 *  - Délégations NFSv4 : ce sont des baux noyau (fs/nfsd/nfs4state.c,
 *    kernel_setlease). ksmbd ouvre avec O_NONBLOCK (smb2pdu.c smb2_open :
 *    « oflags = O_NONBLOCK | O_LARGEFILE ») : __break_lease lance le rappel
 *    puis renvoie -EWOULDBLOCK SANS attendre ; en 6.12 l'erreur n'est pas
 *    traduite et le client reçoit STATUS_UNEXPECTED_IO_ERROR (7.4 :
 *    STATUS_FILE_NOT_AVAILABLE). Cas : ouverture SMB en écriture d'un fichier
 *    délégué en lecture, toute ouverture d'un fichier délégué en écriture.
 *    lease-break-time ne s'applique pas (nfsd_break_deleg_cb met
 *    fl_break_time = 0).
 *  - Suppression à la fermeture (delete-on-close) : __ksmbd_inode_close →
 *    ksmbd_vfs_unlink → vfs_unlink(..., NULL) → -EWOULDBLOCK, consigné
 *    seulement en debug, la fermeture répond succès : le fichier « revient ».
 *  - Renommage / setattr : ksmbd_vfs_rename et notify_change sans
 *    delegated_inode → -EAGAIN → STATUS_FILE_LOCK_CONFLICT (smb2_set_info),
 *    sans nouvel essai automatique connu côté Windows.
 *  - Seul remède : sysctl fs.leases-enable=0 (fs/locks.c generic_add_lease :
 *    refuse les NOUVEAUX baux, donc les délégations nfsd, les layouts pNFS et
 *    F_SETLEASE ; global à l'hôte ; à poser avant nfsd puis redémarrer
 *    nfs-server). Aucun réglage nfsd dédié.
 *  - NFSv3 : pas de délégations, mais verrous NLM = verrous POSIX
 *    (fs/lockd/svclock.c → vfs_lock_file) : mêmes interactions avec ksmbd.
 *  - Verrous de plage : ksmbd les pose en verrous POSIX noyau
 *    (smb2pdu.c smb2_lock → vfs_lock_file), visibles par les verrous NFS ;
 *    les lectures / écritures SMB respectent tout verrou POSIX, y compris
 *    ceux des clients NFS (vfs.c check_lock_range) : un verrou PARTAGÉ posé
 *    par NFS ou un processus local bloque toute écriture SMB sur la plage
 *    (échec immédiat STATUS_FILE_LOCK_CONFLICT, pr_err par E/S refusée).
 *    Les E/S NFS ignorent les verrous (consultatifs).
 *  - Modes de partage (deny read / deny write) : liste interne à ksmbd
 *    (smb_common.c ksmbd_smb_check_shared_mode) ; les « deny » NFSv4 sont
 *    internes à nfsd (nfs4state.c st_deny_bmap). Aucune exclusion croisée.
 *  - acl_xattr : la DACL de security.NTACL n'est vérifiée que par ksmbd
 *    (smbacl.c smb_check_perm_dacl) ; knfsd ne voit que mode + ACL POSIX,
 *    traduits en ACL NFSv4 (fs/nfsd/nfs4acl.c nfsd4_get_nfs4_acl).
 *  - Samba avait « kernel oplocks » / « kernel share modes » (baux et flock
 *    noyau) qui assuraient une cohabitation partielle ; ksmbd n'a aucun
 *    équivalent.
 */
import type { NFSExport } from "@/tabs/nfs/data-types";
import { findSection, getValue, setValue, deleteValue, type IniDocument } from "@/tabs/ksmbd/ini";
import { effectiveShare, globalValue, writeMode, type UserDb } from "@/tabs/ksmbd/permission-stack";
import { ksmbdBool, ksmbdList } from "@/tabs/ksmbd/ksmbd-params";

export type DualLevel = "info" | "warning" | "danger";

export interface DualFinding {
  id: string;
  level: DualLevel;
  title: string;
  detail: string;
  fix?: string;
  ref?: string;
}

export type PathRelation = "same" | "nfs-parent" | "smb-parent" | "none";

/** Commande et fichier sysctl à proposer pour un serveur double protocole. */
export const LEASES_SYSCTL = {
  file: "/etc/sysctl.d/99-nfs-ksmbd.conf",
  content: "fs.leases-enable = 0\n",
  commands: [
    "echo 'fs.leases-enable = 0' > /etc/sysctl.d/99-nfs-ksmbd.conf",
    "sysctl -p /etc/sysctl.d/99-nfs-ksmbd.conf",
    "systemctl restart nfs-server   # les délégations déjà accordées restent jusqu'au redémarrage",
  ],
};

export function normPath(p: string): string {
  const n = ("/" + p.trim()).replace(/\/+/g, "/").replace(/\/$/, "");
  return n || "/";
}

export function pathRelation(smbPath: string, nfsPath: string): PathRelation {
  const a = normPath(smbPath);
  const b = normPath(nfsPath);
  if (a === b) return "same";
  if (a.startsWith(b === "/" ? "/" : b + "/")) return "nfs-parent";
  if (b.startsWith(a === "/" ? "/" : a + "/")) return "smb-parent";
  return "none";
}

/** Exports NFS qui recoupent le chemin d'un partage ksmbd. */
/**
 * @param resolve chemin résolu côté serveur (readlink -f) ; à défaut, la
 *                chaîne normalisée (un lien symbolique échapperait au rapprochement).
 */
export function overlappingExports(smbPath: string, exports: NFSExport[], resolve: (p: string) => string = (p) => p): { export: NFSExport; relation: PathRelation }[] {
  if (!smbPath) return [];
  return exports
    .map((e) => ({ export: e, relation: pathRelation(resolve(smbPath), resolve(e.path)) }))
    .filter((x) => x.relation !== "none");
}

function exportOptionSets(e: NFSExport): { host: string; opts: string[] }[] {
  const split = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);
  const def = split(e.defaultClientSettings);
  if (!e.clients.length) return [{ host: "*", opts: def }];
  return e.clients.map((c) => ({ host: c.host, opts: [...def, ...split(c.settings)] }));
}

const optVal = (opts: string[], key: string) => {
  let v: string | undefined;
  for (const o of opts) if (o.startsWith(key + "=")) v = o.slice(key.length + 1);
  return v;
};

export interface DualContext {
  /** document ksmbd (saveur ksmbd) */
  doc: IniDocument;
  share: string;
  nfsExport: NFSExport;
  db?: UserDb;
  /** la racine du partage a une ACL POSIX par défaut (sonde serveur) */
  rootHasDefaultAcl?: boolean;
  /** umask des workers ksmbd (sonde) */
  workerUmask?: string;
  /** /proc/sys/fs/leases-enable (undefined = inconnu, supposé actif) */
  leasesEnable?: boolean;
  /** NFSv3 servi (versions globales) */
  nfsV3?: boolean;
  /** NFSv4 servi */
  nfsV4?: boolean;
  /** résolution des chemins côté serveur */
  resolve?: (p: string) => string;
}

export function analyzeDualProtocol(ctx: DualContext): DualFinding[] {
  const out: DualFinding[] = [];
  const shareSec = findSection(ctx.doc, ctx.share);
  if (!shareSec) return out;
  const eff = effectiveShare(ctx.doc, ctx.share);
  const v = (k: string) => eff[k]?.value ?? "";
  const smbPath = v("path");
  const res = ctx.resolve ?? ((p: string) => p);
  const rel = pathRelation(res(smbPath), res(ctx.nfsExport.path));
  const v4 = ctx.nfsV4 ?? true;
  const v3 = ctx.nfsV3 ?? true;
  const leasesOn = ctx.leasesEnable !== false;
  if (rel === "none") return out;
  const where = rel === "same" ? "même chemin" : rel === "nfs-parent" ? `l'export ${ctx.nfsExport.path} contient le partage` : `le partage contient l'export ${ctx.nfsExport.path}`;

  // 1. cache client : oplocks / baux
  const oplocks = v("oplocks") ? ksmbdBool(v("oplocks")) : true;
  const leases = ksmbdBool(globalValue(ctx.doc, "smb2 leases"));
  if (oplocks) {
    out.push({
      id: "oplocks",
      level: "danger",
      title: "Cache client SMB non coordonné avec NFS",
      detail: `${where} : ksmbd accorde des oplocks${leases ? " et des baux SMB2" : ""} qu'il gère en interne, sans bail noyau. Une écriture faite par un client NFS ne rappelle pas le cache d'un client SMB : il peut lire des données périmées ou écraser les modifications NFS à la fermeture.`,
      fix: "oplocks = no sur ce partage (bloque oplocks ET baux pour ce partage seulement ; smb2 leases peut rester actif ailleurs).",
      ref: "fs/smb/server/oplock.c (pas de vfs_setlease) ; smb2pdu.c smb2_open (KSMBD_SHARE_FLAG_OPLOCKS)",
    });
  } else {
    out.push({ id: "oplocks", level: "info", title: "oplocks = no : cache client SMB désactivé", detail: "Chaque lecture / écriture SMB va au serveur : cohérent avec NFS, au prix de performances plus faibles pour les petits fichiers." });
  }
  if (ksmbdBool(globalValue(ctx.doc, "durable handles"))) {
    out.push({
      id: "durable",
      level: "warning",
      title: "Poignées durables actives",
      detail: "Accordées selon la demande du client, indépendamment de oplocks = no (parse_durable_handle_context s'exécute avant le test d'oplocks et smb2_check_durable_oplock accepte la reconnexion quand opinfo == NULL) : après une coupure, une poignée orpheline garde le fichier ouvert au moins 60 s (jusqu'à 300 s, modes de partage et verrous POSIX compris), ce qui peut bloquer un client NFS ou SMB.",
      fix: "durable handles = no dans [global] (ou retirer la clé, désactivée par défaut).",
      ref: "fs/smb/server/smb2pdu.c smb2_open, parse_durable_handle_context ; oplock.c smb2_check_durable_oplock",
    });
  }
  out.push({ id: "attrcache", level: "info", title: "Caches d'attributs non couverts", detail: "oplocks = no ne couvre ni le cache d'attributs NFS (actimeo, cohérence garantie seulement fermeture → ouverture) ni le cache de métadonnées du client Windows (~10 s) : un changement fait d'un côté peut mettre quelques secondes à apparaître de l'autre. Le change attribute NFSv4 sur ZFS repose sur ctime (granularité possiblement grossière en 6.12, non vérifié)." });

  if (v4) {
    if (leasesOn) {
      out.push({
        id: "delegations",
        level: "warning",
        title: "Délégations NFSv4 : ouvertures SMB en échec",
        detail: "ksmbd ouvre en O_NONBLOCK : face à une délégation NFS, le rappel est lancé mais l'ouverture échoue aussitôt (-EWOULDBLOCK) au lieu d'attendre. En 6.12 le client SMB reçoit STATUS_UNEXPECTED_IO_ERROR (7.4 : STATUS_FILE_NOT_AVAILABLE). Touche toute ouverture SMB en écriture d'un fichier délégué en lecture, et toute ouverture d'un fichier délégué en écriture. Renommage et changement d'attributs : STATUS_FILE_LOCK_CONFLICT, sans nouvel essai automatique côté Windows. lease-break-time ne s'applique pas (nfsd fixe fl_break_time à 0).",
        fix: `sysctl fs.leases-enable=0 sur ce serveur (persistant : ${LEASES_SYSCTL.file}), à poser AVANT nfsd puis systemctl restart nfs-server. Global à l'hôte : coupe aussi les layouts pNFS et F_SETLEASE. Aucun réglage nfsd dédié.`,
        ref: "smb2pdu.c smb2_open (O_NONBLOCK) ; fs/locks.c __break_lease, generic_add_lease ; fs/nfsd/nfs4state.c nfsd_break_deleg_cb",
      });
      out.push({
        id: "deleteonclose",
        level: "danger",
        title: "Suppression SMB d'un fichier délégué : échec silencieux",
        detail: "Une suppression SMB (delete-on-close, l'Explorateur et la plupart des applications) d'un fichier qu'un client NFS a en délégation échoue dans vfs_unlink (-EWOULDBLOCK), n'est consignée qu'en debug, et la fermeture répond « succès » : le fichier « revient ».",
        fix: `fs.leases-enable=0 (${LEASES_SYSCTL.file}) puis systemctl restart nfs-server.`,
        ref: "fs/smb/server/vfs_cache.c __ksmbd_inode_close → vfs.c ksmbd_vfs_unlink → vfs_unlink(..., NULL)",
      });
    } else {
      out.push({ id: "delegations", level: "info", title: "Délégations NFSv4 désactivées (fs.leases-enable=0)", detail: "Pas de conflit délégation / ksmbd. Les délégations accordées avant le réglage disparaissent au redémarrage de nfs-server." });
    }
  }

  // 2. verrous et modes de partage
  out.push({
    id: "locks",
    level: "warning",
    title: "Verrous de plage partagés",
    detail: `Les verrous SMB sont des verrous POSIX noyau, en conflit avec les verrous NFS${v3 ? " (y compris NLM des clients NFSv3)" : ""}. Les lectures / écritures SMB respectent les verrous NFS : un verrou même PARTAGÉ posé par un client NFS ou un processus local bloque toute écriture SMB sur la plage (échec immédiat STATUS_FILE_LOCK_CONFLICT, un message noyau par E/S refusée, qui peut inonder dmesg). L'inverse n'est pas vrai : les E/S NFS ignorent les verrous.`,
    ref: `smb2pdu.c smb2_lock → vfs_lock_file ; vfs.c check_lock_range${v3 ? " ; fs/lockd/svclock.c nlmsvc_lock → vfs_lock_file" : ""}`,
  });
  if (v3) {
    out.push({ id: "nlm", level: "info", title: "NFSv3 : pas de délégations, mais NLM", detail: "Les clients v3 n'ont pas de délégations (le risque de cache SMB non rappelé reste : oplocks = no toujours nécessaire) ; leurs verrous passent par lockd / NLM et statd, en conflit avec les verrous SMB comme ci-dessus. Après un redémarrage du serveur, la période de grâce ne concerne que lockd / nfsd : ksmbd ne la respecte pas, un client SMB peut donc prendre un verrou qu'un client NFS cherche à récupérer.", ref: "fs/lockd/svclock.c locks_in_grace (aucune vérification équivalente dans fs/smb/server)" });
  }
  out.push({
    id: "sharemodes",
    level: "warning",
    title: "Modes de partage SMB invisibles pour NFS",
    detail: "Un document ouvert par Office via SMB (refus d'écriture aux autres) reste modifiable par un client NFS, et les « deny » NFSv4 ne bloquent pas SMB.",
    fix: "Organiser les dossiers pour qu'un même fichier ne soit pas édité simultanément par les deux protocoles.",
    ref: "smb_common.c ksmbd_smb_check_shared_mode ; fs/nfsd/nfs4state.c st_deny_bmap",
  });

  // 3. ACL
  const vfs = ksmbdList(v("vfs objects"));
  if (vfs.includes("acl_xattr")) {
    out.push({
      id: "acl_xattr",
      level: "danger",
      title: "acl_xattr : droits différents selon le protocole",
      detail: "La DACL Windows (security.NTACL) n'est vérifiée que par ksmbd ; un client NFS n'obéit qu'au mode et à l'ACL POSIX. Un refus posé depuis l'onglet Sécurité de Windows n'empêche rien en NFS, et les fichiers créés en NFS n'ont pas de DACL stockée.",
      fix: "Retirer acl_xattr de vfs objects sur ce partage et gérer les droits en ACL POSIX (visibles en ACL NFSv4 par les clients NFS) ; effacer les security.NTACL existants (cockpit-zfs → Permissions → « Effacer les ACL NT »).",
      ref: "fs/smb/server/smbacl.c smb_check_perm_dacl ; fs/nfsd/nfs4acl.c nfsd4_get_nfs4_acl",
    });
  } else {
    out.push({ id: "acl_xattr", level: "info", title: "ACL POSIX communes", detail: "Sans acl_xattr, SMB et NFS appliquent les mêmes droits POSIX ; knfsd les présente aux clients en ACL NFSv4 (nfs4_getfacl). Une ACL NFSv4 non traduisible en POSIX est refusée par le serveur (EINVAL).", ref: "fs/nfsd/nfs4acl.c nfs4_acl_nfsv4_to_posix" });
  }

  // 4. xattrs SMB
  if (vfs.includes("streams_xattr") || ksmbdBool(v("store dos attributes") || "yes")) {
    out.push({
      id: "xattrs",
      level: "info",
      title: "Flux et attributs DOS invisibles en NFSv4.1",
      detail: `${vfs.includes("streams_xattr") ? "Les flux nommés (métadonnées macOS, Zone.Identifier) " : ""}${vfs.includes("streams_xattr") ? "et " : ""}user.DOSATTRIB sont des xattrs « user. » : NFSv4.1 ne les transporte pas (seul NFSv4.2 gère les xattrs, RFC 8276). Un renommage NFS les conserve, une copie faite par un client NFS les perd.`,
    });
  }
  if (ksmbdBool(v("time machine"))) {
    out.push({ id: "timemachine", level: "warning", title: "Time Machine sur un partage double protocole", detail: "Time Machine exige baux et poignées durables ; avec oplocks = no il ne fonctionnera pas. Gardez la cible Time Machine sur un partage SMB seul." });
  }

  // 5. identités
  const fu = v("force user");
  const fg = v("force group");
  const sets = exportOptionSets(ctx.nfsExport);
  const squashAll = sets.every((s) => s.opts.includes("all_squash"));
  if (fu || fg) {
    const fuUid = fu && ctx.db?.unixUsers[fu]?.uid;
    const consistent = squashAll && sets.every((s) => !fu || optVal(s.opts, "anonuid") === String(fuUid));
    out.push({
      id: "force",
      level: consistent ? "info" : "warning",
      title: consistent ? "force user cohérent avec all_squash" : "force user / force group : propriétaires divergents",
      detail: consistent
        ? `Les deux protocoles créent les fichiers sous ${fu}.`
        : `En SMB, tout est créé sous ${fu || "(utilisateur)"}:${fg || "(groupe)"} ; en NFS sous l'UID du client (ou nobody avec root_squash). Les droits POSIX peuvent alors bloquer l'un ou l'autre protocole.`,
      fix: consistent ? undefined : `Côté NFS : all_squash,anonuid=${fuUid ?? "<uid de " + (fu || "force user") + ">"}${fg && ctx.db?.groups[fg] ? `,anongid=${ctx.db.groups[fg]!.gid}` : ""} — ou retirer force user et compter sur une ACL par défaut.`,
    });
  }
  if (sets.some((s) => s.opts.includes("no_root_squash"))) {
    out.push({ id: "rootsquash", level: "warning", title: "no_root_squash", detail: "root d'un client NFS peut modifier tous les fichiers du partage SMB, y compris les ACL." });
  }
  if (ksmbdBool(v("inherit owner"))) {
    out.push({ id: "inheritowner", level: "info", title: "inherit owner : SMB seulement", detail: "En NFS, le propriétaire reste l'UID du client ; seul le groupe suit setgid." });
  }

  // 6. création : umask / ACL par défaut
  if (ctx.rootHasDefaultAcl) {
    out.push({ id: "umask", level: "info", title: "ACL par défaut présente", detail: "Les fichiers créés par SMB et par NFS reçoivent la même ACL héritée ; l'umask des deux côtés est ignoré." });
  } else {
    out.push({
      id: "umask",
      level: "warning",
      title: "Modes de création différents selon le protocole",
      detail: `Sans ACL par défaut : en SMB, create mask / directory mask puis l'umask des workers ksmbd (${ctx.workerUmask ?? "0022"}) ; en NFS, l'umask de chaque client (souvent 0022 ou 0002). Le même utilisateur obtient des droits différents.`,
      fix: "Poser une ACL par défaut sur la racine (setfacl -d -m u::rwx,g::rwx,o::---) et setgid sur les dossiers (cockpit-zfs → Permissions → Modèle d'ACL).",
      ref: "fs/namei.c vfs_prepare_mode ; fs/posix_acl.c posix_acl_create",
    });
  }

  // 7. accès
  const smbRw = writeMode(eff).writable;
  const nfsRw = sets.some((s) => s.opts.includes("rw"));
  if (smbRw !== nfsRw) {
    out.push({ id: "rw", level: "info", title: "Lecture seule d'un seul côté", detail: `SMB : ${smbRw ? "écriture" : "lecture seule"} ; NFS : ${nfsRw ? "écriture (rw)" : "lecture seule (ro)"}.` });
  }
  if (v("veto files")) {
    out.push({ id: "veto", level: "info", title: "veto files : SMB seulement", detail: "Les clients NFS peuvent créer ces noms ; ils resteront inaccessibles en SMB." });
  }
  return out;
}

/**
 * Applique en mémoire les réglages recommandés pour un partage double
 * protocole. Renvoie la liste des changements effectués.
 */
export function applyDualProtocolRecommendations(doc: IniDocument, share: string): string[] {
  const sec = findSection(doc, share);
  if (!sec) return [];
  const changes: string[] = [];
  if (getValue(sec, "oplocks") !== "no") {
    setValue(sec, "oplocks", "no");
    changes.push("oplocks = no");
  }
  const eff = effectiveShare(doc, share);
  const vfsEff = eff["vfs objects"];
  const vfs = ksmbdList(vfsEff?.value);
  if (vfs.includes("acl_xattr")) {
    const rest = vfs.filter((x) => x !== "acl_xattr");
    if (rest.length) {
      setValue(sec, "vfs objects", rest.join(" "));
      changes.push(`vfs objects = ${rest.join(" ")} (acl_xattr retiré${vfsEff?.origin === "global" ? ", valeur de [global] surchargée" : ""})`);
    } else if (vfsEff?.origin === "share") {
      // une valeur vide est ignorée par ksmbd-tools : on supprime la clé
      deleteValue(sec, "vfs objects");
      changes.push("vfs objects retiré (acl_xattr)");
      if (ksmbdList(getValue(findSection(doc, "global"), "vfs objects")).includes("acl_xattr")) {
        changes.push("ATTENTION : [global] définit aussi vfs objects = acl_xattr, hérité par ce partage : retirez-le de [global]");
      }
    } else {
      changes.push("acl_xattr vient de [global] et ne peut pas être annulé par une valeur vide : retirez-le de [global]");
    }
  }
  if (ksmbdBool(effectiveShare(doc, share)["time machine"]?.value)) {
    setValue(sec, "time machine", "no");
    changes.push(ksmbdBool(getValue(findSection(doc, "global"), "time machine")) ? "time machine = no (surcharge la valeur héritée de [global])" : "time machine = no");
  }
  if (ksmbdBool(globalValue(doc, "durable handles"))) {
    changes.push("ATTENTION : [global] définit durable handles = yes (accordé même avec oplocks = no) : passez-le à no dans [global] si aucun partage n'en a besoin");
  }
  changes.push(`Hors plugin (à confirmer) : fs.leases-enable=0 — ${LEASES_SYSCTL.commands.join(" ; ")}`);
  return changes;
}
