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
 *  - Délégations NFSv4 : ce sont des baux noyau (fs/nfsd/nfs4state.c,
 *    kernel_setlease). ksmbd ouvre par dentry_open → do_dentry_open →
 *    break_lease (fs/open.c) : une ouverture SMB rappelle la délégation
 *    (attente jusqu'au retour du client NFS). Suppression / renommage SMB :
 *    vfs_unlink / vfs_rename sans delegated_inode → try_break_deleg non
 *    bloquant → -EWOULDBLOCK renvoyé au client SMB, qui réessaie.
 *  - Verrous de plage : ksmbd les pose en verrous POSIX noyau
 *    (smb2pdu.c smb2_lock → vfs_lock_file), visibles par les verrous NFS ;
 *    les lectures / écritures SMB respectent tout verrou POSIX, y compris
 *    ceux des clients NFS (vfs.c check_lock_range). Les E/S NFS ignorent les
 *    verrous (consultatifs).
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
export function overlappingExports(smbPath: string, exports: NFSExport[]): { export: NFSExport; relation: PathRelation }[] {
  if (!smbPath) return [];
  return exports
    .map((e) => ({ export: e, relation: pathRelation(smbPath, e.path) }))
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
}

export function analyzeDualProtocol(ctx: DualContext): DualFinding[] {
  const out: DualFinding[] = [];
  const shareSec = findSection(ctx.doc, ctx.share);
  if (!shareSec) return out;
  const eff = effectiveShare(ctx.doc, ctx.share);
  const v = (k: string) => eff[k]?.value ?? "";
  const smbPath = v("path");
  const rel = pathRelation(smbPath, ctx.nfsExport.path);
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
    out.push({ id: "oplocks", level: "info", title: "oplocks = no : cache client SMB désactivé", detail: "Chaque lecture / écriture SMB va au serveur : cohérent avec NFS, au prix de performances plus faibles pour les petits fichiers. Les poignées durables (reprise après coupure) ne sont plus accordées sur ce partage." });
  }
  out.push({
    id: "delegations",
    level: "info",
    title: "Délégations NFSv4 rappelées par les accès SMB",
    detail: "Les délégations NFS sont des baux noyau : une ouverture SMB les rappelle et attend la réponse du client NFS (jusqu'au délai lease-break-time). Une suppression ou un renommage SMB d'un fichier délégué échoue temporairement (-EWOULDBLOCK) le temps du rappel.",
    fix: "Si des ouvertures SMB se figent : désactiver les délégations (sysctl fs.leases-enable=0, effet sur tout le système). Aucun réglage nfsd dédié dans ce noyau.",
    ref: "fs/open.c do_dentry_open → break_lease ; include/linux/filelock.h try_break_deleg ; fs/locks.c leases_enable",
  });

  // 2. verrous et modes de partage
  out.push({
    id: "locks",
    level: "info",
    title: "Verrous de plage partagés",
    detail: "Les verrous SMB sont des verrous POSIX noyau, en conflit avec les verrous NFS. Les lectures / écritures SMB respectent les verrous NFS ; l'inverse n'est pas vrai (les E/S NFS ignorent les verrous, comme toujours sous Unix).",
    ref: "smb2pdu.c smb2_lock → vfs_lock_file ; vfs.c check_lock_range",
  });
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
  if (ksmbdBool(getValue(sec, "time machine"))) {
    setValue(sec, "time machine", "no");
    changes.push("time machine = no");
  }
  return changes;
}
