import { suite, test, expect } from "vitest";
import { parseIni, serializeIni, getValue, findSection } from "./ini";
import { ksmbdBool, ksmbdOpt, ksmbdSize, findParam, findParamExact, defaultFor } from "./ksmbd-params";
import { evaluateTreeConnect, computeCreate, effectiveIdentity, effectiveShare, writeMode, resolveUserList, type UserDb } from "./permission-stack";
import { convertSambaToKsmbd, mergeSambaSources, defaultConversionOptions } from "./samba-to-ksmbd";

const db: UserDb = {
  ksmbdUsers: ["alice", "bob", "carol", "dave", "nobody"],
  unixUsers: {
    alice: { uid: 1000, gid: 1000 },
    bob: { uid: 1001, gid: 1001 },
    carol: { uid: 1002, gid: 2000 },
    dave: { uid: 1003, gid: 1003 },
    erin: { uid: 1004, gid: 2000 },
    share: { uid: 900, gid: 900 },
    nobody: { uid: 65534, gid: 65534 },
  },
  groups: {
    alice: { gid: 1000, members: [] },
    bob: { gid: 1001, members: [] },
    staff: { gid: 2000, members: ["alice"] },
    dave: { gid: 1003, members: [] },
    share: { gid: 900, members: [] },
    nogroup: { gid: 65534, members: [] },
  },
};

const K = (t: string) => parseIni(t, "ksmbd");

suite("ini", () => {
  test("samba : continuation, commentaires, global implicite, dernière occurrence", () => {
    const doc = parseIni("workgroup = X\n; c\n[data]\n path = /tank/data\n valid users = a \\\n  b\n read only = yes\nreadonly = no\n");
    expect(getValue(findSection(doc, "global"), "workgroup")).toBe("X");
    expect(getValue(findSection(doc, "data"), "valid users")).toBe("a    b");
    expect(getValue(findSection(doc, "data"), "read only")).toBe("no");
    expect(serializeIni(doc)).toContain("[data]");
  });
  test("ksmbd : première occurrence, valeur vide ignorée", () => {
    const doc = K("[s]\nvalid users =\nread only = yes\nread only = no\nvalid users = bob\n");
    expect(getValue(findSection(doc, "s"), "read only")).toBe("yes");
    expect(getValue(findSection(doc, "s"), "valid users")).toBe("bob");
  });
  test("ksmbd : « readonly » n'est pas « read only »", () => {
    const doc = K("[s]\nreadonly = yes\n");
    expect(getValue(findSection(doc, "s"), "read only")).toBeUndefined();
    expect(getValue(findSection(doc, "s"), "READONLY")).toBe("yes");
  });
  test("ksmbd : valeur coupée au « ; » / « # », pas de continuation, lignes invalides signalées", () => {
    const doc = K("orphan = 1\n[s]\nveto files = /.DS_Store/#recycle/\ncomment = a ; b\npath = /x \\\nsuite sans egal\n");
    const s = findSection(doc, "s");
    expect(getValue(s, "veto files")).toBe("/.DS_Store/");
    expect(getValue(s, "comment")).toBe("a");
    expect(getValue(s, "path")).toBe("/x \\");
    expect(doc.truncated!.map((t) => t.key)).toEqual(["veto files", "comment"]);
    expect(doc.errors!.map((e) => e.line)).toEqual([1, 6]);
  });
});

suite("valeurs ksmbd-tools", () => {
  test("booléens par préfixe", () => {
    expect(ksmbdBool("yes")).toBe(true);
    expect(ksmbdBool("enabled")).toBe(true);
    expect(ksmbdBool("on")).toBe(false);
    expect(ksmbdBool("True")).toBe(true);
  });
  test("options à 4 états", () => {
    expect(ksmbdOpt("required")).toBe("disabled");
    expect(ksmbdOpt("mandatory")).toBe("mandatory");
    expect(ksmbdOpt("yes")).toBe("disabled");
  });
  test("tailles", () => {
    expect(ksmbdSize("8MB")).toBe(8 * 1024 * 1024);
    expect(ksmbdSize("4k")).toBe(4096);
  });
  test("catalogue : alias Samba absents, synonymes séparés, défaut selon la portée", () => {
    expect(findParam("create mode")).toBeUndefined();
    expect(findParamExact("writeable")?.key).toBe("writeable");
    expect(findParamExact("readonly")).toBeUndefined();
    const mc = findParamExact("max connections")!;
    expect(defaultFor(mc, "global")).toBe("256");
    expect(defaultFor(mc, "share")).toBe("128");
    expect(findParamExact("hosts allow")!.ignored).toContain("IS_BROKEN");
  });
});

suite("listes d'utilisateurs", () => {
  test("@groupe : primaires + secondaires, filtrés par la base ksmbd", () => {
    const r = resolveUserList("@staff", db);
    expect(r.members.sort()).toEqual(["alice", "carol"]);
    expect(r.ignored[0]!.reason).toContain("erin");
  });
  test("syntaxe +groupe signalée", () => {
    expect(resolveUserList("+staff", db).ignored[0]!.reason).toContain("Samba");
  });
});

const conf = `
[global]
  map to guest = bad user
  read only = no
[data]
  path = /tank/data
  admin users = dave
  invalid users = dave carol
  read list = bob
  write list = bob alice
  valid users = alice
  hosts allow = 192.168.1.10
[public]
  path = /tank/pub
  guest ok = yes
  read only = yes
[locked]
  path = /tank/l
  valid users = @share
`;

suite("empilement à la connexion", () => {
  const doc = K(conf);
  const ip = "192.168.1.10";
  test("admin users ignoré : invalid users s'applique", () => {
    const r = evaluateTreeConnect(doc, "data", { account: "dave", peerAddr: ip }, db);
    expect(r.status).toBe("deny");
    expect(r.steps.some((s) => s.param === "admin users" && s.effect === "ignored")).toBe(true);
    expect(r.warnings.join(" ")).toContain("admin users");
  });
  test("hosts allow ignoré : une IP absente passe quand même", () => {
    const r = evaluateTreeConnect(doc, "data", { account: "alice", peerAddr: "10.9.9.9" }, db);
    expect(r.status).toBe("rw");
    expect(r.warnings.join(" ")).toContain("pare-feu");
  });
  test("invalid users refuse", () => {
    expect(evaluateTreeConnect(doc, "data", { account: "carol", peerAddr: ip }, db).status).toBe("deny");
  });
  test("read list prime sur write list et ignore valid users", () => {
    const r = evaluateTreeConnect(doc, "data", { account: "bob", peerAddr: ip }, db);
    expect(r.status).toBe("ro");
    expect(r.warnings.join(" ")).toContain("valid users");
  });
  test("write list", () => {
    expect(evaluateTreeConnect(doc, "data", { account: "alice", peerAddr: ip }, db).status).toBe("rw");
  });
  test("read only en [global] sert de défaut", () => {
    const r = evaluateTreeConnect(doc, "public", { account: "alice", peerAddr: ip, guestSession: true }, db);
    expect(r.status).toBe("ro");
    expect(r.guest).toBe(true);
  });
  test("valid users vide après résolution : tout le monde refusé", () => {
    const r = evaluateTreeConnect(doc, "locked", { account: "alice", peerAddr: ip }, db);
    expect(r.status).toBe("deny");
    expect(r.warnings.join(" ")).toContain("TOUT LE MONDE");
  });
  test("compte absent de la base ksmbd", () => {
    expect(evaluateTreeConnect(doc, "data", { account: "erin", peerAddr: ip }, db).status).toBe("deny");
  });
  test("restrict anonymous : seules 1 et 2 comptent", () => {
    const d = K("[global]\nrestrict anonymous = 3\n[p]\npath = /p\nguest ok = no\n");
    const r = evaluateTreeConnect(d, "p", { account: "x", peerAddr: ip, guestSession: true }, db);
    expect(r.steps.at(-1)!.label).toBe("Invité");
  });
  test("synonymes hérités clé par clé (writable global prime sur writeable du partage)", () => {
    const d = K("[global]\nwritable = no\n[s]\npath = /s\nwriteable = yes\n");
    const eff = effectiveShare(d, "s");
    expect(eff["writable"]!.origin).toBe("global");
    expect(writeMode(eff)).toMatchObject({ writable: false, key: "writable" });
  });
  test("sans read only ni writable : lecture seule", () => {
    expect(writeMode(effectiveShare(K("[s]\npath = /s\n"), "s")).writable).toBe(false);
  });
});

suite("identité et création", () => {
  const doc = K(`[s]\n path = /tank/s\n force user = share\n create mask = 0664\n force create mode = 0060\n directory mask = 2775\n force directory mode = 2000\n inherit owner = yes\n vfs objects = acl_xattr streams_xattr\n`);
  test("force user garde les groupes secondaires", () => {
    const id = effectiveIdentity(doc, "s", "alice", db);
    expect(id.uid).toBe("share");
    expect(id.gid).toBe("share");
    expect(id.supplementary).toEqual(["staff"]);
  });
  test("umask sans ACL par défaut retire g+w (valeur fournie, pas codée en dur)", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "file", posixAclFs: false, parentHasDefaultAcl: false, umask: 0o022 });
    expect(r.mode).toBe(0o644);
    expect(r.warnings[0]).toContain("umask");
    const r0 = computeCreate(doc, "s", "alice", db, { kind: "file", posixAclFs: false, parentHasDefaultAcl: false, umask: 0 });
    expect(r0.mode).toBe(0o664);
  });
  test("ACL par défaut du parent : pas d'umask", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "file", posixAclFs: true, parentHasDefaultAcl: true, umask: 0o022 });
    expect(r.mode).toBe(0o664);
  });
  test("vfs_mkdir retire le setgid de force directory mode", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "dir", posixAclFs: true, parentHasDefaultAcl: true, umask: 0o022 });
    expect(r.mode & 0o2000).toBe(0);
  });
  test("dossier : setgid seulement via le parent, inherit owner", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "dir", posixAclFs: true, parentHasDefaultAcl: true, parentSetgid: true, parentGroup: "staff", parentOwner: "bob", umask: 0o022 });
    expect(r.mode & 0o2000).toBe(0o2000);
    expect(r.group).toBe("staff");
    expect(r.owner).toBe("bob");
  });
  test("posixacl sans ACL par défaut : ACL initiale avec masque rwx, stat montre g=rwx", () => {
    const d = K(`[s]\n path = /s\n create mask = 0640\n`);
    const r = computeCreate(d, "s", "alice", db, { kind: "file", posixAclFs: true, parentHasDefaultAcl: false, umask: 0o022 });
    expect(r.mode).toBe(0o640);
    expect(r.statMode).toBe(0o670);
    expect(r.effective).toBe("u=rw- g=r-- o=---");
    expect(r.acl).toContain("mask::rwx");
    expect(r.acl).toContain("user:alice:rw-");
  });
});

const smbConf = `
[global]
  workgroup = MAISON
  server min protocol = NT1
  server signing = yes
  server smb encrypt = required
  map to guest = Bad Password
  vfs objects = catia fruit streams_xattr
  fruit:model = MacSamba
  security = user
  include = registry
  smb ports = 445 139
  log level = 3
  create mode = 0664
  max connections = 20
  interfaces = 192.168.8.5/24 ens18
  bind interfaces only = yes
  kerberos method = secrets only
[homes]
  browseable = no
[Projets]
  path = /tank/projets
  writeable = Yes
  valid users = @staff +admins DOMAIN\\bob alice "@Domain Users"
  read list = carol @staff
  write list = alice carol
  admin users = root
  hosts allow = 192.168.8. 10.0.0.5
  vfs objects = acl_xattr shadow_copy2 recycle
  inherit permissions = yes
  inherit owner = unix only
  shadow:snapdir = .zfs/snapshot
  force group = +staff
  force user = svc
  veto files = /.DS_Store/#recycle/
  wide links = yes
[TM]
  path = /tank/tm
  fruit:time machine = yes
  read only = no
  follow symlinks = no
`;

suite("conversion Samba → ksmbd", () => {
  const res = convertSambaToKsmbd(parseIni(smbConf), {
    ...defaultConversionOptions(),
    rdma: { enable: true, interfaces: [], maxIoSize: "8MB" },
  });
  const g = findSection(res.doc, "global")!;
  const p = findSection(res.doc, "Projets")!;
  const tm = findSection(res.doc, "TM")!;

  test("valeurs normalisées pour ksmbd-tools", () => {
    expect(getValue(g, "server min protocol")).toBe("SMB2_10");
    expect(getValue(g, "server signing")).toBe("auto");
    expect(getValue(g, "smb3 encryption")).toBe("mandatory");
    expect(getValue(g, "map to guest")).toBe("never");
    expect(getValue(g, "tcp port")).toBe("445");
    expect(getValue(g, "aapl model")).toBe("MacSamba");
    expect(getValue(g, "create mask")).toBe("0664");
    expect(getValue(g, "kerberos support")).toBeUndefined();
  });
  test("interfaces : adresses retirées, noms gardés", () => {
    expect(getValue(g, "interfaces")).toBe("ens18");
    expect(getValue(g, "bind interfaces only")).toBe("yes");
    const only = convertSambaToKsmbd(parseIni("[global]\ninterfaces = 10.0.0.1/24\nbind interfaces only = yes\n"), { ...defaultConversionOptions(), multichannel: false });
    const og = findSection(only.doc, "global")!;
    expect(getValue(og, "interfaces")).toBeUndefined();
    expect(getValue(og, "bind interfaces only")).toBeUndefined();
  });
  test("max connections : recopié dans les partages, pas en global", () => {
    expect(getValue(g, "max connections")).toBeUndefined();
    expect(getValue(p, "max connections")).toBe("20");
  });
  test("RDMA et multicanal", () => {
    expect(getValue(g, "server multi channel support")).toBe("yes");
    expect(getValue(g, "smbd max io size")).toBe("8MB");
    expect(res.followUp.join("\n")).toContain("5445");
  });
  test("hosts allow et admin users abandonnés avec avertissement bloquant", () => {
    expect(getValue(p, "hosts allow")).toBeUndefined();
    expect(getValue(p, "admin users")).toBeUndefined();
    expect(res.blocking.join(" ")).toContain("RESTRICTION D'ACCÈS DISPARAÎT");
    expect(res.report.some((r) => r.key === "admin users" && r.action === "dropped" && r.note.includes("aucun effet"))).toBe(true);
  });
  test("listes : guillemets, groupes, intersection avec valid users", () => {
    expect(getValue(p, "valid users")).toBe("@staff @admins alice");
    expect(res.report.some((r) => r.note.includes("Domain Users"))).toBe(true);
    // carol absente de valid users : retirée ; @staff présent littéralement : gardé
    expect(getValue(p, "read list")).toBe("@staff");
    expect(getValue(p, "write list")).toBe("alice");
    expect(res.report.some((r) => r.action === "warning" && r.note.includes("read list ET write list"))).toBe(true);
  });
  test("sans intersection : simple avertissement", () => {
    const r2 = convertSambaToKsmbd(parseIni(smbConf), { ...defaultConversionOptions(), intersectWithValidUsers: false });
    expect(getValue(findSection(r2.doc, "Projets"), "write list")).toBe("alice carol");
    expect(r2.report.some((r) => r.action === "warning" && r.note.includes("absents de valid users"))).toBe(true);
  });
  test("partage : synonymes, vfs, veto avec #", () => {
    expect(getValue(p, "read only")).toBe("no");
    expect(getValue(p, "vfs objects")).toBe("acl_xattr");
    expect(getValue(p, "inherit owner")).toBe("yes");
    expect(getValue(p, "force group")).toBe("staff");
    expect(getValue(p, "veto files")).toBeUndefined();
    expect(getValue(g, "allow insecure wide links")).toBe("yes");
    expect(getValue(p, "follow symlinks")).toBe("yes");
  });
  test("follow symlinks non défini : avertissement", () => {
    expect(res.report.some((r) => r.section === "Projets" && r.key === "follow symlinks")).toBe(false);
    const r2 = convertSambaToKsmbd(parseIni("[a]\npath = /a\n"));
    expect(r2.report.some((r) => r.key === "follow symlinks" && r.action === "warning")).toBe(true);
  });
  test("homes ignoré, Time Machine converti une seule fois", () => {
    expect(findSection(res.doc, "homes")).toBeUndefined();
    expect(getValue(tm, "time machine")).toBe("yes");
    expect(getValue(tm, "vfs objects")).toContain("streams_xattr");
    expect(res.report.filter((r) => r.key === "fruit:time machine").map((r) => r.action)).toEqual(["converted"]);
    expect(getValue(g, "durable handles")).toBe("yes");
  });
  test("rapport : rien d'ignoré en silence", () => {
    const dropped = res.report.filter((r) => r.action === "dropped").map((r) => r.key ?? r.from);
    for (const k of ["security", "include", "log level", "inherit permissions", "shadow:snapdir", "kerberos method", "veto files"]) expect(dropped).toContain(k);
    expect(res.report.some((r) => r.from === "shadow_copy2" && r.action === "dropped")).toBe(true);
    expect(res.report.some((r) => r.action === "warning" && r.note.includes("kthreadd"))).toBe(true);
  });
  test("comptes : force user exclu de ksmbd.adduser, redémarrage complet", () => {
    expect(res.followUp).toContain("ksmbd.adduser -a alice");
    expect(res.followUp).not.toContain("ksmbd.adduser -a svc");
    expect(res.followUp.join("\n")).toContain("systemctl restart ksmbd");
    expect(res.followUp.some((l) => !l.startsWith("#") && l.includes("ksmbd.control --reload"))).toBe(false);
  });
  test("le résultat relu par ksmbd-tools donne les mêmes valeurs", () => {
    const back = K(res.text);
    expect(back.errors).toEqual([]);
    expect(getValue(findSection(back, "Projets"), "valid users")).toBe("@staff @admins alice");
  });
  test("registre fusionné, include = registry retiré", () => {
    const m = mergeSambaSources("[global]\ninclude = registry\nworkgroup = A\n", "[global]\n\tworkgroup = B\n[r]\n\tpath = /x\n");
    expect(getValue(findSection(m, "global"), "workgroup")).toBe("B");
    expect(getValue(findSection(m, "global"), "include")).toBeUndefined();
    expect(findSection(m, "r")).toBeDefined();
  });
});
