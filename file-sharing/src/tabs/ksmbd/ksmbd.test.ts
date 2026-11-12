import { suite, test, expect } from "vitest";
import { parseIni, serializeIni, getValue, findSection } from "./ini";
import { ksmbdBool, ksmbdOpt, ksmbdSize, findParam } from "./ksmbd-params";
import { evaluateTreeConnect, computeCreate, effectiveIdentity, resolveUserList, type UserDb } from "./permission-stack";
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

suite("ini", () => {
  test("continuation, commentaires, global implicite, dernière occurrence", () => {
    const doc = parseIni("workgroup = X\n; c\n[data]\n path = /tank/data\n valid users = a \\\n  b\n read only = yes\nreadonly = no\n");
    expect(getValue(findSection(doc, "global"), "workgroup")).toBe("X");
    expect(getValue(findSection(doc, "data"), "valid users")).toBe("a    b");
    expect(getValue(findSection(doc, "data"), "read only")).toBe("no");
    expect(serializeIni(doc)).toContain("[data]");
  });
  test("mode ksmbd : la première occurrence gagne", () => {
    const doc = parseIni("[s]\nread only = yes\nread only = no\n", "first");
    expect(getValue(findSection(doc, "s"), "read only")).toBe("yes");
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
  test("pas d'alias Samba dans ksmbd", () => {
    expect(findParam("create mode")).toBeUndefined();
    expect(findParam("writeable")?.key).toBe("writable");
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
  hosts allow = 192.168.1.10 192.168.1.0/24
[public]
  path = /tank/pub
  guest ok = yes
  read only = yes
[locked]
  path = /tank/l
  valid users = @share
`;

suite("empilement à la connexion", () => {
  const doc = parseIni(conf);
  const ip = "192.168.1.10";
  test("admin users court-circuite invalid users", () => {
    const r = evaluateTreeConnect(doc, "data", { account: "dave", peerAddr: ip }, db);
    expect(r.status).toBe("rw");
    expect(r.admin).toBe(true);
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
  test("hosts allow : comparaison exacte, CIDR ignoré", () => {
    const r = evaluateTreeConnect(doc, "data", { account: "alice", peerAddr: "192.168.1.20" }, db);
    expect(r.status).toBe("deny");
    expect(r.warnings.join(" ")).toContain("CIDR");
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
});

suite("identité et création", () => {
  const doc = parseIni(`[s]\n path = /tank/s\n force user = share\n create mask = 0664\n force create mode = 0060\n directory mask = 2775\n inherit owner = yes\n vfs objects = acl_xattr streams_xattr\n`);
  test("force user garde les groupes secondaires", () => {
    const id = effectiveIdentity(doc, "s", "alice", db);
    expect(id.uid).toBe("share");
    expect(id.gid).toBe("share");
    expect(id.supplementary).toEqual(["staff"]);
  });
  test("umask 0022 sans ACL par défaut retire g+w", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "file", posixAclFs: false, parentHasDefaultAcl: false });
    expect(r.mode).toBe(0o644);
    expect(r.warnings[0]).toContain("umask");
  });
  test("ACL par défaut du parent : pas d'umask", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "file", posixAclFs: true, parentHasDefaultAcl: true });
    expect(r.mode).toBe(0o664);
  });
  test("dossier setgid + inherit owner", () => {
    const r = computeCreate(doc, "s", "alice", db, { kind: "dir", posixAclFs: true, parentHasDefaultAcl: true, parentSetgid: true, parentGroup: "staff", parentOwner: "bob" });
    expect(r.mode & 0o2000).toBe(0o2000);
    expect(r.group).toBe("staff");
    expect(r.owner).toBe("bob");
  });
});

const smbConf = `
[global]
  workgroup = MAISON
  server min protocol = NT1
  server signing = required
  server smb encrypt = desired
  map to guest = Bad Password
  vfs objects = catia fruit streams_xattr
  fruit:model = MacSamba
  security = user
  include = registry
  smb ports = 445 139
  log level = 3
  create mode = 0664
[homes]
  browseable = no
[Projets]
  path = /tank/projets
  writeable = Yes
  valid users = @staff +admins DOMAIN\\bob alice
  hosts allow = 192.168.8. 10.0.0.5 EXCEPT 10.0.0.9
  vfs objects = acl_xattr shadow_copy2 recycle
  inherit permissions = yes
  inherit owner = unix only
  shadow:snapdir = .zfs/snapshot
  force group = +staff
  wide links = yes
[TM]
  path = /tank/tm
  fruit:time machine = yes
  read only = no
`;

suite("conversion Samba → ksmbd", () => {
  const res = convertSambaToKsmbd(parseIni(smbConf), {
    ...defaultConversionOptions(),
    rdma: { enable: true, interfaces: ["ens1f0np0"], maxIoSize: "8MB" },
    extraInterfaces: ["ens18"],
  });
  const g = findSection(res.doc, "global")!;
  const p = findSection(res.doc, "Projets")!;
  const tm = findSection(res.doc, "TM")!;

  test("valeurs normalisées pour ksmbd-tools", () => {
    expect(getValue(g, "server min protocol")).toBe("SMB2_10");
    expect(getValue(g, "server signing")).toBe("mandatory");
    expect(getValue(g, "smb3 encryption")).toBe("auto");
    expect(getValue(g, "map to guest")).toBe("never");
    expect(getValue(g, "tcp port")).toBe("445");
    expect(getValue(g, "aapl model")).toBe("MacSamba");
    expect(getValue(g, "create mask")).toBe("0664");
  });
  test("RDMA, multicanal, interfaces", () => {
    expect(getValue(g, "server multi channel support")).toBe("yes");
    expect(getValue(g, "smbd max io size")).toBe("8MB");
    expect(getValue(g, "interfaces")).toBe("ens1f0np0 ens18");
    expect(getValue(g, "bind interfaces only")).toBe("yes");
    expect(res.followUp.join("\n")).toContain("5445");
  });
  test("partage : synonymes, listes, hôtes, vfs", () => {
    expect(getValue(p, "read only")).toBe("no");
    expect(getValue(p, "valid users")).toBe("@staff @admins alice");
    expect(getValue(p, "hosts allow")).toBe("10.0.0.5");
    expect(getValue(p, "vfs objects")).toBe("acl_xattr");
    expect(getValue(p, "inherit owner")).toBe("yes");
    expect(getValue(p, "force group")).toBe("staff");
    expect(getValue(g, "allow insecure wide links")).toBe("yes");
    expect(getValue(p, "follow symlinks")).toBe("yes");
  });
  test("homes ignoré, Time Machine converti", () => {
    expect(findSection(res.doc, "homes")).toBeUndefined();
    expect(getValue(tm, "time machine")).toBe("yes");
    expect(getValue(tm, "vfs objects")).toContain("streams_xattr");
    expect(getValue(g, "durable handles")).toBe("yes");
    expect(getValue(g, "smb2 leases")).toBe("yes");
  });
  test("rapport : rien d'ignoré en silence", () => {
    const dropped = res.report.filter((r) => r.action === "dropped").map((r) => r.key ?? r.from);
    for (const k of ["security", "include", "log level", "inherit permissions", "shadow:snapdir"]) expect(dropped).toContain(k);
    expect(res.report.some((r) => r.from === "shadow_copy2" && r.action === "dropped")).toBe(true);
    expect(res.report.some((r) => r.action === "skipped-section" && r.section === "homes")).toBe(true);
    expect(res.report.some((r) => r.action === "warning" && r.note.includes("umask"))).toBe(true);
  });
  test("comptes à recréer", () => {
    expect(res.followUp).toContain("ksmbd.adduser -a alice");
  });
  test("registre fusionné, include = registry retiré", () => {
    const m = mergeSambaSources("[global]\ninclude = registry\nworkgroup = A\n", "[global]\n\tworkgroup = B\n[r]\n\tpath = /x\n");
    expect(getValue(findSection(m, "global"), "workgroup")).toBe("B");
    expect(getValue(findSection(m, "global"), "include")).toBeUndefined();
    expect(findSection(m, "r")).toBeDefined();
  });
});
