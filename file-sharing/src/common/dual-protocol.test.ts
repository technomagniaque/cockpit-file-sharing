import { suite, test, expect } from "vitest";
import { parseIni, findSection, getValue } from "@/tabs/ksmbd/ini";
import { analyzeDualProtocol, applyDualProtocolRecommendations, pathRelation, overlappingExports } from "./dual-protocol";
import { convertSambaToKsmbd, defaultConversionOptions } from "@/tabs/ksmbd/samba-to-ksmbd";
import type { NFSExport } from "@/tabs/nfs/data-types";
import type { UserDb } from "@/tabs/ksmbd/permission-stack";

const exp = (path: string, def: string, clients: [string, string][] = []): NFSExport => ({
  path, defaultClientSettings: def, clients: clients.map(([host, settings]) => ({ host, settings })), comment: "",
});

const ksmbd = `[global]
\tvfs objects = acl_xattr
[data]
\tpath = /tank/data/
\tread only = no
\tforce user = share
\tvfs objects = acl_xattr streams_xattr
[tm]
\tpath = /tank/tm
\ttime machine = yes
\toplocks = no
`;

const db: UserDb = { ksmbdUsers: ["alice"], unixUsers: { share: { uid: 900, gid: 900 } }, groups: { share: { gid: 900, members: [] } } };

suite("chemins", () => {
  test("relations", () => {
    expect(pathRelation("/tank/data/", "/tank/data")).toBe("same");
    expect(pathRelation("/tank/data/a", "/tank/data")).toBe("nfs-parent");
    expect(pathRelation("/tank", "/tank/data")).toBe("smb-parent");
    expect(pathRelation("/tank/data2", "/tank/data")).toBe("none");
    expect(overlappingExports("/tank/data", [exp("/tank", ""), exp("/srv", "")]).length).toBe(1);
  });
});

suite("constats double protocole", () => {
  const doc = parseIni(ksmbd, "ksmbd");
  test("oplocks, acl_xattr, force user", () => {
    const f = analyzeDualProtocol({ doc, share: "data", nfsExport: exp("/tank/data", "", [["10.0.0.0/24", "rw,root_squash"]]), db });
    const byId = Object.fromEntries(f.map((x) => [x.id, x]));
    expect(byId.oplocks!.level).toBe("danger");
    expect(byId.acl_xattr!.level).toBe("danger");
    expect(byId.force!.level).toBe("warning");
    expect(byId.force!.fix).toContain("anonuid=900");
    expect(byId.umask!.level).toBe("warning");
    expect(byId.sharemodes!.level).toBe("warning");
    // C1 / C2 : délégations actives par défaut
    expect(byId.delegations!.level).toBe("warning");
    expect(byId.delegations!.detail).toContain("O_NONBLOCK");
    expect(byId.delegations!.detail).not.toContain("attend la réponse");
    expect(byId.deleteonclose!.level).toBe("danger");
    expect(byId.deleteonclose!.fix).toContain("fs.leases-enable=0");
    // NFSv3 actif par défaut : NLM
    expect(byId.nlm).toBeDefined();
    expect(byId.locks!.detail).toContain("PARTAGÉ");
  });
  test("C4 : fs.leases-enable=0 retire les constats de délégation", () => {
    const f = analyzeDualProtocol({ doc, share: "data", nfsExport: exp("/tank/data", "", [["*", "rw"]]), leasesEnable: false });
    const byId = Object.fromEntries(f.map((x) => [x.id, x]));
    expect(byId.delegations!.level).toBe("info");
    expect(byId.deleteonclose).toBeUndefined();
  });
  test("NFSv4 coupé : pas de constat délégation ; NFSv3 coupé : pas de NLM", () => {
    const f1 = analyzeDualProtocol({ doc, share: "data", nfsExport: exp("/tank/data", ""), nfsV4: false });
    expect(f1.some((x) => x.id === "delegations")).toBe(false);
    const f2 = analyzeDualProtocol({ doc, share: "data", nfsExport: exp("/tank/data", ""), nfsV3: false });
    expect(f2.some((x) => x.id === "nlm")).toBe(false);
  });
  test("C5 : poignées durables signalées indépendamment de oplocks", () => {
    const d = parseIni("[global]\n\tdurable handles = yes\n[s]\n\tpath = /tank/s\n\toplocks = no\n", "ksmbd");
    const f = analyzeDualProtocol({ doc: d, share: "s", nfsExport: exp("/tank/s", "") });
    const byId = Object.fromEntries(f.map((x) => [x.id, x]));
    expect(byId.durable!.level).toBe("warning");
    expect(byId.durable!.detail).toContain("60 s");
    expect(byId.durable!.detail).toContain("parse_durable_handle_context");
    expect(byId.oplocks!.detail).not.toContain("durables");
    const ch = applyDualProtocolRecommendations(d, "s");
    expect(ch.some((c) => c.includes("durable handles = yes"))).toBe(true);
  });
  test("C14 : chemins comparés après résolution", () => {
    const d = parseIni("[s]\n\tpath = /srv/lien\n", "ksmbd");
    const resolve = (p: string) => (p === "/srv/lien" ? "/tank/s" : p);
    expect(analyzeDualProtocol({ doc: d, share: "s", nfsExport: exp("/tank/s", "") })).toEqual([]);
    expect(analyzeDualProtocol({ doc: d, share: "s", nfsExport: exp("/tank/s", ""), resolve }).length).toBeGreaterThan(0);
    expect(overlappingExports("/srv/lien", [exp("/tank/s", "")], resolve).length).toBe(1);
  });
  test("force user cohérent avec all_squash + anonuid", () => {
    const f = analyzeDualProtocol({ doc, share: "data", nfsExport: exp("/tank/data", "", [["*", "rw,all_squash,anonuid=900"]]), db, rootHasDefaultAcl: true });
    const byId = Object.fromEntries(f.map((x) => [x.id, x]));
    expect(byId.force!.level).toBe("info");
    expect(byId.umask!.level).toBe("info");
  });
  test("Time Machine signalé, oplocks = no reconnu", () => {
    const f = analyzeDualProtocol({ doc, share: "tm", nfsExport: exp("/tank", "") });
    const byId = Object.fromEntries(f.map((x) => [x.id, x]));
    expect(byId.oplocks!.level).toBe("info");
    expect(byId.timemachine!.level).toBe("warning");
    expect(byId.acl_xattr!.level).toBe("danger"); // hérité de [global]
  });
  test("chemins sans rapport : aucun constat", () => {
    expect(analyzeDualProtocol({ doc, share: "data", nfsExport: exp("/srv/x", "") })).toEqual([]);
  });
});

suite("réglages recommandés", () => {
  test("partage avec sa propre valeur vfs objects", () => {
    const doc = parseIni(ksmbd, "ksmbd");
    const ch = applyDualProtocolRecommendations(doc, "data");
    const s = findSection(doc, "data")!;
    expect(getValue(s, "oplocks")).toBe("no");
    expect(getValue(s, "vfs objects")).toBe("streams_xattr");
    expect(ch.length).toBe(3);
    expect(ch[2]).toContain("fs.leases-enable=0");
  });
  test("acl_xattr hérité de [global] seul : signalé, pas d'annulation impossible", () => {
    const doc = parseIni(ksmbd, "ksmbd");
    const ch = applyDualProtocolRecommendations(doc, "tm");
    expect(ch.some((c) => c.includes("[global]"))).toBe(true);
    expect(getValue(findSection(doc, "tm")!, "time machine")).toBe("no");
  });
  test("C13 : time machine hérité de [global]", () => {
    const doc = parseIni("[global]\n\ttime machine = yes\n[s]\n\tpath = /tank/s\n", "ksmbd");
    const ch = applyDualProtocolRecommendations(doc, "s");
    expect(getValue(findSection(doc, "s")!, "time machine")).toBe("no");
    expect(ch.some((c) => c.includes("héritée de [global]"))).toBe(true);
  });
});

suite("conversion Samba avec export NFS", () => {
  test("constats ajoutés au rapport et blocage", () => {
    const smb = parseIni("[global]\n kernel oplocks = yes\n[Projets]\n path = /tank/projets\n read only = no\n");
    const r = convertSambaToKsmbd(smb, { ...defaultConversionOptions(), nfsExports: [exp("/tank/projets", "fsid=1", [["*", "rw"]])] });
    const notes = r.report.filter((l) => l.section === "Projets" && l.action === "warning").map((l) => l.note).join("\n");
    expect(notes).toContain("kernel oplocks = yes");
    expect(notes).toContain("Cache client SMB non coordonné");
    expect(r.blocking.some((b) => b.includes("Projets") && b.includes("oplocks = no"))).toBe(true);
  });
});
