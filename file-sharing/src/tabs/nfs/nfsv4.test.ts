import { suite, test, expect } from "vitest";
import {
  getNfsConf, setNfsConf, applyV41OnlyPreset, applyV3V41Preset, applyRdma, parseProcVersions, configuredVersions,
  analyzeServer, analyzeExportV41, analyzeExportV3, analyzeRdma, parsePortlist, firewallPorts, setVersions,
  versionGuards, currentVersions, exportLineFor, clientMountCommands, overriddenKeys,
} from "./nfsv4";
import { validateNFSClientOptions } from "./client-options";
import type { NFSExport } from "./data-types";

const sample = `#
# This is a general configuration for the
# NFS daemons and tools
#
[general]
# pipefs-directory=/var/lib/nfs/rpc_pipefs
[nfsd]
# debug=0
# threads=8
# vers3=y
# vers4.0=y
vers4.1=y
[mountd]
# manage-gids=n
`;

const exp = (path: string, def: string, clients: [string, string][] = []): NFSExport => ({
  path, defaultClientSettings: def, clients: clients.map(([host, settings]) => ({ host, settings })), comment: "",
});

suite("nfs.conf", () => {
  test("lecture : commentaires ignorés, défauts appliqués", () => {
    expect(getNfsConf(sample, "nfsd", "vers3")).toBeUndefined();
    expect(getNfsConf(sample, "nfsd", "vers4.1")).toBe("y");
    expect(configuredVersions(sample)).toEqual({ v3: true, v40: true, v41: true, v42: true });
  });
  test("écriture : décommente l'exemple de la section", () => {
    const t = setNfsConf(sample, "nfsd", "threads", "32");
    expect(t).toContain("\nthreads=32\n");
    expect(t).not.toContain("# threads=8");
    expect(getNfsConf(t, "nfsd", "threads")).toBe("32");
  });
  test("écriture : ajoute en fin de section ou crée la section", () => {
    const t = setNfsConf(sample, "nfsd", "rdma", "y");
    expect(t.indexOf("rdma=y")).toBeLessThan(t.indexOf("[mountd]"));
    const t2 = setNfsConf(sample, "lockd", "port", "32803");
    expect(t2).toMatch(/\[lockd\]\nport=32803/);
  });
  test("suppression = retour au défaut (commenté)", () => {
    const t = setNfsConf(sample, "nfsd", "vers4.1", undefined);
    expect(getNfsConf(t, "nfsd", "vers4.1")).toBeUndefined();
  });
  test("préréglage NFSv4.1 seulement", () => {
    const t = applyV41OnlyPreset(sample, false);
    expect(configuredVersions(t)).toEqual({ v3: false, v40: false, v41: true, v42: false });
    expect(configuredVersions(applyV41OnlyPreset(sample, true)).v42).toBe(true);
  });
  test("/proc/fs/nfsd/versions", () => {
    expect(parseProcVersions("-3 +4 -4.0 +4.1 +4.2\n")).toEqual({ v3: false, v40: false, v41: true, v42: true });
  });
  test("C6 : +4 sans -4.0 implique 4.0 ; -4 coupe tout", () => {
    expect(parseProcVersions("-2 +3 +4 +4.1 +4.2")).toEqual({ v3: true, v40: true, v41: true, v42: true });
    expect(parseProcVersions("+3 -4 -4.0 -4.1 -4.2")).toEqual({ v3: true, v40: false, v41: false, v42: false });
    expect(parseProcVersions("+3 +4 -4.1 +4.2").v41).toBe(false);
  });
  test("préréglage recommandé NFSv3 + NFSv4.1 : versions et ports fixes", () => {
    const t = applyV3V41Preset(sample, true, { rdma: true });
    expect(configuredVersions(t)).toEqual({ v3: true, v40: false, v41: true, v42: true });
    expect(getNfsConf(t, "mountd", "port")).toBe("20048");
    expect(getNfsConf(t, "statd", "port")).toBe("662");
    expect(getNfsConf(t, "lockd", "udp-port")).toBe("32769");
    expect(getNfsConf(t, "nfsd", "rdma-port")).toBe("20049");
  });
});

suite("analyse serveur", () => {
  test("NFSv3 actif, écart avec le noyau, sharenfs", () => {
    const f = analyzeServer({ nfsConf: sample, procVersions: "+3 +4 -4.1 +4.2", zfsExports: "/tank/x *(rw)" }, []);
    const titles = f.map((x) => x.title);
    expect(titles).toContain("NFSv3 actif sur tous les exports");
    expect(titles).toContain("Ports NFSv3 dynamiques");
    expect(titles).toContain("État réel différent de nfs.conf");
    expect(titles).toContain("Exports générés par ZFS (sharenfs)");
  });
  test("NFSv4.1 seul : pare-feu 2049 uniquement, mountd doit tourner (C9)", () => {
    const f = analyzeServer({ nfsConf: applyV41OnlyPreset(sample, true) }, []);
    expect(f.find((x) => x.title === "Pare-feu")!.detail).toBe("2049/tcp (nfsd)");
    expect(f.find((x) => x.title === "mountd en NFSv4 seul")!.detail).toContain("doit continuer de tourner");
    expect(f.find((x) => x.title === "NFSv3 désactivé")!.level).toBe("warning");
  });
  test("v3 + v4.1 : pare-feu complet et services", () => {
    const conf = applyV3V41Preset(sample, true);
    const ports = firewallPorts(conf).map((p) => `${p.port}/${p.proto}`);
    for (const p of ["2049/tcp", "111/tcp", "111/udp", "20048/tcp", "662/udp", "32803/tcp", "32769/udp"]) expect(ports).toContain(p);
    const f = analyzeServer({ nfsConf: conf, services: { "rpcbind.socket": false, "nfs-mountd.service": true, "rpc-statd.service": false } }, []);
    expect(f.find((x) => x.title === "Services NFSv3 arrêtés")!.detail).toContain("rpcbind.socket, rpc-statd.service");
    expect(f.some((x) => x.title === "Ports NFSv3 dynamiques")).toBe(false);
  });
  test("idmapping incohérent entre v3 et v4.1", () => {
    const f = analyzeServer({ nfsConf: sample, disableIdmapping: false, idmapdDomain: "lab" }, [exp("/tank/a", "", [["10.0.0.0/24", "rw"]])]);
    expect(f.find((x) => x.title === "Propriétaires différents entre v3 et v4.1")!.level).toBe("warning");
  });
  test("C7 : nfs.conf.d surcharge nfs.conf", () => {
    const state = { nfsConf: applyV3V41Preset(sample, true), nfsConfD: [{ file: "/etc/nfs.conf.d/local.conf", text: "[nfsd]\nvers3=n\n" }] };
    expect(overriddenKeys(state)).toEqual([{ section: "nfsd", key: "vers3", file: "/etc/nfs.conf.d/local.conf", value: "n" }]);
    const f = analyzeServer(state, []);
    expect(f.some((x) => x.title === "Réglages surchargés par /etc/nfs.conf.d")).toBe(true);
    expect(f.some((x) => x.title === "NFSv3 désactivé")).toBe(true);
  });
  test("C10 : threads réels affichés", () => {
    const f = analyzeServer({ nfsConf: sample, liveThreads: 32 }, []);
    expect(f.some((x) => x.title === "Threads nfsd : 32")).toBe(true);
  });
  test("idmapping : UID numériques avec sec=sys", () => {
    const f = analyzeServer({ nfsConf: sample, disableIdmapping: true }, [exp("/tank/a", "", [["10.0.0.0/24", "rw,sec=sys"]])]);
    expect(f.some((x) => x.title.includes("UID / GID numériques"))).toBe(true);
  });
  test("idmapping : Domain absent avec krb5", () => {
    const f = analyzeServer({ nfsConf: sample, disableIdmapping: true }, [exp("/tank/a", "", [["*", "rw,sec=krb5p"]])]);
    expect(f.some((x) => x.title.includes("Domain absent"))).toBe(true);
  });
});

suite("options d'export NFSv4.1", () => {
  test("constats principaux", () => {
    const f = analyzeExportV41(exp("/tank/data", "", [["*", "rw,async,no_root_squash,no_acl,pnfs"]]));
    const t = f.map((x) => x.title).join(" | ");
    for (const k of ["fsid", "sec=sys ouvert", "no_root_squash", "async", "no_acl", "pnfs", "Datasets enfants"]) expect(t).toContain(k);
  });
  test("export propre", () => {
    const f = analyzeExportV41(exp("/tank/data", "fsid=1c2b", [["10.0.8.0/24", "rw,sync,no_subtree_check,crossmnt,sec=krb5p,root_squash"]]));
    expect(f.filter((x) => x.level !== "info")).toEqual([]);
  });
  test("nouvelles options reconnues", () => {
    expect(validateNFSClientOptions("rw,security_label,no_pnfs,nordirplus,xprtsec=tls:mtls").type).toBe("success");
  });
});

suite("interrupteurs de version NFS", () => {
  test("tout couper est refusé", () => {
    const r = setVersions(sample, { v3: false, v40: false, v41: false, v42: false });
    expect(r.ok).toBe(false);
    expect(versionGuards({ v3: false, v40: false, v41: false, v42: false }, { nfsConf: sample })[0]!.level).toBe("danger");
  });
  test("mineures indépendantes, vers4 suit", () => {
    const r = setVersions(sample, { v3: true, v40: false, v41: false, v42: true });
    expect(r.ok).toBe(true);
    expect(getNfsConf(r.text, "nfsd", "vers4")).toBe("y");
    expect(currentVersions(r.text)).toEqual({ v3: true, v40: false, v41: false, v42: true });
    const g = versionGuards({ v3: true, v40: false, v41: false, v42: true }, { nfsConf: sample }).map((x) => x.title);
    expect(g).toContain("4.2 sans 4.1");
    expect(g).toContain("NFSv4.1 coupé");
  });
  test("v4 entièrement coupé : vers4=n", () => {
    const r = setVersions(sample, { v3: true, v40: false, v41: false, v42: false });
    expect(getNfsConf(r.text, "nfsd", "vers4")).toBe("n");
    expect(currentVersions(r.text).v41).toBe(false);
  });
  test("RDMA indépendant des versions", () => {
    const g = versionGuards({ v3: true, v40: false, v41: false, v42: true }, { nfsConf: applyRdma(sample, true) });
    expect(g.some((x) => x.title === "RDMA indépendant des versions")).toBe(true);
  });
});

suite("NFSv3 : datasets enfants", () => {
  const e = exp("/tank/data", "fsid=aaaa", [["10.0.0.0/24", "rw,sync,no_subtree_check"]]);
  const children = [
    { name: "tank/data", mountpoint: "/tank/data" },
    { name: "tank/data/vm", mountpoint: "/tank/data/vm" },
    { name: "tank/data/iso", mountpoint: "/tank/data/iso" },
    { name: "tank/other", mountpoint: "/tank/other" },
  ];
  test("enfants non exportés → lignes proposées avec fsid unique", () => {
    let n = 0;
    const r = analyzeExportV3(e, children, ["/tank/data", "/tank/data/iso/"], () => `uuid-${++n}`);
    expect(r.findings[0]!.title).toBe("1 dataset(s) enfant(s) non exporté(s)");
    expect(r.suggestedLines).toEqual(["/tank/data/vm -fsid=uuid-1 10.0.0.0/24(rw,sync,no_subtree_check)"]);
  });
  test("ligne d'export : fsid remplacé partout", () => {
    expect(exportLineFor(exp("/a", "fsid=1,ro", [["h", "rw,fsid=2"]]), "/a b", "X")).toBe('"/a b" -ro,fsid=X h(rw)');
  });
  test("async et sec=sys signalés", () => {
    const r = analyzeExportV3(exp("/tank/x", "", [["*", "rw,async"]]), [], []);
    const t = r.findings.map((x) => x.title);
    expect(t).toContain("async avec NFSv3");
    expect(t).toContain("AUTH_SYS en v3");
  });
});

suite("NFS sur RDMA", () => {
  const conf = applyRdma(applyV3V41Preset(sample, true), true);
  test("portlist", () => {
    expect(parsePortlist("tcp 2049\nrdma 20049\n")).toEqual([{ transport: "tcp", port: "2049" }, { transport: "rdma", port: "20049" }]);
  });
  test("écoute absente, module, liens", () => {
    const f = analyzeRdma({ nfsConf: conf, portlist: "tcp 2049", rpcrdmaLoaded: false, rdmaLinks: [], xprtRdmaConfig: "m" });
    const t = f.map((x) => x.title);
    expect(t).toContain("nfsd n'écoute pas en RDMA");
    expect(t).toContain("Module rpcrdma non chargé");
    expect(t).toContain("Aucun lien RDMA détecté");
  });
  test("iWARP actif et à l'écoute", () => {
    const f = analyzeRdma({ nfsConf: conf, portlist: "tcp 2049\nrdma 20049", rpcrdmaLoaded: true, rdmaLinks: [{ dev: "qedr0", port: "1", state: "ACTIVE", netdev: "ens1f2" }], rdmaNodeTypes: { qedr0: "iwarp" } });
    const t = f.map((x) => x.title);
    expect(t).toContain("NFS/RDMA à l'écoute");
    expect(t).toContain("iWARP");
    expect(f.find((x) => x.title === "iWARP")!.detail).toContain("5445");
  });
  test("pare-feu RDMA et commandes client", () => {
    const ports = firewallPorts(conf).map((p) => `${p.port}/${p.proto}`);
    expect(ports).toContain("20049/tcp");
    expect(ports).toContain("4791/udp");
    const cmds = clientMountCommands("nas", "/tank/data", true);
    expect(cmds).toContain("mount -t nfs -o vers=4.1,proto=rdma,port=20049,hard nas:/tank/data /mnt/data");
    expect(cmds).toContain("mount -t nfs -o vers=3,proto=rdma,port=20049,hard nas:/tank/data /mnt/data");
  });
  test("RDMA désactivé avec lien actif : suggestion", () => {
    const f = analyzeRdma({ nfsConf: sample, rdmaLinks: [{ dev: "qedr0", port: "1", state: "ACTIVE", netdev: "" }] });
    expect(f[0]!.title).toBe("Liens RDMA disponibles, NFS/RDMA désactivé");
  });
});
