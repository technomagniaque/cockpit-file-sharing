import { suite, test, expect } from "vitest";
import {
  getNfsConf, setNfsConf, applyV41OnlyPreset, parseProcVersions, configuredVersions,
  analyzeServer, analyzeExportV41,
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
    const t2 = setNfsConf(sample, "gssd", "use-gss-proxy", "1");
    expect(t2).toMatch(/\[gssd\]\nuse-gss-proxy=1/);
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
});

suite("analyse serveur", () => {
  test("NFSv3 actif, écart avec le noyau, sharenfs", () => {
    const f = analyzeServer({ nfsConf: sample, procVersions: "+3 +4 +4.0 -4.1 +4.2", zfsExports: "/tank/x *(rw)" }, []);
    const titles = f.map((x) => x.title);
    expect(titles).toContain("NFSv3 actif");
    expect(titles).toContain("État réel différent de nfs.conf");
    expect(titles).toContain("Exports générés par ZFS (sharenfs)");
  });
  test("NFSv4.1 seul : pare-feu 2049 uniquement", () => {
    const f = analyzeServer({ nfsConf: applyV41OnlyPreset(sample, true) }, []);
    expect(f.find((x) => x.title === "Pare-feu")!.detail).toContain("uniquement 2049/tcp");
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
