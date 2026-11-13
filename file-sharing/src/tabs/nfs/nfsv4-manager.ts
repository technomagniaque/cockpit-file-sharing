/**
 * Accès serveur pour le volet NFSv4.1 et la cohabitation SMB / NFS :
 * nfs.conf, état réel de nfsd, idmapping, lecture de tous les exports.
 */
import { BashCommand, File, server as defaultServer, unwrap, type Server } from "@45drives/houston-common-lib";
import { NFSExportParser } from "@/tabs/nfs/exports-parser";
import type { NFSExport } from "@/tabs/nfs/data-types";
import type { ServerState, RdmaLink, ZfsChild } from "@/tabs/nfs/nfsv4";

export const NFS_CONF = "/etc/nfs.conf";

export interface NfsServerSnapshot extends ServerState {
  /** type de système de fichiers par chemin d'export */
  fstypes: Record<string, string>;
  /** chemin résolu (readlink -f) par chemin d'export */
  resolved: Record<string, string>;
  /** datasets ZFS (récursifs) sous chaque chemin d'export ZFS */
  zfsChildren: Record<string, ZfsChild[]>;
  hostname: string;
}

async function run(server: Server, script: string, args: string[] = []) {
  return unwrap(
    server
      .execute(new BashCommand(script, args, { superuser: "try" }), false)
      .map((p) => ({ code: p.exitStatus, out: p.getStdout(), err: p.getStderr() }))
  );
}

/** Découpe un fichier exports en enregistrements (continuations « \ », commentaires). */
export function splitExportRecords(raw: string): string[] {
  const lines: string[] = [];
  for (const line of raw.replace(/\r\n?/g, "\n").split("\n")) {
    const prev = lines[lines.length - 1];
    if (prev !== undefined && prev.endsWith("\\")) lines[lines.length - 1] = prev.slice(0, -1) + " " + line;
    else lines.push(line);
  }
  return lines.map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
}

/** Analyse tolérante : un enregistrement illisible est ignoré au lieu de tout faire échouer. */
export function parseExportsLenient(raw: string): { exports: NFSExport[]; errors: string[] } {
  const parser = new NFSExportParser();
  const exports: NFSExport[] = [];
  const errors: string[] = [];
  for (const rec of splitExportRecords(raw)) {
    parser.apply(rec).match(
      (e) => exports.push(e),
      (err) => errors.push(`${rec} : ${err.message}`)
    );
  }
  return { exports, errors };
}

export class NFSv4Manager {
  constructor(private server: Server = defaultServer) {}

  async snapshot(exportPaths: string[] = []): Promise<NfsServerSnapshot> {
    const r = await run(this.server, String.raw`
conf="$1"; shift
echo "@@conf"; [ -f "$conf" ] && cat -- "$conf"
for f in /etc/nfs.conf.d/*.conf; do [ -f "$f" ] || continue; echo "@@confd $f"; cat -- "$f"; done
echo "@@versions"; cat /proc/fs/nfsd/versions 2>/dev/null
echo "@@portlist"; cat /proc/fs/nfsd/portlist 2>/dev/null
echo "@@threads"; cat /proc/fs/nfsd/threads 2>/dev/null
echo "@@leases"; cat /proc/sys/fs/leases-enable 2>/dev/null
echo "@@rpcrdma"; [ -d /sys/module/rpcrdma ] && echo 1 || echo 0
echo "@@xprtrdma"; k=$(uname -r); { grep -E '^CONFIG_SUNRPC_XPRT_RDMA=' "/boot/config-$k" 2>/dev/null || zgrep -E '^CONFIG_SUNRPC_XPRT_RDMA=' /proc/config.gz 2>/dev/null; } | cut -d= -f2
echo "@@rdma"; command -v rdma >/dev/null && rdma -j link show 2>/dev/null
echo "@@nodetypes"; for d in /sys/class/infiniband/*; do [ -e "$d/node_type" ] && printf '%s\t%s\n' "$(basename "$d")" "$(cat "$d/node_type")"; done
echo "@@services"; for u in rpcbind.socket nfs-mountd.service rpc-statd.service nfs-server.service; do printf '%s\t%s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done
echo "@@idmap"; [ -f /etc/idmapd.conf ] && sed -n 's/^[[:space:]]*Domain[[:space:]]*=[[:space:]]*//Ip' /etc/idmapd.conf | head -1
echo "@@dns"; dnsdomainname 2>/dev/null || hostname -d 2>/dev/null
echo "@@host"; hostname -f 2>/dev/null || hostname
echo "@@disable"; cat /sys/module/nfsd/parameters/nfs4_disable_idmapping 2>/dev/null
echo "@@zfs"; [ -f /etc/exports.d/zfs.exports ] && cat /etc/exports.d/zfs.exports
echo "@@fstypes"; for p in "$@"; do printf '%s\t%s\t%s\n' "$p" "$(findmnt -no FSTYPE -T "$p" 2>/dev/null)" "$(readlink -f -- "$p" 2>/dev/null)"; done
echo "@@children"; for p in "$@"; do
  [ "$(findmnt -no FSTYPE -T "$p" 2>/dev/null)" = zfs ] || continue
  ds=$(findmnt -no SOURCE -T "$p" 2>/dev/null)
  zfs list -H -o name,mountpoint -t filesystem -r -- "$ds" 2>/dev/null | while IFS="$(printf '\t')" read -r n m; do printf '%s\t%s\t%s\n' "$p" "$n" "$m"; done
done
echo "@@end"
`, [NFS_CONF, ...exportPaths]);
    const parts: Record<string, string> = {};
    const confD: { file: string; text: string }[] = [];
    let cur = "";
    for (const line of r.out.split("\n")) {
      const d = /^@@confd (.*)$/.exec(line);
      if (d) { cur = "confd"; confD.push({ file: d[1]!, text: "" }); continue; }
      const m = /^@@(\w+)$/.exec(line);
      if (m) { cur = m[1]!; parts[cur] = ""; continue; }
      if (cur === "confd") confD[confD.length - 1]!.text += line + "\n";
      else if (cur) parts[cur] += line + "\n";
    }
    const fstypes: Record<string, string> = {};
    const resolved: Record<string, string> = {};
    for (const l of (parts.fstypes ?? "").split("\n")) {
      const [p, t, rp] = l.split("\t");
      if (p) {
        fstypes[p] = (t ?? "").trim();
        resolved[p] = (rp ?? "").trim() || p;
      }
    }
    const zfsChildren: Record<string, ZfsChild[]> = {};
    for (const l of (parts.children ?? "").split("\n")) {
      const [p, name, mountpoint] = l.split("\t");
      if (p && name && mountpoint && mountpoint.startsWith("/")) (zfsChildren[p] ??= []).push({ name, mountpoint });
    }
    let rdmaLinks: RdmaLink[] = [];
    try {
      rdmaLinks = (JSON.parse((parts.rdma ?? "").trim() || "[]") as any[]).map((l) => ({ dev: String(l.ifname), port: String(l.port), state: String(l.state), netdev: String(l.netdev ?? "") }));
    } catch { rdmaLinks = []; }
    const rdmaNodeTypes: Record<string, "iwarp" | "ib-roce" | "unknown"> = {};
    for (const l of (parts.nodetypes ?? "").split("\n")) {
      const [dev, t] = l.split("\t");
      if (!dev) continue;
      rdmaNodeTypes[dev] = /RNIC|^4/.test(t ?? "") ? "iwarp" : /CA|^1/.test(t ?? "") ? "ib-roce" : "unknown";
    }
    const services: Record<string, boolean> = {};
    for (const l of (parts.services ?? "").split("\n")) {
      const [u, st] = l.split("\t");
      if (u) services[u] = (st ?? "").trim() === "active";
    }
    const dis = (parts.disable ?? "").trim();
    const leases = (parts.leases ?? "").trim();
    const threads = Number((parts.threads ?? "").trim());
    const xr = (parts.xprtrdma ?? "").trim();
    return {
      nfsConf: (parts.conf ?? "").replace(/\n$/, ""),
      nfsConfD: confD,
      procVersions: (parts.versions ?? "").trim() || undefined,
      portlist: parts.portlist !== undefined ? parts.portlist.trim() : undefined,
      liveThreads: (parts.threads ?? "").trim() !== "" && !isNaN(threads) ? threads : undefined,
      leasesEnable: leases === "0" ? false : leases === "1" ? true : undefined,
      rpcrdmaLoaded: (parts.rpcrdma ?? "").trim() === "1",
      xprtRdmaConfig: xr === "y" || xr === "m" ? xr : xr === "" ? "?" : "n",
      rdmaLinks,
      rdmaNodeTypes,
      services,
      idmapdDomain: (parts.idmap ?? "").trim() || undefined,
      dnsDomain: (parts.dns ?? "").trim() || undefined,
      hostname: (parts.host ?? "").trim() || "serveur",
      disableIdmapping: dis === "Y" ? true : dis === "N" ? false : undefined,
      zfsExports: parts.zfs,
      fstypes,
      resolved,
      zfsChildren,
    };
  }

  async writeNfsConf(text: string): Promise<string> {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backup = `${NFS_CONF}.bak-${stamp}`;
    const cp = await run(this.server, '[ ! -f "$1" ] || cp -a -- "$1" "$2"', [NFS_CONF, backup]);
    if (cp.code !== 0) throw new Error(`Copie de sauvegarde impossible (${backup}) : ${cp.err.trim() || "code " + cp.code} — nfs.conf non modifié`);
    const file = new File(this.server, NFS_CONF);
    await unwrap(
      file.exists({ superuser: "try" }).andThen((exists) =>
        exists
          ? file.replace(text, { superuser: "try" })
          : file.create(true, { superuser: "try" }).andThen((f) => f.replace(text, { superuser: "try" }))
      )
    );
    return backup;
  }

  /** Tous les exports connus du serveur : fichier du plugin, /etc/exports, /etc/exports.d/*.exports. */
  async allExports(pluginExportsPath: string): Promise<{ exports: NFSExport[]; errors: string[]; files: string[] }> {
    const r = await run(this.server, String.raw`
for f in "$1" /etc/exports /etc/exports.d/*.exports; do
  [ -f "$f" ] || continue
  rf=$(readlink -f -- "$f")
  case " $seen " in *" $rf "*) continue;; esac
  seen="$seen $rf"
  echo "@@file $f"; cat -- "$f"; echo
done
`, [pluginExportsPath]);
    const files: string[] = [];
    let buf = "";
    const all: NFSExport[] = [];
    const errors: string[] = [];
    const flush = () => {
      if (!buf) return;
      const p = parseExportsLenient(buf);
      all.push(...p.exports);
      errors.push(...p.errors);
      buf = "";
    };
    for (const line of r.out.split("\n")) {
      const m = /^@@file (.*)$/.exec(line);
      if (m) { flush(); files.push(m[1]!); continue; }
      buf += line + "\n";
    }
    flush();
    return { exports: all, errors, files };
  }
}
