/**
 * Accès serveur pour le volet NFSv4.1 et la cohabitation SMB / NFS :
 * nfs.conf, état réel de nfsd, idmapping, lecture de tous les exports.
 */
import { BashCommand, File, server as defaultServer, unwrap, type Server } from "@45drives/houston-common-lib";
import { NFSExportParser } from "@/tabs/nfs/exports-parser";
import type { NFSExport } from "@/tabs/nfs/data-types";
import type { ServerState } from "@/tabs/nfs/nfsv4";

export const NFS_CONF = "/etc/nfs.conf";

export interface NfsServerSnapshot extends ServerState {
  /** type de système de fichiers par chemin d'export */
  fstypes: Record<string, string>;
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
echo "@@versions"; cat /proc/fs/nfsd/versions 2>/dev/null
echo "@@idmap"; [ -f /etc/idmapd.conf ] && sed -n 's/^[[:space:]]*Domain[[:space:]]*=[[:space:]]*//Ip' /etc/idmapd.conf | head -1
echo "@@dns"; dnsdomainname 2>/dev/null || hostname -d 2>/dev/null
echo "@@disable"; cat /sys/module/nfsd/parameters/nfs4_disable_idmapping 2>/dev/null
echo "@@zfs"; [ -f /etc/exports.d/zfs.exports ] && cat /etc/exports.d/zfs.exports
echo "@@fstypes"; for p in "$@"; do printf '%s\t%s\n' "$p" "$(findmnt -no FSTYPE -T "$p" 2>/dev/null)"; done
echo "@@end"
`, [NFS_CONF, ...exportPaths]);
    const parts: Record<string, string> = {};
    let cur = "";
    for (const line of r.out.split("\n")) {
      const m = /^@@(\w+)$/.exec(line);
      if (m) { cur = m[1]!; parts[cur] = ""; continue; }
      if (cur) parts[cur] += line + "\n";
    }
    const fstypes: Record<string, string> = {};
    for (const l of (parts.fstypes ?? "").split("\n")) {
      const [p, t] = l.split("\t");
      if (p) fstypes[p] = (t ?? "").trim();
    }
    const dis = (parts.disable ?? "").trim();
    return {
      nfsConf: (parts.conf ?? "").replace(/\n$/, ""),
      procVersions: (parts.versions ?? "").trim() || undefined,
      idmapdDomain: (parts.idmap ?? "").trim() || undefined,
      dnsDomain: (parts.dns ?? "").trim() || undefined,
      disableIdmapping: dis === "Y" ? true : dis === "N" ? false : undefined,
      zfsExports: parts.zfs,
      fstypes,
    };
  }

  async writeNfsConf(text: string): Promise<string> {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backup = `${NFS_CONF}.bak-${stamp}`;
    await run(this.server, '[ ! -f "$1" ] || cp -a -- "$1" "$2"', [NFS_CONF, backup]);
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
