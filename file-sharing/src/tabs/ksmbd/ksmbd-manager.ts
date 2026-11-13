/**
 * Accès serveur pour l'onglet ksmbd : lecture / écriture de ksmbd.conf,
 * lecture de la configuration Samba, base d'utilisateurs, sondes
 * d'environnement (module noyau, RDMA, ZFS) et inspection d'un chemin.
 */
import { BashCommand, File, server as defaultServer, unwrap, type Server } from "@45drives/houston-common-lib";
import type { UserDb } from "./permission-stack";
import { findSection, parseIni, serializeIni } from "./ini";
import { parseIbvDevinfoSge, parseSgeRejection, type RdmaSge } from "./rdma-sge";

export const KSMBD_CONF = "/etc/ksmbd/ksmbd.conf";
export const KSMBD_PWDDB = "/etc/ksmbd/ksmbdpwd.db";

export interface RunResult {
  code: number;
  out: string;
  err: string;
}

export interface KsmbdProbe {
  kernel: string;
  kernelMajor: number;
  kernelMinor: number;
  moduleAvailable: boolean;
  moduleLoaded: boolean;
  smbdirectBuilt: "y" | "m" | "n" | "?";
  smbServerBuilt: "y" | "m" | "n" | "?";
  toolsInstalled: boolean;
  toolsVersion: string;
  mountdRunning: boolean;
  confExists: boolean;
  sambaRunning: boolean;
  rdmaLinks: { dev: string; port: string; state: string; netdev: string }[];
  /** max_sge par périphérique RDMA (ibv_devinfo -v) ; vide si ibverbs-utils absent */
  rdmaSge: RdmaSge[];
  /** refus de SMB Direct par ksmbd vu dans dmesg (SGE insuffisants) */
  sgeRejection?: { dev: string; send: number; recv: number };
  netdevs: { name: string; state: string; driver: string; speed: string }[];
  zfsVersion: string;
  timeMachineCapable: boolean;
  /** umask des workers ksmbd (celui de kthreadd), ex. 0o022 ; null si illisible */
  workerUmask: number | null;
}

export interface PathProbe {
  exists: boolean;
  owner: string;
  group: string;
  mode: string;
  setgid: boolean;
  fstype: string;
  acltype: string;
  posixAclFs: boolean;
  hasDefaultAcl: boolean;
  hasNtAcl: boolean;
}

export class KsmbdManager {
  constructor(private server: Server = defaultServer, public confPath: string = KSMBD_CONF) {}

  run(script: string, args: string[] = []): Promise<RunResult> {
    return unwrap(
      this.server
        .execute(new BashCommand(script, args, { superuser: "try" }), false)
        .map((p) => ({ code: p.exitStatus, out: p.getStdout(), err: p.getStderr() }))
    );
  }

  async readConf(): Promise<string> {
    const r = await this.run('[ -f "$1" ] && cat -- "$1" || true', [this.confPath]);
    return r.out;
  }

  /**
   * Écrit ksmbd.conf avec copie de sauvegarde puis recharge ksmbd.mountd.
   * ksmbd.control --reload ne relit que les partages : si [global] a changé,
   * needsRestart est vrai et rien n'est appliqué tant que ksmbd n'est pas
   * redémarré (systemctl restart ksmbd = ksmbd.control --shutdown puis ksmbd.mountd).
   */
  async writeConf(text: string): Promise<{ backup: string; reload: RunResult; needsRestart: boolean }> {
    const previous = await this.readConf();
    const globalOf = (t: string) => {
      const g = findSection(parseIni(t, "ksmbd"), "global");
      return g ? serializeIni({ sections: [{ ...g, entries: [...g.entries].sort((a, b) => a.key.localeCompare(b.key)) }] }) : "";
    };
    const needsRestart = globalOf(previous) !== globalOf(text);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backup = `${this.confPath}.bak-${stamp}`;
    await this.run('mkdir -p -- "$(dirname -- "$1")" && { [ ! -f "$1" ] || cp -a -- "$1" "$2"; }', [this.confPath, backup]);
    const content = text.endsWith("\n") ? text : text + "\n";
    const file = new File(this.server, this.confPath);
    await unwrap(file.exists({ superuser: "try" }).andThen((exists) => (exists ? file.replace(content, { superuser: "try" }) : file.create(true, { superuser: "try" }).andThen((f) => f.replace(content, { superuser: "try" })))));
    const reload = await this.run('export PATH="$PATH:/usr/sbin:/sbin"; if pgrep -x ksmbd.mountd >/dev/null; then ksmbd.control --reload; else echo "ksmbd.mountd arrêté : rien à recharger"; fi');
    return { backup, reload, needsRestart };
  }

  /** Redémarrage complet (nécessaire après un changement de [global]). */
  async restart(): Promise<RunResult> {
    return this.run("systemctl restart ksmbd.service");
  }

  async readSamba(smbConfPath: string): Promise<{ smbConf: string; registry: string; testparm: string }> {
    const conf = await this.run('[ -f "$1" ] && cat -- "$1" || true', [smbConfPath]);
    const reg = await this.run("command -v net >/dev/null && net conf list 2>/dev/null || true");
    const tp = await this.run('command -v testparm >/dev/null && testparm -s --suppress-prompt "$1" 2>/dev/null || true', [smbConfPath]);
    return { smbConf: conf.out, registry: reg.out, testparm: tp.out };
  }

  async userDb(): Promise<UserDb> {
    const r = await this.run(
      `echo '--ksmbd'; [ -f "$1" ] && cut -d: -f1 -- "$1"; echo '--passwd'; getent passwd | cut -d: -f1,3,4; echo '--group'; getent group | cut -d: -f1,3,4`,
      [KSMBD_PWDDB]
    );
    const db: UserDb = { ksmbdUsers: [], unixUsers: {}, groups: {} };
    let section = "";
    for (const line of r.out.split("\n")) {
      if (line.startsWith("--")) { section = line.slice(2); continue; }
      if (!line.trim()) continue;
      const parts = line.split(":");
      if (section === "ksmbd") db.ksmbdUsers.push(parts[0]!);
      else if (section === "passwd") db.unixUsers[parts[0]!] = { uid: Number(parts[1]), gid: Number(parts[2]) };
      else if (section === "group") db.groups[parts[0]!] = { gid: Number(parts[1]), members: (parts[2] ?? "").split(",").filter(Boolean) };
    }
    return db;
  }

  async probe(): Promise<KsmbdProbe> {
    const r = await this.run(String.raw`
export PATH="$PATH:/usr/sbin:/sbin"
k=$(uname -r)
echo "kernel=$k"
cfg=/boot/config-$k; [ -f "$cfg" ] || cfg=/proc/config.gz
get() { if [ "$cfg" = /proc/config.gz ]; then zgrep -E "^$1=" "$cfg" 2>/dev/null; else grep -E "^$1=" "$cfg" 2>/dev/null; fi | cut -d= -f2; }
smbsrv=$(get CONFIG_SMB_SERVER)
if [ -z "$smbsrv" ] && { [ -d /sys/module/ksmbd ] || modinfo ksmbd >/dev/null 2>&1; }; then smbsrv=m; fi
echo "smbserver=$smbsrv"
smbdir=$(get CONFIG_SMB_SERVER_SMBDIRECT)
if [ -z "$smbdir" ] && { grep -q ksmbd_rdma /proc/kallsyms 2>/dev/null || modinfo -F depends ksmbd 2>/dev/null | grep -Eq 'ib_core|rdma_cm'; }; then smbdir=y; fi
echo "smbdirect=$smbdir"
modinfo ksmbd >/dev/null 2>&1 && echo "modavail=1" || echo "modavail=0"
[ -d /sys/module/ksmbd ] && echo "modloaded=1" || echo "modloaded=0"
command -v ksmbd.mountd >/dev/null && echo "tools=1" || echo "tools=0"
echo "toolsver=$(ksmbd.mountd --version 2>&1 | head -1)"
pgrep -x ksmbd.mountd >/dev/null && echo "mountd=1" || echo "mountd=0"
[ -f "$1" ] && echo "conf=1" || echo "conf=0"
(systemctl is-active -q smb || systemctl is-active -q smbd) 2>/dev/null && echo "samba=1" || echo "samba=0"
echo "zfs=$(zfs version 2>/dev/null | head -1)"
kt=$(pgrep -x kthreadd 2>/dev/null | head -1); [ -n "$kt" ] || kt=2
echo "umask=$(awk '/^Umask:/{print $2}' /proc/$kt/status 2>/dev/null)"
command -v rdma >/dev/null && rdma -j link show 2>/dev/null | sed 's/^/rdma=/'
command -v ibv_devinfo >/dev/null && ibv_devinfo -v 2>/dev/null | grep -E '^hca_id:|^[[:space:]]*max_sge:' | sed 's/^/ibv=/'
dmesg 2>/dev/null | grep -E 'max_send_sge/max_recv_sge = [0-9]+/[0-9]+ too small' | tail -1 | sed 's/^/sgerej=/'
for d in /sys/class/infiniband/*; do
  [ -d "$d" ] || continue
  dev=$(basename "$d")
  nd=""; for n in "$d"/device/net/*; do [ -e "$n" ] && { nd=$(basename "$n"); break; }; done
  for p in "$d"/ports/*; do
    [ -d "$p" ] || continue
    pn=$(basename "$p")
    st=$(sed 's/^[0-9]*:[[:space:]]*//' "$p/state" 2>/dev/null)
    echo "rdmasys=$dev|$pn|$st|$nd"
  done
done
for n in /sys/class/net/*; do b=$(basename "$n"); [ "$b" = lo ] && continue
  drv=$(basename "$(readlink -f "$n/device/driver" 2>/dev/null)" 2>/dev/null)
  echo "net=$b|$(cat "$n/operstate" 2>/dev/null)|$drv|$(cat "$n/speed" 2>/dev/null)"
done
`, [this.confPath]);
    const kv: Record<string, string> = {};
    const nets: KsmbdProbe["netdevs"] = [];
    const sysLinks: KsmbdProbe["rdmaLinks"] = [];
    let rdmaJson = "";
    let ibvText = "";
    let sgeRej = "";
    for (const line of r.out.split("\n")) {
      const i = line.indexOf("=");
      if (i < 0) continue;
      const k = line.slice(0, i);
      const v = line.slice(i + 1);
      if (k === "net") {
        const [name, state, driver, speed] = v.split("|");
        nets.push({ name: name!, state: state ?? "", driver: driver ?? "", speed: speed && Number(speed) > 0 ? `${speed} Mb/s` : "" });
      } else if (k === "rdmasys") {
        const [dev, port, state, netdev] = v.split("|");
        if (dev && port) sysLinks.push({ dev, port, state: (state ?? "").trim(), netdev: (netdev ?? "").trim() });
      } else if (k === "rdma") rdmaJson += v;
      else if (k === "ibv") ibvText += v + "\n";
      else if (k === "sgerej") sgeRej = v;
      else kv[k] = v;
    }
    let rdmaLinks: KsmbdProbe["rdmaLinks"] = [];
    try {
      rdmaLinks = (JSON.parse(rdmaJson || "[]") as any[]).map((l) => ({ dev: l.ifname, port: String(l.port), state: l.state, netdev: l.netdev ?? "" }));
    } catch { rdmaLinks = []; }
    if (!rdmaLinks.length && sysLinks.length) rdmaLinks = sysLinks;
    const m = /^(\d+)\.(\d+)/.exec(kv.kernel ?? "");
    const major = m ? Number(m[1]) : 0;
    const minor = m ? Number(m[2]) : 0;
    const flag = (v?: string) => (v === "y" || v === "m" ? v : v === undefined || v === "" ? "?" : "n") as KsmbdProbe["smbdirectBuilt"];
    return {
      kernel: kv.kernel ?? "",
      kernelMajor: major,
      kernelMinor: minor,
      smbServerBuilt: flag(kv.smbserver),
      smbdirectBuilt: flag(kv.smbdirect),
      moduleAvailable: kv.modavail === "1",
      moduleLoaded: kv.modloaded === "1",
      toolsInstalled: kv.tools === "1",
      toolsVersion: kv.toolsver ?? "",
      mountdRunning: kv.mountd === "1",
      confExists: kv.conf === "1",
      sambaRunning: kv.samba === "1",
      zfsVersion: kv.zfs ?? "",
      rdmaLinks,
      rdmaSge: parseIbvDevinfoSge(ibvText),
      sgeRejection: parseSgeRejection(sgeRej),
      netdevs: nets,
      timeMachineCapable: major > 7 || (major === 7 && minor >= 3),
      workerUmask: /^[0-7]{3,4}$/.test(kv.umask ?? "") ? parseInt(kv.umask!, 8) : null,
    };
  }

  async probePath(path: string): Promise<PathProbe> {
    const r = await this.run(String.raw`
p="$1"
[ -e "$p" ] || { echo "exists=0"; exit 0; }
echo "exists=1"
stat --printf 'owner=%U\ngroup=%G\nmode=%a\n' -- "$p"
echo "fstype=$(findmnt -no FSTYPE -T "$p" 2>/dev/null)"
src=$(findmnt -no SOURCE -T "$p" 2>/dev/null)
[ "$(findmnt -no FSTYPE -T "$p")" = zfs ] && echo "acltype=$(zfs get -H -o value acltype "$src" 2>/dev/null)"
findmnt -no OPTIONS -T "$p" 2>/dev/null | tr ',' '\n' | grep -qx posixacl && echo "mntposixacl=1"
getfacl -p --absolute-names -- "$p" 2>/dev/null | grep -q '^default:' && echo "defacl=1" || echo "defacl=0"
getfattr -n security.NTACL --absolute-names -- "$p" >/dev/null 2>&1 && echo "ntacl=1" || echo "ntacl=0"
`, [path]);
    const kv: Record<string, string> = {};
    for (const line of r.out.split("\n")) {
      const i = line.indexOf("=");
      if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1);
    }
    const mode = kv.mode ?? "";
    const acltype = kv.acltype ?? "";
    const posix = acltype === "posix" || acltype === "posixacl" || (!acltype && kv.mntposixacl === "1") ||
      (!acltype && ["ext4", "xfs", "btrfs"].includes(kv.fstype ?? ""));
    return {
      exists: kv.exists === "1",
      owner: kv.owner ?? "",
      group: kv.group ?? "",
      mode,
      setgid: mode.length === 4 && (Number(mode[0]) & 2) === 2,
      fstype: kv.fstype ?? "",
      acltype,
      posixAclFs: posix,
      hasDefaultAcl: kv.defacl === "1",
      hasNtAcl: kv.ntacl === "1",
    };
  }
}
