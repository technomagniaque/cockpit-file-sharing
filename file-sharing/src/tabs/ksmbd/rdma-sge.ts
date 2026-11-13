/**
 * Limite SGE de SMB Direct.
 *
 * ksmbd refuse un périphérique RDMA dont max_send_sge est inférieur à
 * SMB_DIRECT_MAX_SEND_SGES (6) : fs/smb/server/transport_rdma.c, contrôle ajouté
 * par d1626940 (« smb: server: let smb_direct_writev() respect
 * SMB_DIRECT_MAX_SEND_SGES ») ; le client cifs exige la même valeur depuis
 * d2e81f92. Message noyau : « smb_direct: device <dev> max_send_sge/max_recv_sge
 * = 4/4 too small ». qedr (QLogic FastLinQ QL41xxx, iWARP / RoCE) n'expose que
 * 4 SGE : SMB Direct est impossible avec ces cartes, côté serveur comme côté
 * client ; NFS/RDMA (rpcrdma) reste possible.
 */

export const SMB_DIRECT_MIN_SEND_SGE = 6;

export interface RdmaSge {
  dev: string;
  maxSge: number;
}

/** Extrait « max_sge » par périphérique de la sortie de « ibv_devinfo -v » (max_sge_rd ignoré). */
export function parseIbvDevinfoSge(text: string): RdmaSge[] {
  const out: RdmaSge[] = [];
  let dev = "";
  for (const line of text.split("\n")) {
    const h = /^hca_id:\s*(\S+)/.exec(line);
    if (h) { dev = h[1]!; continue; }
    const m = /^\s*max_sge:\s*(\d+)\s*$/.exec(line);
    if (m && dev && !out.some((x) => x.dev === dev)) out.push({ dev, maxSge: Number(m[1]) });
  }
  return out;
}

/** Repère, dans des lignes de dmesg, le refus de ksmbd pour cause de SGE insuffisants. */
export function parseSgeRejection(text: string): { dev: string; send: number; recv: number } | undefined {
  let found: { dev: string; send: number; recv: number } | undefined;
  for (const line of text.split("\n")) {
    const m = /device\s+(\S+)\s+max_send_sge\/max_recv_sge\s*=\s*(\d+)\/(\d+)\s+too small/.exec(line);
    if (m) found = { dev: m[1]!, send: Number(m[2]), recv: Number(m[3]) };
  }
  return found;
}

/** Avertissements à afficher : un par périphérique trop limité, ou le refus vu dans dmesg. */
export function smbDirectSgeIssues(sge: RdmaSge[], rejection?: { dev: string; send: number; recv: number }): string[] {
  const out: string[] = [];
  for (const s of sge) {
    if (s.maxSge < SMB_DIRECT_MIN_SEND_SGE) {
      out.push(`SMB Direct impossible avec ${s.dev} : max_send_sge=${s.maxSge} < ${SMB_DIRECT_MIN_SEND_SGE} exigés par ksmbd ; SMB reste en TCP, NFS/RDMA reste possible.`);
    }
  }
  if (rejection && !sge.some((s) => s.dev === rejection.dev && s.maxSge < SMB_DIRECT_MIN_SEND_SGE)) {
    out.push(`ksmbd a refusé SMB Direct sur ${rejection.dev} (dmesg : max_send_sge/max_recv_sge = ${rejection.send}/${rejection.recv} too small) ; SMB reste en TCP, NFS/RDMA reste possible.`);
  }
  return out;
}
