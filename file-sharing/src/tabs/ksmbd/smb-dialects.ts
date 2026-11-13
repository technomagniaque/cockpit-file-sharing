/**
 * Dialectes SMB de ksmbd : interrupteurs par dialecte, ramenés à la seule
 * chose que ksmbd sait faire, une PLAGE CONTIGUË « server min protocol » …
 * « server max protocol ».
 *
 * Vérifié dans le noyau (fs/smb/server/smb_common.c, identique en v6.12) :
 *  - dialectes SMB2+ négociables : SMB2_10, SMB3_00, SMB3_02, SMB3_11
 *    (smb2_protos[]) ; SMB2.0.2 n'existe pas dans ksmbd.
 *  - « SMB2_22 » (SMB2X_PROT, « SMB 2.??? ») n'est pas un dialecte : c'est le
 *    joker de la négociation multi-protocole lancée en SMB1, toujours accepté
 *    (supported_protocol). En min, son index (3) exclut SMB2_10 : équivaut à
 *    SMB3_00.
 *  - ksmbd_lookup_protocol_idx compare par préfixe de la valeur saisie : on
 *    écrit toujours le nom complet.
 *  - supported_protocol : min_protocol <= idx <= max_protocol.
 */
import { findSection, getValue, setValue, deleteValue, type IniDocument } from "./ini";

export type SmbDialect = "SMB2_10" | "SMB3_00" | "SMB3_02" | "SMB3_11";

export interface DialectInfo {
  id: SmbDialect;
  label: string;
  brings: string;
  clients: string;
}

export const SMB_DIALECTS: DialectInfo[] = [
  { id: "SMB2_10", label: "SMB 2.1", brings: "Baux (leases) de fichiers, MTU étendu. Pas de chiffrement, pas de multicanal.", clients: "Windows 7 / Server 2008 R2, vieux NAS, imprimantes et scanners « scan to folder », Android anciens, certaines TV." },
  { id: "SMB3_00", label: "SMB 3.0", brings: "Multicanal, SMB Direct (RDMA), chiffrement AES-CCM, poignées durables / persistantes.", clients: "Windows 8 / Server 2012." },
  { id: "SMB3_02", label: "SMB 3.0.2", brings: "Améliorations RDMA (invalidation à distance), désactivation possible de SMB1 côté client.", clients: "Windows 8.1 / Server 2012 R2." },
  { id: "SMB3_11", label: "SMB 3.1.1", brings: "Intégrité de pré-authentification (protection contre la rétrogradation), chiffrement AES-GCM (plus rapide), signature AES-GMAC selon le client, compression.", clients: "Windows 10 / 11 / Server 2016+, macOS récents, Linux cifs, smbclient." },
];

const ORDER: SmbDialect[] = SMB_DIALECTS.map((d) => d.id);

function idx(d: string | undefined, fallback: SmbDialect): number {
  if (!d) return ORDER.indexOf(fallback);
  const v = d.trim().toUpperCase();
  if (v.startsWith("SMB2_22")) return 1; // joker SMB2X : exclut SMB2_10 en min
  const exact = ORDER.indexOf(v as SmbDialect);
  if (exact >= 0) return exact;
  // préfixe, comme ksmbd_lookup_protocol_idx (dernier dialecte correspondant)
  for (let i = ORDER.length - 1; i >= 0; i--) if (ORDER[i]!.startsWith(v)) return i;
  return ORDER.indexOf(fallback);
}

export interface DialectRange {
  min: SmbDialect;
  max: SmbDialect;
}

export function readRange(doc: IniDocument): DialectRange {
  const g = findSection(doc, "global");
  let lo = idx(getValue(g, "server min protocol"), "SMB2_10");
  let hi = idx(getValue(g, "server max protocol"), "SMB3_11");
  if (lo > hi) [lo, hi] = [hi, lo];
  return { min: ORDER[lo]!, max: ORDER[hi]! };
}

export function enabledDialects(r: DialectRange): SmbDialect[] {
  return ORDER.slice(ORDER.indexOf(r.min), ORDER.indexOf(r.max) + 1);
}

export interface ToggleResult {
  ok: boolean;
  range: DialectRange;
  message: string;
  /** dialectes coupés en plus de celui demandé pour garder une plage contiguë */
  alsoDisabled: SmbDialect[];
  /** clients qui ne pourront plus se connecter */
  lostClients: string[];
}

/**
 * Active / désactive un dialecte. Activer étend la plage jusqu'à lui.
 * Désactiver une extrémité réduit la plage ; désactiver un dialecte au milieu
 * est impossible (ksmbd n'a qu'un min et un max) : refusé, sauf si
 * « trimTowards » indique de quel côté couper (le côté coupé est alors listé).
 */
export function toggleDialect(r: DialectRange, d: SmbDialect, on: boolean, trimTowards?: "low" | "high"): ToggleResult {
  const lo = ORDER.indexOf(r.min);
  const hi = ORDER.indexOf(r.max);
  const i = ORDER.indexOf(d);
  const lost = (ids: SmbDialect[]) => SMB_DIALECTS.filter((x) => ids.includes(x.id)).map((x) => `${x.label} : ${x.clients}`);
  if (on) {
    const nlo = Math.min(lo, i);
    const nhi = Math.max(hi, i);
    const range = { min: ORDER[nlo]!, max: ORDER[nhi]! };
    const added = ORDER.slice(nlo, nhi + 1).filter((x, k) => nlo + k < lo || nlo + k > hi);
    const extra = added.filter((x) => x !== d);
    return { ok: true, range, alsoDisabled: [], lostClients: [], message: extra.length ? `Plage contiguë : ${extra.join(", ")} sont aussi activés.` : `${d} activé.` };
  }
  if (i < lo || i > hi) return { ok: true, range: r, alsoDisabled: [], lostClients: [], message: `${d} est déjà désactivé.` };
  if (lo === hi) return { ok: false, range: r, alsoDisabled: [], lostClients: [], message: "Impossible de désactiver le dernier dialecte : ksmbd n'accepterait plus aucun client." };
  if (i === lo) return { ok: true, range: { min: ORDER[lo + 1]!, max: r.max }, alsoDisabled: [], lostClients: lost([d]), message: `server min protocol = ${ORDER[lo + 1]}.` };
  if (i === hi) return { ok: true, range: { min: r.min, max: ORDER[hi - 1]! }, alsoDisabled: [], lostClients: lost([d]), message: `server max protocol = ${ORDER[hi - 1]}.` };
  // au milieu
  if (!trimTowards) {
    return { ok: false, range: r, alsoDisabled: [], lostClients: [], message: `${d} est au milieu de la plage ${r.min}–${r.max} : ksmbd n'a qu'un minimum et un maximum, il est impossible de retirer un dialecte intermédiaire. Coupez plutôt depuis une extrémité.` };
  }
  if (trimTowards === "low") {
    const cut = ORDER.slice(lo, i + 1);
    return { ok: true, range: { min: ORDER[i + 1]!, max: r.max }, alsoDisabled: cut.filter((x) => x !== d), lostClients: lost(cut), message: `server min protocol = ${ORDER[i + 1]} (coupe aussi ${cut.filter((x) => x !== d).join(", ")}).` };
  }
  const cut = ORDER.slice(i, hi + 1);
  return { ok: true, range: { min: r.min, max: ORDER[i - 1]! }, alsoDisabled: cut.filter((x) => x !== d), lostClients: lost(cut), message: `server max protocol = ${ORDER[i - 1]} (coupe aussi ${cut.filter((x) => x !== d).join(", ")}).` };
}

/** Écrit la plage dans [global] ; une borne égale au défaut est retirée. */
export function writeRange(doc: IniDocument, r: DialectRange): void {
  const g = findSection(doc, "global");
  if (!g) return;
  if (r.min === "SMB2_10") deleteValue(g, "server min protocol");
  else setValue(g, "server min protocol", r.min);
  if (r.max === "SMB3_11") deleteValue(g, "server max protocol");
  else setValue(g, "server max protocol", r.max);
}

/** Conséquences de la plage sur les fonctions de ksmbd. */
export function rangeWarnings(doc: IniDocument, r: DialectRange): string[] {
  const g = findSection(doc, "global");
  const out: string[] = [];
  const hi = ORDER.indexOf(r.max);
  const multichannel = /^(yes|true|1|enable)/i.test(getValue(g, "server multi channel support") ?? "");
  if (hi < 1 && multichannel) out.push("server multi channel support = yes mais le dialecte max est SMB2_10 : multicanal et SMB Direct (RDMA) exigent SMB3_00 ou plus.");
  const enc = (getValue(g, "smb3 encryption") ?? "").toLowerCase();
  if (hi < 1 && enc.startsWith("mandatory")) out.push("smb3 encryption = mandatory avec un maximum SMB2_10 : aucun client ne pourra se connecter (le chiffrement arrive en SMB3_00).");
  if (hi < 3) out.push("Sans SMB3_11 : pas d'intégrité de pré-authentification ni d'AES-GCM ; Windows 10 / 11 et macOS se rabattent sur un dialecte plus ancien, plus lent pour le chiffrement.");
  if (ORDER.indexOf(r.min) === 0) out.push("SMB2_10 accepté : utile pour les vieux équipements, mais sans protection contre la rétrogradation de dialecte.");
  return out;
}

/** Réglages qui pèsent réellement sur le débit (groupe « Performances »). */
export const SMB_PERF_KEYS = [
  "server multi channel support",
  "smbd max io size",
  "smb2 max read",
  "smb2 max write",
  "smb2 max trans",
  "smb2 max credits",
  "server signing",
  "smb3 encryption",
  "smb2 leases",
  "durable handles",
];
