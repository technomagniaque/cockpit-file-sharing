/**
 * Dialectes SMB de ksmbd : interrupteurs par dialecte, ramenés à la seule
 * chose que ksmbd sait faire, une PLAGE CONTIGUË « server min protocol » …
 * « server max protocol ».
 *
 * Vérifié dans le noyau (fs/smb/server/smb_common.c et smb_common.h,
 * identiques en v6.12 et HEAD sur ces points) :
 *  - indices : SMB21_PROT=2, SMB2X_PROT=3, SMB30_PROT=4, SMB302_PROT=5,
 *    SMB311_PROT=6 ; défauts min = 2, max = 6 (ksmbd_min/max_protocol).
 *  - dialectes SMB2+ négociables : SMB2_10, SMB3_00, SMB3_02, SMB3_11
 *    (smb2_protos[]) ; SMB2.0.2 et SMB1 n'existent pas dans ksmbd.
 *  - « SMB2_22 » (SMB2X_PROT, « SMB 2.??? ») n'est pas un dialecte : c'est le
 *    joker de la négociation multi-protocole lancée en SMB1. Son indice 3
 *    vaut SMB3_00 en minimum (exclut SMB2_10) et SMB2_10 en maximum.
 *  - ksmbd_lookup_protocol_idx : strncmp(valeur, nom, strlen(valeur)), donc
 *    la valeur est un PRÉFIXE du nom, sensible à la casse ; smb1_protos est
 *    parcouru en premier (du dernier au premier), puis smb2_protos (du dernier
 *    au premier). « SMB » ou « SMB2 » donnent donc SMB2X (3), « SMB3_0 »
 *    donne SMB3_02. Une valeur non reconnue (-1) est ignorée : la borne garde
 *    son défaut (transport_ipc.c ipc_server_config_on_startup).
 *  - supported_protocol : min_protocol <= idx <= max_protocol. Si min > max,
 *    aucun dialecte n'est accepté (pas d'inversion automatique).
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
  { id: "SMB3_00", label: "SMB 3.0", brings: "Multicanal, SMB Direct (RDMA), chiffrement AES-CCM, signature AES-CMAC. Pas de poignées persistantes annoncées en 3.0 par ksmbd.", clients: "Windows 8 / Server 2012." },
  { id: "SMB3_02", label: "SMB 3.0.2", brings: "Améliorations RDMA (invalidation à distance). Noyau 6.12 : poignées persistantes annoncées seulement avec « durable handles = yes » (absentes des noyaux récents).", clients: "Windows 8.1 / Server 2012 R2." },
  { id: "SMB3_11", label: "SMB 3.1.1", brings: "Intégrité de pré-authentification (protection contre la rétrogradation), chiffrement AES-GCM (plus rapide). Signature : HMAC-SHA256 / AES-CMAC seulement (pas d'AES-GMAC dans ksmbd). Compression : absente des noyaux 6.x (dont 6.12 de Debian 13), seulement noyaux 7.x : dépend du noyau actif, pas de la distribution. Noyau 6.12 : poignées persistantes avec « durable handles = yes ».", clients: "Windows 10 / 11 / Server 2016+, macOS récents, Linux cifs, smbclient." },
];

const ORDER: SmbDialect[] = SMB_DIALECTS.map((d) => d.id);

/** Indices du noyau (smb_common.h). */
const KIDX: Record<SmbDialect, number> = { SMB2_10: 2, SMB3_00: 4, SMB3_02: 5, SMB3_11: 6 };
const SMB1_PROTOS: [string, number][] = [["SMB2_10", 2], ["SMB2_22", 3]];
const SMB2_PROTOS: [string, number][] = [["SMB2_10", 2], ["SMB3_00", 4], ["SMB3_02", 5], ["SMB3_11", 6]];

/**
 * Émulation exacte de ksmbd_lookup_protocol_idx : indice noyau, ou -1 si la
 * valeur n'est reconnue par aucun nom (comparaison sensible à la casse, la
 * valeur doit être un préfixe du nom ; smb1_protos puis smb2_protos, chaque
 * table parcourue de la fin vers le début).
 */
export function kernelProtocolIdx(value: string): number {
  const str = value;
  if (!str) return -1;
  for (const table of [SMB1_PROTOS, SMB2_PROTOS]) {
    for (let i = table.length - 1; i >= 0; i--) {
      const [name, index] = table[i]!;
      if (name.startsWith(str)) return index;
    }
  }
  return -1;
}

function dialectsBetween(minIdx: number, maxIdx: number): SmbDialect[] {
  return ORDER.filter((d) => KIDX[d] >= minIdx && KIDX[d] <= maxIdx);
}

export interface DialectRange {
  min: SmbDialect;
  max: SmbDialect;
  /** plage vide (min > max après résolution) : aucun client accepté */
  empty?: boolean;
  /** remarques sur la lecture (valeur ignorée, joker, préfixe…) */
  notes?: string[];
}

function resolveBound(raw: string | undefined, kind: "min" | "max", notes: string[]): number {
  const def = kind === "min" ? 2 : 6;
  // ksmbd-tools transmet la valeur telle quelle (après coupure au premier « ; » / « # ») ; seul un espace final est ôté par le parseur
  const v = raw?.trim() ?? "";
  if (!v) return def;
  const k = kernelProtocolIdx(v);
  const label = `server ${kind} protocol = ${v}`;
  if (k < 0) {
    notes.push(`${label} : ignoré par ksmbd (aucun dialecte ne commence par « ${v} », comparaison sensible à la casse) — la borne garde son défaut (${kind === "min" ? "SMB2_10" : "SMB3_11"}).`);
    return def;
  }
  if (k === 3) notes.push(`${label} : joker SMB2X (indice 3) — vaut SMB3_00 en minimum et SMB2_10 en maximum.`);
  else {
    const exact = ORDER.find((d) => KIDX[d] === k)!;
    if (exact !== v) notes.push(`${label} : lu par ksmbd comme ${exact} (préfixe).`);
  }
  return k;
}

export function readRange(doc: IniDocument): DialectRange {
  const g = findSection(doc, "global");
  const notes: string[] = [];
  const lo = resolveBound(getValue(g, "server min protocol"), "min", notes);
  const hi = resolveBound(getValue(g, "server max protocol"), "max", notes);
  const list = dialectsBetween(lo, hi);
  if (!list.length) {
    notes.push("Plage vide : le minimum dépasse le maximum, ksmbd n'accepte aucun dialecte (aucune inversion automatique).");
    // bornes indicatives pour l'interface ; enabledDialects renverra []
    return { min: ORDER.find((d) => KIDX[d] >= lo) ?? "SMB3_11", max: [...ORDER].reverse().find((d) => KIDX[d] <= hi) ?? "SMB2_10", empty: true, notes };
  }
  return { min: list[0]!, max: list[list.length - 1]!, notes };
}

export function enabledDialects(r: DialectRange): SmbDialect[] {
  if (r.empty) return [];
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
  if (r.empty) {
    if (on) return { ok: true, range: { min: d, max: d }, alsoDisabled: [], lostClients: [], message: `Plage vide corrigée : ${d} seul.` };
    return { ok: true, range: r, alsoDisabled: [], lostClients: [], message: `${d} est déjà inactif (plage vide).` };
  }
  const lo = ORDER.indexOf(r.min);
  const hi = ORDER.indexOf(r.max);
  const i = ORDER.indexOf(d);
  const lost = (ids: SmbDialect[]) => SMB_DIALECTS.filter((x) => ids.includes(x.id)).map((x) => `${x.label} : ${x.clients}`);
  if (on) {
    const nlo = Math.min(lo, i);
    const nhi = Math.max(hi, i);
    const range: DialectRange = { min: ORDER[nlo]!, max: ORDER[nhi]! };
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
  if (r.empty) return out;
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
