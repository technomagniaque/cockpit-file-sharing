/**
 * Lecture / écriture des fichiers de configuration smb.conf et ksmbd.conf.
 *
 * Deux « saveurs », car Samba et ksmbd-tools ne lisent pas le même fichier
 * de la même façon :
 *
 * | | samba | ksmbd (config_parser.c) |
 * |---|---|---|
 * | comparaison des clés | casse, espaces et « _ » ignorés | casse ignorée seulement |
 * | doublons | la dernière occurrence gagne | la première gagne |
 * | continuation « \ » | oui | non |
 * | « ; » ou « # » dans une valeur | gardés | la valeur s'arrête là |
 * | valeur vide | définit la clé à vide | clé ignorée |
 * | ligne sans « = » ou clé hors section | ignorée | fichier rejeté (erreur) |
 */
import { normalizeKey } from "./ksmbd-params";

export type IniFlavor = "samba" | "ksmbd";

export interface IniEntry {
  key: string;
  value: string;
}

export interface IniSection {
  name: string;
  entries: IniEntry[];
  /** règle de comparaison des clés ; « samba » par défaut */
  flavor?: IniFlavor;
}

export interface IniError {
  line: number;
  text: string;
  reason: string;
}

export interface IniDocument {
  sections: IniSection[];
  flavor?: IniFlavor;
  /** lignes que ksmbd-tools rejetterait (saveur ksmbd seulement) */
  errors?: IniError[];
  /** valeurs tronquées par ksmbd-tools au premier « ; » ou « # » */
  truncated?: { section: string; key: string; raw: string; value: string }[];
}

/** Normalisation de clé selon la saveur. */
export function keyNorm(key: string, flavor: IniFlavor = "samba"): string {
  return flavor === "ksmbd" ? key.trim().toLowerCase() : normalizeKey(key);
}

// eslint-disable-next-line no-control-regex
const isPrintable = (s: string) => !/[\x00-\x08\x0a-\x1f\x7f]/.test(s);

export function parseIni(text: string, flavor: IniFlavor = "samba"): IniDocument {
  const doc: IniDocument = { sections: [], flavor, errors: [], truncated: [] };
  let current: IniSection | null = null;
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  let pending = "";
  let pendingStart = 0;
  lines.forEach((raw, idx) => {
    const lineNo = idx + 1;
    let line = pending + raw;
    const startLine = pending ? pendingStart : lineNo;
    pending = "";
    if (flavor === "samba" && /\\\s*$/.test(line) && !/^\s*[;#]/.test(line)) {
      pending = line.replace(/\\\s*$/, " ");
      pendingStart = startLine;
      return;
    }
    line = line.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) return;
    const sec = /^\[([^\]]+)\]/.exec(line);
    if (sec) {
      const name = sec[1]!.trim();
      current = findSection(doc, name) ?? { name, entries: [], flavor };
      if (!doc.sections.includes(current)) doc.sections.push(current);
      return;
    }
    const eq = line.indexOf("=");
    if (eq < 0) {
      if (flavor === "ksmbd") doc.errors!.push({ line: startLine, text: line, reason: "ligne sans « = » : ksmbd-tools rejette tout le fichier" });
      return;
    }
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (!current) {
      if (flavor === "ksmbd") {
        doc.errors!.push({ line: startLine, text: line, reason: "paramètre avant toute section : rejeté par ksmbd-tools" });
        return;
      }
      current = findSection(doc, "global") ?? { name: "global", entries: [], flavor };
      if (!doc.sections.includes(current)) doc.sections.push(current);
    }
    if (flavor === "ksmbd") {
      const cut = value.search(/[;#]/);
      if (cut >= 0) {
        const kept = value.slice(0, cut).trimEnd();
        if (kept) doc.truncated!.push({ section: current.name, key, raw: value, value: kept });
        value = kept;
      }
      if (!isPrintable(value)) {
        doc.errors!.push({ line: startLine, text: line, reason: "caractère non imprimable dans la valeur" });
        return;
      }
      // valeur vide : ksmbd-tools n'enregistre pas la clé ; première occurrence gagnante
      if (value === "" || getValue(current, key) !== undefined) return;
    }
    setValue(current, key, value);
  });
  return doc;
}

export function findSection(doc: IniDocument, name: string): IniSection | undefined {
  const n = name.toLowerCase();
  return doc.sections.find((s) => s.name.toLowerCase() === n);
}

export function getValue(section: IniSection | undefined, key: string): string | undefined {
  if (!section) return undefined;
  const n = keyNorm(key, section.flavor);
  for (let i = section.entries.length - 1; i >= 0; i--) {
    const e = section.entries[i]!;
    if (keyNorm(e.key, section.flavor) === n) return e.value;
  }
  return undefined;
}

/** Remplace (ou ajoute) une clé ; une seule occurrence est conservée. */
export function setValue(section: IniSection, key: string, value: string): void {
  const n = keyNorm(key, section.flavor);
  const idx = section.entries.findIndex((e) => keyNorm(e.key, section.flavor) === n);
  if (idx >= 0) {
    section.entries[idx] = { key, value };
    section.entries = section.entries.filter((e, i) => i === idx || keyNorm(e.key, section.flavor) !== n);
  } else {
    section.entries.push({ key, value });
  }
}

export function deleteValue(section: IniSection, key: string): void {
  const n = keyNorm(key, section.flavor);
  section.entries = section.entries.filter((e) => keyNorm(e.key, section.flavor) !== n);
}

export function serializeIni(doc: IniDocument, header: string[] = []): string {
  const out: string[] = header.map((h) => `; ${h}`.trimEnd());
  if (out.length) out.push("");
  for (const s of doc.sections) {
    out.push(`[${s.name}]`);
    for (const e of s.entries) out.push(`\t${e.key} = ${e.value}`);
    out.push("");
  }
  return out.join("\n");
}

export function cloneDoc(doc: IniDocument): IniDocument {
  return {
    flavor: doc.flavor,
    sections: doc.sections.map((s) => ({ name: s.name, flavor: s.flavor, entries: s.entries.map((e) => ({ ...e })) })),
  };
}
