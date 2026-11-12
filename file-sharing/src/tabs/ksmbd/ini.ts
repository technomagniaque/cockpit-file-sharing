/**
 * Lecture / écriture minimaliste des fichiers de configuration de type
 * smb.conf / ksmbd.conf.
 *
 * - commentaires « ; » et « # » en début de ligne
 * - continuation de ligne par « \ » final (syntaxe Samba)
 * - paramètres placés avant toute section rattachés à [global]
 * - l'ordre des sections et des clés est conservé
 */
import { normalizeKey } from "./ksmbd-params";

export interface IniEntry {
  key: string;
  value: string;
}

export interface IniSection {
  name: string;
  entries: IniEntry[];
}

export interface IniDocument {
  sections: IniSection[];
}

/**
 * @param duplicates « last » : la dernière occurrence d'une clé gagne (Samba) ;
 *                   « first » : la première gagne (ksmbd-tools).
 */
export function parseIni(text: string, duplicates: "last" | "first" = "last"): IniDocument {
  const doc: IniDocument = { sections: [] };
  let current: IniSection | null = null;
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  let pending = "";
  for (const raw of lines) {
    let line = pending + raw;
    pending = "";
    if (/\\\s*$/.test(line) && !/^\s*[;#]/.test(line)) {
      pending = line.replace(/\\\s*$/, " ");
      continue;
    }
    line = line.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    const sec = /^\[([^\]]+)\]/.exec(line);
    if (sec) {
      const name = sec[1]!.trim();
      current = findSection(doc, name) ?? { name, entries: [] };
      if (!doc.sections.includes(current)) doc.sections.push(current);
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (!current) {
      current = findSection(doc, "global") ?? { name: "global", entries: [] };
      if (!doc.sections.includes(current)) doc.sections.push(current);
    }
    if (duplicates === "first") {
      // ksmbd-tools ignore les valeurs vides (ou commentaire seul) puis garde la première
      if (value === "" || /^[;#]/.test(value) || getValue(current, key) !== undefined) continue;
    }
    setValue(current, key, value);
  }
  return doc;
}

export function findSection(doc: IniDocument, name: string): IniSection | undefined {
  const n = name.toLowerCase();
  return doc.sections.find((s) => s.name.toLowerCase() === n);
}

export function getValue(section: IniSection | undefined, key: string): string | undefined {
  if (!section) return undefined;
  const n = normalizeKey(key);
  for (let i = section.entries.length - 1; i >= 0; i--) {
    const e = section.entries[i]!;
    if (normalizeKey(e.key) === n) return e.value;
  }
  return undefined;
}

/** Remplace (ou ajoute) une clé ; la dernière occurrence gagne comme dans Samba. */
export function setValue(section: IniSection, key: string, value: string): void {
  const n = normalizeKey(key);
  const idx = section.entries.findIndex((e) => normalizeKey(e.key) === n);
  if (idx >= 0) {
    section.entries[idx] = { key, value };
    section.entries = section.entries.filter((e, i) => i === idx || normalizeKey(e.key) !== n);
  } else {
    section.entries.push({ key, value });
  }
}

export function deleteValue(section: IniSection, key: string): void {
  const n = normalizeKey(key);
  section.entries = section.entries.filter((e) => normalizeKey(e.key) !== n);
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
  return { sections: doc.sections.map((s) => ({ name: s.name, entries: s.entries.map((e) => ({ ...e })) })) };
}
