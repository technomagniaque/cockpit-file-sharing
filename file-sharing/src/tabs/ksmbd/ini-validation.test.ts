import { suite, test, expect } from "vitest";
import { parseIni, serializeIni, setValue, getValue, findSection, shareNameError, KSMBD_MAX_SHARE_NAME_BYTES } from "./ini";

suite("noms de partage et sérialisation sûre", () => {
  test("noms valides", () => {
    expect(shareNameError("d1")).toBeUndefined();
    expect(shareNameError("Données-partagées_2", ["p1"])).toBeUndefined();
    expect(shareNameError("homes")).toBeUndefined();
  });
  test("noms refusés", () => {
    expect(shareNameError("")).toBe("nom vide");
    expect(shareNameError(" d1")).toContain("espace");
    expect(shareNameError("GLOBAL")).toContain("réservé");
    expect(shareNameError("IPC$")).toContain("réservé");
    expect(shareNameError("D1", ["d1"])).toContain("existe déjà");
    for (const n of ["a]b", "a[b", "a;b", "a#b", "a=b", "a\nb", "a\\b", "a/b", "a:b", "a*b", "a?b", 'a"b', "a<b", "a|b"]) {
      expect(shareNameError(n), n).toContain("caractère interdit");
    }
    expect(shareNameError("x".repeat(KSMBD_MAX_SHARE_NAME_BYTES))).toBeUndefined();
    expect(shareNameError("x".repeat(KSMBD_MAX_SHARE_NAME_BYTES + 1))).toContain("trop long");
    expect(shareNameError("é".repeat(32))).toContain("trop long"); // 64 octets en UTF-8
  });
  test("un saut de ligne dans une valeur ou un nom n'injecte ni directive ni section", () => {
    const doc = parseIni("[global]\n\tworkgroup = WG\n[s]\n\tpath = /tank/s\n", "ksmbd");
    setValue(findSection(doc, "s")!, "comment", "ok\n[pirate]\n\tpath = /\n\tguest ok = yes");
    doc.sections.push({ name: "x]\n[y", entries: [{ key: "path\nguest ok", value: "/t" }], flavor: "ksmbd" });
    const text = serializeIni(doc, ["en-tête\n[global]"]);
    const back = parseIni(text, "ksmbd");
    // un nom contenant « ] » (refusé par shareNameError) est tronqué à la relecture, mais ne crée aucune section
    expect(back.sections.map((s) => s.name)).toEqual(["global", "s", "x"]);
    expect(getValue(findSection(back, "s"), "comment")).toBe("ok [pirate] \tpath = / \tguest ok = yes");
    expect(findSection(back, "pirate")).toBeUndefined();
    expect(text.split("\n").filter((l) => l.trim().startsWith("[")).length).toBe(3);
  });
});
