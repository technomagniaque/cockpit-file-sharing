import { suite, test, expect } from "vitest";
import { parseIni, findSection, getValue } from "./ini";
import { readRange, toggleDialect, writeRange, enabledDialects, rangeWarnings } from "./smb-dialects";

suite("dialectes SMB : plage contiguë", () => {
  test("défauts et lecture", () => {
    expect(readRange(parseIni("[global]\n", "ksmbd"))).toEqual({ min: "SMB2_10", max: "SMB3_11" });
    expect(readRange(parseIni("[global]\n\tserver min protocol = SMB2_22\n", "ksmbd")).min).toBe("SMB3_00");
  });
  test("couper une extrémité", () => {
    const r = toggleDialect({ min: "SMB2_10", max: "SMB3_11" }, "SMB2_10", false);
    expect(r.ok).toBe(true);
    expect(r.range).toEqual({ min: "SMB3_00", max: "SMB3_11" });
    expect(r.lostClients[0]).toContain("Windows 7");
  });
  test("couper au milieu : refusé sans choix de côté", () => {
    const r = toggleDialect({ min: "SMB2_10", max: "SMB3_11" }, "SMB3_02", false);
    expect(r.ok).toBe(false);
    expect(r.message).toContain("milieu");
  });
  test("couper au milieu avec côté : plage ajustée et dialectes perdus listés", () => {
    const r = toggleDialect({ min: "SMB2_10", max: "SMB3_11" }, "SMB3_00", false, "low");
    expect(r.range).toEqual({ min: "SMB3_02", max: "SMB3_11" });
    expect(r.alsoDisabled).toEqual(["SMB2_10"]);
    const h = toggleDialect({ min: "SMB2_10", max: "SMB3_11" }, "SMB3_02", false, "high");
    expect(h.range).toEqual({ min: "SMB2_10", max: "SMB3_00" });
    expect(h.alsoDisabled).toEqual(["SMB3_11"]);
  });
  test("dernier dialecte : refusé", () => {
    expect(toggleDialect({ min: "SMB3_11", max: "SMB3_11" }, "SMB3_11", false).ok).toBe(false);
  });
  test("activer étend la plage de façon contiguë", () => {
    const r = toggleDialect({ min: "SMB3_11", max: "SMB3_11" }, "SMB3_00", true);
    expect(enabledDialects(r.range)).toEqual(["SMB3_00", "SMB3_02", "SMB3_11"]);
    expect(r.message).toContain("SMB3_02");
  });
  test("écriture : bornes par défaut retirées", () => {
    const doc = parseIni("[global]\n\tserver min protocol = SMB2_10\n", "ksmbd");
    writeRange(doc, { min: "SMB3_00", max: "SMB3_11" });
    const g = findSection(doc, "global")!;
    expect(getValue(g, "server min protocol")).toBe("SMB3_00");
    expect(getValue(g, "server max protocol")).toBeUndefined();
  });
  test("conséquences : multicanal sans SMB3", () => {
    const doc = parseIni("[global]\n\tserver multi channel support = yes\n", "ksmbd");
    expect(rangeWarnings(doc, { min: "SMB2_10", max: "SMB2_10" }).join(" ")).toContain("multicanal");
  });
});
