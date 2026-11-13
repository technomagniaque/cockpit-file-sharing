import { suite, test, expect } from "vitest";
import { parseIbvDevinfoSge, parseSgeRejection, smbDirectSgeIssues, SMB_DIRECT_MIN_SEND_SGE } from "./rdma-sge";

const IBV = [
  "hca_id:\tqedr0",
  "\ttransport:\t\t\tiWARP (1)",
  "\tmax_sge:\t\t\t4",
  "\tmax_sge_rd:\t\t\t4",
  "hca_id:\tiwp1s0",
  "\tmax_sge:\t\t\t4",
  "hca_id:\tcxgb4_0",
  "\tmax_sge_rd:\t\t\t17",
  "\tmax_sge:\t\t\t17",
].join("\n");

suite("limite SGE de SMB Direct", () => {
  test("max_sge lu par périphérique, max_sge_rd ignoré", () => {
    expect(parseIbvDevinfoSge(IBV)).toEqual([
      { dev: "qedr0", maxSge: 4 },
      { dev: "iwp1s0", maxSge: 4 },
      { dev: "cxgb4_0", maxSge: 17 },
    ]);
    expect(parseIbvDevinfoSge("")).toEqual([]);
  });
  test("refus de ksmbd repéré dans dmesg", () => {
    const d = "[  12.3] ksmbd: smb_direct: device iwp1s0 max_send_sge/max_recv_sge = 4/4 too small";
    expect(parseSgeRejection(d)).toEqual({ dev: "iwp1s0", send: 4, recv: 4 });
    expect(parseSgeRejection("ksmbd: kill command received")).toBeUndefined();
  });
  test("avertissement seulement sous le seuil, sans doublon avec dmesg", () => {
    expect(SMB_DIRECT_MIN_SEND_SGE).toBe(6);
    const issues = smbDirectSgeIssues(parseIbvDevinfoSge(IBV), { dev: "iwp1s0", send: 4, recv: 4 });
    expect(issues).toHaveLength(2);
    expect(issues[0]).toContain("SMB Direct impossible avec qedr0 : max_send_sge=4 < 6");
    expect(issues.join(" ")).not.toContain("cxgb4_0");
    expect(smbDirectSgeIssues([], { dev: "iwp1s0", send: 4, recv: 4 })[0]).toContain("ksmbd a refusé SMB Direct sur iwp1s0");
    expect(smbDirectSgeIssues([{ dev: "mlx5_0", maxSge: 30 }])).toEqual([]);
  });
});
