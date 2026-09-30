import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { describe, it, expect, vi } from "vitest";
const require = createRequire(import.meta.url);
const { createJsonRepairAction } = require("../electron/json-repair.cjs");

const caseId = "case_" + "a".repeat(32);
const now = Date.parse("2026-09-30T00:00:00Z");
const destination = "C:\\private\\corrected.json";
const offer = "offer_" + "b".repeat(32);
const proposal = "proposal_" + "c".repeat(32);
const digest = "d".repeat(64);
const preview = {
  case_id: caseId,
  operation: "remove_utf8_bom_copy",
  capture_sha256: "1".repeat(64),
  captured_at: "2026-09-29T23:59:00Z",
  source_size_bytes: 5,
  output_sha256: "2".repeat(64),
  output_size_bytes: 2,
  expires_at: "2026-09-30T00:04:00Z",
};

function setup() {
  const request = vi.fn(async (command) => {
    const base = { request_id: command.request_id };
    if (command.type === "json_repair_prepare")
      return {
        ...base,
        type: "json_repair_prepared",
        offer_token: offer,
        preview,
      };
    if (command.type === "json_repair_bind_destination")
      return {
        ...base,
        type: "json_repair_bound",
        proposal_token: proposal,
        proposal_digest: digest,
        destination_path_sha256: createHash("sha256")
          .update(destination, "utf8")
          .digest("hex"),
        preview,
      };
    if (
      command.type === "json_repair_execute" ||
      command.type === "json_repair_status"
    )
      return {
        ...base,
        type: "json_repair_result",
        operation_id: "operation_" + "e".repeat(32),
        status: "verified",
        verification: "independent_output_read",
        capture_sha256: preview.capture_sha256,
        source_size_bytes: preview.source_size_bytes,
        output_sha256: preview.output_sha256,
        output_size_bytes: preview.output_size_bytes,
        evidence_ids: ["ev_" + "f".repeat(32)],
      };
    return { ...base, type: "json_repair_abandoned" };
  });
  const showSaveDialog = vi
    .fn()
    .mockResolvedValue({ canceled: false, filePath: destination });
  const showMessageBox = vi.fn().mockResolvedValue({ response: 1 });
  const deps = { request, showSaveDialog, showMessageBox, now: () => now };
  return { ...deps, begin: createJsonRepairAction(deps) };
}

describe("captured JSON copy approval", () => {
  it("binds native selection and explicit approval before one execution", async () => {
    const flow = setup();
    const result = await flow.begin(caseId);
    expect(result.status).toBe("verified");
    expect(flow.request.mock.calls.map(([command]) => command.type)).toEqual([
      "json_repair_prepare",
      "json_repair_bind_destination",
      "json_repair_execute",
    ]);
    const commands = flow.request.mock.calls.map(([command]) => command);
    expect(new Set(commands.map((command) => command.request_id)).size).toBe(3);
    commands.forEach((command) =>
      expect(command.request_id).toMatch(
        /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/,
      ),
    );
    expect(commands[1]).toMatchObject({
      offer_token: offer,
      destination_path: destination,
    });
    expect(commands[2]).toMatchObject({
      proposal_token: proposal,
      proposal_digest: digest,
    });
    const confirmation = flow.showMessageBox.mock.calls[0][0];
    expect(confirmation.defaultId).toBe(0);
    expect(confirmation.cancelId).toBe(0);
    expect(confirmation.detail).toContain(preview.captured_at);
    expect(confirmation.detail).toContain(preview.capture_sha256);
    expect(confirmation.detail).toContain(caseId);
    expect(confirmation.detail).toContain(destination);
    expect(confirmation.detail).toMatch(/exactly 3 bytes/);
    expect(confirmation.detail).toMatch(
      /Current disk contents and application recovery are unverified/,
    );
    expect(JSON.stringify(result).includes(destination)).toBe(false);
    expect(JSON.stringify(result).includes(proposal)).toBe(false);
  });

  it.each(["save", "confirmation"])(
    "abandons on %s cancellation without execute",
    async (stage) => {
      const flow = setup();
      if (stage === "save")
        flow.showSaveDialog.mockResolvedValue({ canceled: true });
      else flow.showMessageBox.mockResolvedValue({ response: 0 });
      await expect(flow.begin(caseId)).resolves.toEqual({ cancelled: true });
      expect(
        flow.request.mock.calls.some(
          ([command]) => command.type === "json_repair_execute",
        ),
      ).toBe(false);
      expect(flow.request.mock.calls.at(-1)?.[0]).toMatchObject({
        type: "json_repair_abandon",
        offer_token: offer,
      });
    },
  );

  it("abandons the offer when binding fails and hides raw error content", async () => {
    const flow = setup();
    const original = flow.request.getMockImplementation()!;
    flow.request.mockImplementation(async (command) => {
      if (command.type === "json_repair_bind_destination")
        throw Error("secret " + destination);
      return original(command);
    });
    await expect(flow.begin(caseId)).rejects.toThrow(
      "The JSON copy could not be prepared. No copy was requested.",
    );
    expect(flow.showMessageBox).not.toHaveBeenCalled();
    expect(flow.request.mock.calls.at(-1)?.[0].type).toBe(
      "json_repair_abandon",
    );
  });

  it.each([
    { case_id: "case_" + "9".repeat(32) },
    { operation: "replace_original" },
    { source_size_bytes: 6 },
    { source_size_bytes: 262145, output_size_bytes: 262142 },
    { source_size_bytes: 3, output_size_bytes: 0 },
    { captured_at: "2026-02-31T00:00:00Z" },
    { captured_at: "2026-09-30T00:01:00Z" },
    { expires_at: "2026-09-30T00:05:01Z" },
    { extra_authority: "path" },
  ])(
    "refuses an invalid preview before opening a native dialog: %j",
    async (change) => {
      const flow = setup();
      const original = flow.request.getMockImplementation()!;
      flow.request.mockImplementation(async (command) => {
        const response = await original(command);
        return command.type === "json_repair_prepare"
          ? { ...response, preview: { ...preview, ...change } }
          : response;
      });
      await expect(flow.begin(caseId)).rejects.toThrow(/not recognized/);
      expect(flow.showSaveDialog).not.toHaveBeenCalled();
      expect(flow.request.mock.calls.at(-1)?.[0].type).toBe(
        "json_repair_abandon",
      );
    },
  );

  it("does not treat a stored capture hash as authority after restart", async () => {
    const flow = setup();
    flow.request.mockImplementation(async (command) => ({
      type: "json_repair_error",
      request_id: command.request_id,
      error_code: "source_unavailable",
    }));
    await expect(flow.begin(caseId)).rejects.toThrow(/Check the file again/);
    expect(flow.showSaveDialog).not.toHaveBeenCalled();
    expect(flow.request.mock.calls.map(([command]) => command.type)).toEqual([
      "json_repair_prepare",
    ]);
  });

  it("reports failed abandonment without claiming cancellation closed the proposal", async () => {
    const flow = setup();
    const original = flow.request.getMockImplementation()!;
    flow.showSaveDialog.mockResolvedValue({ canceled: true });
    flow.request.mockImplementation(async (command) => {
      if (command.type === "json_repair_abandon") throw Error(destination);
      return original(command);
    });
    await expect(flow.begin(caseId)).rejects.toThrow(
      /approval could not be closed/,
    );
    expect(
      flow.request.mock.calls.filter(
        ([command]) => command.type === "json_repair_abandon",
      ),
    ).toHaveLength(1);
    expect(
      flow.request.mock.calls.some(
        ([command]) => command.type === "json_repair_execute",
      ),
    ).toBe(false);
  });

  it("serializes native approval flows and releases the slot after cancellation", async () => {
    const flow = setup();
    let cancel!: (value: { canceled: boolean }) => void;
    flow.showSaveDialog.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          cancel = resolve;
        }),
    );
    const first = flow.begin(caseId);
    await vi.waitFor(() => expect(flow.showSaveDialog).toHaveBeenCalledOnce());
    await expect(flow.begin(caseId)).rejects.toThrow(/already open/);
    cancel({ canceled: true });
    await expect(first).resolves.toEqual({ cancelled: true });
    await expect(flow.begin(caseId)).resolves.toMatchObject({
      status: "verified",
    });
  });

  it("does not bind an offer that expired while the Save dialog was open", async () => {
    const flow = setup();
    let clock = now;
    const begin = createJsonRepairAction({ ...flow, now: () => clock });
    flow.showSaveDialog.mockImplementation(async () => {
      clock = Date.parse(preview.expires_at);
      return { canceled: false, filePath: destination };
    });
    await expect(begin(caseId)).rejects.toThrow(/expired/);
    expect(flow.request.mock.calls.map(([command]) => command.type)).toEqual([
      "json_repair_prepare",
      "json_repair_abandon",
    ]);
  });

  it.each(["capture", "destination", "request"])(
    "rejects a rebound %s before confirmation",
    async (field) => {
      const flow = setup();
      const original = flow.request.getMockImplementation()!;
      flow.request.mockImplementation(async (command) => {
        const response = await original(command);
        if (command.type !== "json_repair_bind_destination") return response;
        return {
          ...response,
          ...(field === "capture"
            ? { preview: { ...preview, capture_sha256: "9".repeat(64) } }
            : {}),
          ...(field === "destination"
            ? { destination_path_sha256: "9".repeat(64) }
            : {}),
          ...(field === "request" ? { request_id: "unrelated" } : {}),
        };
      });
      await expect(flow.begin(caseId)).rejects.toThrow(/not recognized/);
      expect(flow.showMessageBox).not.toHaveBeenCalled();
      expect(flow.request.mock.calls.at(-1)?.[0].type).toBe(
        "json_repair_abandon",
      );
    },
  );

  it("refuses expiry during native approval and abandons the proposal", async () => {
    const flow = setup();
    let clock = now;
    const begin = createJsonRepairAction({ ...flow, now: () => clock });
    flow.showMessageBox.mockImplementation(async () => {
      clock = Date.parse(preview.expires_at);
      return { response: 1 };
    });
    await expect(begin(caseId)).rejects.toThrow(/expired/);
    expect(
      flow.request.mock.calls.some(
        ([command]) => command.type === "json_repair_execute",
      ),
    ).toBe(false);
    expect(flow.request.mock.calls.at(-1)?.[0].type).toBe(
      "json_repair_abandon",
    );
  });

  it("uses status after a lost execute acknowledgment and never executes twice", async () => {
    const flow = setup();
    const original = flow.request.getMockImplementation()!;
    flow.request.mockImplementation(async (command) => {
      if (command.type === "json_repair_execute")
        throw Error("lost acknowledgment");
      return original(command);
    });
    await expect(flow.begin(caseId)).resolves.toMatchObject({
      status: "verified",
    });
    expect(flow.request.mock.calls.map(([command]) => command.type)).toEqual([
      "json_repair_prepare",
      "json_repair_bind_destination",
      "json_repair_execute",
      "json_repair_status",
    ]);
    expect(flow.request.mock.calls.at(-1)?.[0]).toMatchObject({
      proposal_token: proposal,
    });
  });

  it.each(["verification", "evidence", "hash", "size", "operation", "private"])(
    "cannot turn an unsupported %s receipt into success",
    async (missing) => {
      const flow = setup();
      const original = flow.request.getMockImplementation()!;
      flow.request.mockImplementation(async (command) => {
        const response = await original(command);
        if (
          !["json_repair_execute", "json_repair_status"].includes(command.type)
        )
          return response;
        return {
          ...response,
          ...(missing === "verification"
            ? { verification: "echoed_candidate" }
            : {}),
          ...(missing === "evidence" ? { evidence_ids: [] } : {}),
          ...(missing === "hash" ? { output_sha256: "9".repeat(64) } : {}),
          ...(missing === "size" ? { output_size_bytes: 100 } : {}),
          ...(missing === "operation" ? { operation_id: "" } : {}),
          ...(missing === "private" ? { destination_path: destination } : {}),
        };
      });
      await expect(flow.begin(caseId)).resolves.toMatchObject({
        status: "uncertain",
      });
      expect(
        flow.request.mock.calls.filter(
          ([command]) => command.type === "json_repair_execute",
        ),
      ).toHaveLength(1);
    },
  );

  it("bounds a hung execution and returns uncertainty if status is unavailable", async () => {
    vi.useFakeTimers();
    try {
      const flow = setup();
      const original = flow.request.getMockImplementation()!;
      flow.request.mockImplementation(async (command) => {
        if (command.type === "json_repair_execute")
          return new Promise(() => {});
        if (command.type === "json_repair_status") throw Error("offline");
        return original(command);
      });
      const result = flow.begin(caseId);
      await vi.advanceTimersByTimeAsync(10001);
      await expect(result).resolves.toMatchObject({
        status: "uncertain",
        operation_id: null,
      });
      expect(
        flow.request.mock.calls.filter(
          ([command]) => command.type === "json_repair_execute",
        ),
      ).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects renderer paths, tokens, and approval arguments before any action", async () => {
    const flow = setup();
    await expect(
      flow.begin(caseId, { destination, approved: true }),
    ).rejects.toThrow(/case only/);
    await expect(flow.begin(destination)).rejects.toThrow(/case only/);
    expect(flow.request).not.toHaveBeenCalled();
  });
});
