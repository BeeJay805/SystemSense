import { createRequire } from "node:module";
import { describe, it, expect, vi } from "vitest";
const require = createRequire(import.meta.url);
const {
  LocalJsonRequests,
  createJsonFileAction,
} = require("../electron/local-json.cjs");
const caseId = "case_" + "a".repeat(32);

describe("native JSON file command boundary", () => {
  it("sends one selected path only to the owned pipe and accepts its matching case receipt", async () => {
    const send = vi.fn();
    const requests = new LocalJsonRequests({ send });
    const result = requests.start("C:\\private\\config.json");
    const command = JSON.parse(send.mock.calls[0][0]);
    expect(command).toMatchObject({
      type: "start_local_json_case",
      selected_path: "C:\\private\\config.json",
    });
    expect(command.request_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(() => requests.start("C:\\other.json")).toThrow(/already/);
    expect(
      requests.receive({
        type: "local_json_case_started",
        request_id: "unknown",
        case_id: caseId,
      }),
    ).toBe(false);
    requests.receive({
      type: "local_json_case_started",
      request_id: command.request_id,
      case_id: caseId,
    });
    await expect(result).resolves.toBe(caseId);
  });

  it.each([
    { case_id: "../../private" },
    { case_id: caseId, selected_path: "C:\\private\\config.json" },
  ])(
    "rejects malformed or overbroad receipts without exposing data",
    async (receipt) => {
      const send = vi.fn();
      const requests = new LocalJsonRequests({ send });
      const result = requests.start("C:\\private\\config.json");
      const rejected = expect(result).rejects.toThrow(/not recognized/);
      const command = JSON.parse(send.mock.calls[0][0]);
      requests.receive({
        type: "local_json_case_started",
        request_id: command.request_id,
        ...receipt,
      });
      await rejected;
    },
  );

  it("maps bounded errors without showing arbitrary backend messages", async () => {
    const send = vi.fn();
    const requests = new LocalJsonRequests({ send });
    const result = requests.start("C:\\private\\config.json");
    const rejected = expect(result).rejects.toThrow(/256 KiB/);
    const command = JSON.parse(send.mock.calls[0][0]);
    requests.receive({
      type: "local_json_case_error",
      request_id: command.request_id,
      error_code: "file_too_large",
    });
    await rejected;
  });

  it("hides unknown backend errors and rejects a failed pipe write", async () => {
    const send = vi.fn();
    const requests = new LocalJsonRequests({ send });
    const result = requests.start("C:\\private\\config.json");
    const rejected = expect(result).rejects.toThrow(/not recognized/);
    const command = JSON.parse(send.mock.calls[0][0]);
    requests.receive({
      type: "local_json_case_error",
      request_id: command.request_id,
      error_code: "C:\\private\\config.json contains secret text",
    });
    await rejected;
    const broken = new LocalJsonRequests({
      send: () => {
        throw Error("private pipe payload");
      },
    });
    await expect(broken.start("C:\\private\\config.json")).rejects.toThrow(
      /connection/,
    );
  });

  it("does not retry a timed out request that might have started", async () => {
    vi.useFakeTimers();
    try {
      const send = vi.fn();
      const requests = new LocalJsonRequests({ send });
      const result = requests.start("C:\\private\\config.json");
      const rejected = expect(result).rejects.toThrow(/may have started/);
      await vi.advanceTimersByTimeAsync(10000);
      await rejected;
      expect(send).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects a pending request when the owned backend exits", async () => {
    const requests = new LocalJsonRequests({ send: vi.fn() });
    const result = requests.start("C:\\private\\config.json");
    const rejected = expect(result).rejects.toThrow(/connection/);
    requests.close();
    await rejected;
    expect(() => requests.start("C:\\private\\config.json")).toThrow(
      /connection/,
    );
  });
});

describe("native JSON file picker flow", () => {
  function setup() {
    const chooseFile = vi.fn().mockResolvedValue({
      canceled: false,
      filePaths: ["C:\\private\\config.json"],
    });
    const capabilities = vi.fn().mockResolvedValue({
      read_only: true,
      active_case_id: null,
      local_json_task: { enabled: true },
    });
    const startCase = vi.fn().mockResolvedValue(caseId);
    const getCase = vi
      .fn()
      .mockResolvedValue({ case_id: caseId, status: "running" });
    return { chooseFile, capabilities, startCase, getCase };
  }

  it("opens a single-file picker and returns the case without the selected path", async () => {
    const deps = setup();
    const action = createJsonFileAction(deps);
    await expect(action()).resolves.toEqual({
      case: { case_id: caseId, status: "running" },
    });
    expect(deps.chooseFile).toHaveBeenCalledWith(
      expect.objectContaining({ properties: ["openFile"] }),
    );
    expect(deps.startCase).toHaveBeenCalledWith("C:\\private\\config.json");
    expect(deps.getCase).toHaveBeenCalledWith(caseId);
  });

  it("does not read or start a case when the picker is cancelled", async () => {
    const deps = setup();
    deps.chooseFile.mockResolvedValue({ canceled: true, filePaths: [] });
    await expect(createJsonFileAction(deps)()).resolves.toEqual({
      cancelled: true,
    });
    expect(deps.startCase).not.toHaveBeenCalled();
  });

  it("keeps one picker open and rejects multi-file results", async () => {
    const deps = setup();
    let picked: (value: unknown) => void = () => {};
    deps.chooseFile.mockReturnValue(
      new Promise((resolve) => {
        picked = resolve;
      }),
    );
    const action = createJsonFileAction(deps);
    const first = action();
    const rejected = expect(first).rejects.toThrow(/one regular JSON file/);
    await expect(action()).rejects.toThrow(/already/);
    picked({ canceled: false, filePaths: ["C:\\one.json", "C:\\two.json"] });
    await rejected;
    expect(deps.startCase).not.toHaveBeenCalled();
  });

  it("does not let a caller supply a path instead of selecting it", async () => {
    const deps = setup();
    await expect(
      createJsonFileAction(deps)("C:\\private\\config.json"),
    ).rejects.toThrow(/native file picker/);
    expect(deps.chooseFile).not.toHaveBeenCalled();
    expect(deps.startCase).not.toHaveBeenCalled();
  });

  it("checks active case ownership again after the picker closes", async () => {
    const deps = setup();
    deps.capabilities
      .mockResolvedValueOnce({
        read_only: true,
        local_json_task: { enabled: true },
      })
      .mockResolvedValueOnce({ read_only: true, active_case_id: caseId });
    await expect(createJsonFileAction(deps)()).rejects.toThrow(
      /active investigation/,
    );
    expect(deps.startCase).not.toHaveBeenCalled();
  });

  it.each([
    { read_only: true, active_case_id: caseId },
    { read_only: true, inference: { start_allowed: false } },
    { read_only: false },
    { read_only: true },
  ])("keeps unavailable checks out of the native picker", async (caps) => {
    const deps = setup();
    deps.capabilities.mockResolvedValue(caps);
    await expect(createJsonFileAction(deps)()).rejects.toThrow();
    expect(deps.chooseFile).not.toHaveBeenCalled();
    expect(deps.startCase).not.toHaveBeenCalled();
  });
});
