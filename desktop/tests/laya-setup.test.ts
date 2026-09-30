import { createRequire } from "node:module";
import { describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const { createLayaSetupAction } = require("../electron/laya-setup.cjs");
const ready = {
  state: "ready_to_install",
  stage: "idle",
  reason_code: null,
  can_install: true,
  existing_install: false,
};

function setup() {
  const request = vi.fn(async (command: string) =>
    command === "install"
      ? { ...ready, state: "installing", can_install: false }
      : ready,
  );
  const checkIdle = vi.fn(async () => {});
  const confirm = vi.fn(async () => ({ response: 0 }));
  const action = createLayaSetupAction({ request, checkIdle, confirm });
  return { request, checkIdle, confirm, action };
}

describe("native Laya setup authorization", () => {
  it("uses a Cancel-default native dialog and does nothing when cancelled", async () => {
    const { action, confirm, request } = setup();
    await expect(action.install()).resolves.toEqual(ready);
    expect(confirm).toHaveBeenCalledWith(
      expect.objectContaining({ defaultId: 0, cancelId: 0 }),
    );
    expect(request.mock.calls).toEqual([["status"]]);
  });

  it("rechecks active work after approval before the fixed install request", async () => {
    const { action, confirm, checkIdle, request } = setup();
    confirm.mockResolvedValue({ response: 1 });
    await expect(action.install()).resolves.toMatchObject({
      state: "installing",
    });
    expect(checkIdle).toHaveBeenCalledTimes(2);
    expect(request.mock.calls).toEqual([["status"], ["install"]]);
    expect(action.busy).toBe(true);
  });

  it("never forwards renderer arguments as installation authority", async () => {
    const { action, request } = setup();
    await expect(action.install("C:\\custom.exe")).rejects.toThrow("arguments");
    await expect(action.status({ path: "anything" })).rejects.toThrow(
      "arguments",
    );
    await expect(action.cancel("anything")).rejects.toThrow("arguments");
    expect(request).not.toHaveBeenCalled();
  });

  it("blocks active work, including work that starts while consent is open", async () => {
    const { action, request, checkIdle, confirm } = setup();
    confirm.mockResolvedValue({ response: 1 });
    checkIdle
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(Error("active case"));
    await expect(action.install()).rejects.toThrow("active case");
    expect(request.mock.calls).toEqual([["status"]]);
    expect(action.busy).toBe(false);
  });

  it("reuses an existing installation without offering overwrite", async () => {
    const { action, request, confirm } = setup();
    request.mockResolvedValue({
      ...ready,
      state: "installed",
      can_install: false,
      existing_install: true,
    });
    await expect(action.install()).resolves.toMatchObject({
      state: "installed",
    });
    expect(confirm).not.toHaveBeenCalled();
    expect(request.mock.calls).toEqual([["status"]]);
  });

  it("rejects malformed or overbroad child status", async () => {
    const { action, request } = setup();
    const invalid = { ...ready, command: "powershell" };
    request.mockResolvedValue(invalid);
    await expect(action.status()).rejects.toThrow("recognized");
  });

  it("does not retry an uncertain install command", async () => {
    const { action, request, confirm } = setup();
    confirm.mockResolvedValue({ response: 1 });
    request
      .mockResolvedValueOnce(ready)
      .mockRejectedValueOnce(Error("pipe lost"));
    await expect(action.install()).rejects.toThrow("pipe lost");
    expect(request.mock.calls).toEqual([["status"], ["install"]]);
    expect(action.busy).toBe(true);
  });
});
