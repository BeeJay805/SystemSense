import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { createRequire } from "node:module";
import { describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const { LayaSetupClient } = require("../electron/laya-setup-client.cjs");
const snapshot = {
  state: "ready_to_install",
  stage: "idle",
  reason_code: null,
  can_install: true,
  existing_install: false,
};
function setup() {
  const child = Object.assign(new EventEmitter(), {
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    kill: vi.fn(() => true),
  });
  const commands: string[] = [];
  child.stdin.on("data", (line) => commands.push(String(line)));
  const launch = vi.fn(() => child);
  return {
    child,
    commands,
    launch,
    client: new LayaSetupClient("C:\\fixed\\investigator.exe", launch),
  };
}

describe("dedicated local setup pipe", () => {
  it("launches only the fixed setup mode and serializes exact requests", async () => {
    const { client, launch, child, commands } = setup();
    const first = client.request("status");
    const second = client.request("install");
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    expect(launch).toHaveBeenCalledWith(
      "C:\\fixed\\investigator.exe",
      ["--laya-setup"],
      { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
    );
    child.stdout.write(JSON.stringify(snapshot) + "\n");
    await expect(first).resolves.toEqual(snapshot);
    await vi.waitFor(() => expect(commands).toHaveLength(2));
    child.stdout.write(
      JSON.stringify({ ...snapshot, state: "installing", can_install: false }) +
        "\n",
    );
    await second;
    expect(commands).toEqual(['{"type":"status"}\n', '{"type":"install"}\n']);
    child.emit("exit", 0);
  });

  it("waits for the child to exit after EOF, without pretending cancellation is done", async () => {
    const { client, child } = setup();
    const request = client.request("status");
    await vi.waitFor(() => expect(child.stdin.readableLength).toBe(0));
    await Promise.resolve();
    child.stdout.write(JSON.stringify(snapshot) + "\n");
    await request;
    let closed = false;
    const closing = client.close().then(() => {
      closed = true;
    });
    await Promise.resolve();
    expect(child.stdin.writableEnded).toBe(true);
    expect(closed).toBe(false);
    child.emit("exit", 0);
    await closing;
    expect(closed).toBe(true);
  });

  it("fails closed on an oversized response and never restarts or retries", async () => {
    const { client, child, launch, commands } = setup();
    const request = client.request("install");
    const rejected = expect(request).rejects.toThrow("stopped responding");
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    child.stdout.write("x".repeat(4097));
    await rejected;
    expect(child.stdin.writableEnded).toBe(true);
    await expect(client.request("install")).rejects.toThrow("unavailable");
    expect(launch).toHaveBeenCalledTimes(1);
    child.emit("exit", 1);
  });

  it("rejects all non-protocol commands before spawning", async () => {
    const { client, launch } = setup();
    await expect(client.request("powershell")).rejects.toThrow("Invalid");
    expect(launch).not.toHaveBeenCalled();
  });

  it("bounds EOF shutdown by terminating only its owned setup child", async () => {
    const { client, child, commands } = setup();
    const request = client.request("status");
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    child.stdout.write(JSON.stringify(snapshot) + "\n");
    await request;
    vi.useFakeTimers();
    try {
      child.kill.mockImplementation(() => {
        child.emit("exit", 1);
        return true;
      });
      const closing = client.close();
      await vi.advanceTimersByTimeAsync(29999);
      expect(child.kill).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await closing;
      expect(child.kill).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reports an unresolved shutdown when the owned child never exits", async () => {
    const { client, child, commands } = setup();
    const request = client.request("status");
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    child.stdout.write(JSON.stringify(snapshot) + "\n");
    await request;
    vi.useFakeTimers();
    try {
      child.kill.mockReturnValue(false);
      const rejected = expect(client.close()).rejects.toThrow(
        "could not be confirmed",
      );
      await vi.advanceTimersByTimeAsync(35000);
      await rejected;
      expect(child.kill).toHaveBeenCalledTimes(1);
      child.emit("exit", 1);
    } finally {
      vi.useRealTimers();
    }
  });
});
