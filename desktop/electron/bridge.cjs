const CASE = /^case_[0-9a-f]{32}$/;
const CANDIDATE = /^proc_[0-9a-f]{32}$/;
function caseId(value) {
  if (typeof value !== "string" || !CASE.test(value))
    throw Error("Invalid case");
  return value;
}
function exact(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((k) => !keys.includes(k))
  )
    throw Error("Invalid request");
}
function routeFor(method, value) {
  switch (method) {
    case "capabilities":
      return { path: "/api/capabilities" };
    case "listCases":
      return { path: "/api/cases" };
    case "getCase":
      return { path: `/api/cases/${caseId(value)}` };
    case "exportCase":
      return { path: `/api/cases/${caseId(value)}/export` };
    case "cancel":
    case "resume":
      return { path: `/api/cases/${caseId(value)}/${method}`, body: {} };
    case "start": {
      exact(value, ["objective"]);
      if (
        typeof value.objective !== "string" ||
        !value.objective.trim() ||
        value.objective.trim().length > 2000
      )
        throw Error("Describe the problem in 1–2,000 characters.");
      return {
        path: "/api/cases",
        body: {
          objective: value.objective.trim(),
          budget_ms: 60000,
          max_rounds: 4,
        },
      };
    }
    case "selectTarget":
      exact(value, ["caseId", "candidateId"]);
      if (
        typeof value.candidateId !== "string" ||
        !CANDIDATE.test(value.candidateId)
      )
        throw Error("Invalid process target");
      return {
        path: `/api/cases/${caseId(value.caseId)}/process-target`,
        body: { candidate_id: value.candidateId },
      };
    default:
      throw Error("Unsupported operation");
  }
}
class LocalClient {
  constructor(port) {
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw Error("Invalid local service port");
    this.origin = `http://127.0.0.1:${port}`;
    this.cookie = null;
    this.csrf = null;
    this.session = null;
  }
  async connect() {
    if (!this.session)
      this.session = this.openSession().catch((error) => {
        this.session = null;
        throw error;
      });
    await this.session;
  }
  async openSession() {
    const response = await fetch(this.origin + "/", {
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok)
      throw Error("Local service could not establish a session.");
    const html = await response.text();
    const cookie = response.headers
      .get("set-cookie")
      ?.match(/systemsense_session=([A-Za-z0-9_-]+)/);
    const csrf = html.match(/name="csrf-token" content="([A-Za-z0-9_-]+)"/);
    if (!cookie || !csrf)
      throw Error("Local service session was not recognized.");
    this.cookie = cookie[0];
    this.csrf = csrf[1];
  }
  async request(method, value) {
    const route = routeFor(method, value);
    await this.connect();
    let response;
    try {
      response = await fetch(this.origin + route.path, {
        method: route.body ? "POST" : "GET",
        redirect: "error",
        signal: AbortSignal.timeout(20000),
        headers: {
          Origin: this.origin,
          Cookie: this.cookie,
          "X-CSRF-Token": this.csrf,
          "Content-Type": "application/json",
        },
        ...(route.body ? { body: JSON.stringify(route.body) } : {}),
      });
    } catch {
      throw Error(
        "Connection to the local investigator was lost. Reconnect to check whether the request completed.",
      );
    }
    if (response.status === 403) {
      this.session = null;
      throw Error(
        "Local session expired or access was denied. Reconnect before trying again.",
      );
    }
    const text = await response.text();
    if (text.length > 12000000)
      throw Error("The local report exceeded the desktop display limit.");
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw Error("Local investigator returned an unreadable response.");
    }
    if (!response.ok)
      throw Error(
        payload?.error?.message ||
          "The local investigator could not complete that request.",
      );
    return payload;
  }
}
module.exports = { routeFor, LocalClient };
