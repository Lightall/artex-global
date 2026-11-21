import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

vi.mock("@/lib/mock/enabled", () => ({ MOCK: false }));

describe("task domain scope transport", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("submits the single domain input with domain mode enabled", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{"id":"1"}'));
    vi.stubGlobal("fetch", fetcher);
    await api.createTask({ description: "a.test\nb.test", goal: "goal", domainScopeEnabled: true });
    const [path, request] = fetcher.mock.calls[0];
    expect(path).toBe("/api/tasks");
    expect(JSON.parse(request.body)).toMatchObject({
      description: "a.test\nb.test",
      domain_scope_enabled: true,
      intercept_rules: [],
    });
  });

  it("keeps legacy task creation in manual scope mode", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{"id":"1"}'));
    vi.stubGlobal("fetch", fetcher);
    await api.createTask({ description: "existing description", goal: "goal" });
    expect(JSON.parse(fetcher.mock.calls[0][1].body).domain_scope_enabled).toBe(false);
  });

  it("previews through the dedicated endpoint without sending a create request", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{"domains":["a.test"],"intercept_rules":[]}'));
    vi.stubGlobal("fetch", fetcher);
    await api.previewTaskDomainScope("a.test");
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe("/api/task-domain-scope/preview");
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ domains: "a.test" });
  });
});
