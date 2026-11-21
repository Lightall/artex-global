import "@testing-library/jest-dom/vitest";

import { act, cleanup, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";

import messages from "../../messages/zh.json";
import { TaskDomainScopePreview } from "./task-domain-scope-preview";

vi.mock("@/lib/api", () => ({ api: { previewTaskDomainScope: vi.fn() } }));

function preview(value: string) {
  return (
    <NextIntlClientProvider locale="zh" messages={messages}>
      <TaskDomainScopePreview value={value} />
    </NextIntlClientProvider>
  );
}

describe("domain scope preview", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(api.previewTaskDomainScope).mockReset();
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("accepts one input and renders the backend-normalized domain list", async () => {
    vi.mocked(api.previewTaskDomainScope).mockResolvedValue({ domains: ["a.test", "b.test"], intercept_rules: [] });
    render(preview("A.TEST.\nb.test\na.test"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(api.previewTaskDomainScope).toHaveBeenCalledExactlyOnceWith("A.TEST.\nb.test\na.test");
    expect(screen.getByRole("status")).toHaveTextContent("a.test, b.test");
  });

  it("shows validation failure without presenting it as generated rules", async () => {
    vi.mocked(api.previewTaskDomainScope).mockRejectedValue(new Error("invalid domain"));
    render(preview("*.a.test"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    expect(screen.getByRole("alert")).toHaveTextContent("invalid domain");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("ignores an older response after the developer changes the domains", async () => {
    let resolveOld: (value: { domains: string[]; intercept_rules: [] }) => void = () => {
      throw new Error("The first preview request has not started");
    };
    vi.mocked(api.previewTaskDomainScope)
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveOld = resolve;
          }),
      )
      .mockResolvedValueOnce({ domains: ["b.test"], intercept_rules: [] });
    const view = render(preview("a.test"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    view.rerender(preview("b.test"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    await act(async () => {
      resolveOld({ domains: ["a.test"], intercept_rules: [] });
    });
    expect(screen.getByRole("status")).toHaveTextContent("b.test");
    expect(screen.getByRole("status")).not.toHaveTextContent("a.test");
    view.rerender(preview(""));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
