/* @vitest-environment jsdom */
import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GraphTab } from "./GraphTab";
import { ResizeHandle } from "./ResizeHandle";
import type { GraphData } from "../lib/types";

vi.mock("./GraphScene", () => ({
  GraphScene: () => null,
  computeCameraTarget: () => null,
}));

const SAMPLE: GraphData = {
  nodes: [
    { id: 1, x: 0, y: 0, z: 0, label: "Function", name: "foo", size: 1, color: "#fff" },
    { id: 2, x: 1, y: 0, z: 0, label: "Class", name: "Bar", size: 1, color: "#fff" },
  ],
  edges: [{ source: 1, target: 2, type: "CALLS" }],
  total_nodes: 2,
};

function mockApiFetch(data: GraphData) {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).startsWith("/api/layout")) {
      return new Response(JSON.stringify(data), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("{}", { status: 200 });
  }));
}

describe("graph accessibility", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resizes the left panel from its focusable vertical separator", () => {
    const onResize = vi.fn();
    render(<ResizeHandle side="left" onResize={onResize} />);

    const separator = screen.getByRole("separator", { name: "Resize left panel" });
    expect(separator).toHaveAttribute("aria-orientation", "vertical");
    expect(separator).toHaveClass("focus-visible:outline-2");

    separator.focus();
    expect(separator).toHaveFocus();
    fireEvent.keyDown(separator, { key: "ArrowRight" });
    fireEvent.keyDown(separator, { key: "ArrowLeft" });
    expect(onResize).toHaveBeenNthCalledWith(1, 10);
    expect(onResize).toHaveBeenNthCalledWith(2, -10);

    const onRightResize = vi.fn();
    render(<ResizeHandle side="right" onResize={onRightResize} />);
    const rightSeparator = screen.getByRole("separator", { name: "Resize right panel" });
    fireEvent.keyDown(rightSeparator, { key: "ArrowLeft" });
    fireEvent.keyDown(rightSeparator, { key: "ArrowRight" });
    expect(onRightResize).toHaveBeenNthCalledWith(1, 10);
    expect(onRightResize).toHaveBeenNthCalledWith(2, -10);
  });

  it("exposes filter state and the sidebar search label to assistive technology", async () => {
    mockApiFetch(SAMPLE);
    render(<GraphTab project="demo" />);

    expect(await screen.findByText("Filters")).toBeInTheDocument();

    const functionFilter = screen.getByRole("button", { name: /function 1/i });
    expect(functionFilter).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(functionFilter);
    expect(functionFilter).toHaveAttribute("aria-pressed", "false");

    const statusToggle = screen.getByRole("checkbox", { name: "Color by status" });
    expect(statusToggle).toHaveAttribute("aria-checked", "false");
    fireEvent.click(statusToggle);
    expect(statusToggle).toHaveAttribute("aria-checked", "true");

    const search = screen.getByRole("textbox", { name: "Search..." });
    expect(search).toHaveClass("focus-visible:outline-2");
  });
});
