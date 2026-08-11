import { useCallback, useEffect, useRef, useState } from "react";
import type { GraphData } from "../lib/types";

export interface LoadProgress {
  receivedBytes: number;
  totalBytes: number | null;
}

interface UseGraphDataResult {
  data: GraphData | null;
  loading: boolean;
  error: string | null;
  progress: LoadProgress;
  fetchOverview: (
    project: string,
    maxNodes?: number,
    graph?: "code" | "missed",
  ) => void;
  fetchDetail: (project: string, centerNode: string) => void;
}

/* Node budget: how many nodes the layout endpoint is asked for. The default
 * keeps first paint fast; the user can raise it in 5k steps up to the hard
 * ceiling (mirrors HARD_MAX_NODES in src/ui/layout3d.c). Edges always follow
 * the budget — the server returns every edge between the loaded nodes. */
export const GRAPH_RENDER_NODE_LIMIT = 5000;
export const GRAPH_NODE_BUDGET_STEP = 5000;
export const GRAPH_NODE_BUDGET_MAX = 10_000_000;

export function clampNodeBudget(value: number): number {
  if (!Number.isFinite(value)) return GRAPH_RENDER_NODE_LIMIT;
  const stepped =
    Math.round(value / GRAPH_NODE_BUDGET_STEP) * GRAPH_NODE_BUDGET_STEP;
  if (stepped < GRAPH_NODE_BUDGET_STEP) return GRAPH_NODE_BUDGET_STEP;
  if (stepped > GRAPH_NODE_BUDGET_MAX) return GRAPH_NODE_BUDGET_MAX;
  return stepped;
}

/** Which graph to lay out: the code graph (default) or the missed graph —
 *  only files the indexer could not fully cover, as their file structure. */
export type GraphVariant = "code" | "missed";

export async function fetchLayout(
  project: string,
  maxNodes = GRAPH_RENDER_NODE_LIMIT,
  onProgress?: (progress: LoadProgress) => void,
  graph: GraphVariant = "code",
  signal?: AbortSignal,
): Promise<GraphData> {
  const params = new URLSearchParams({ project, max_nodes: String(maxNodes) });
  if (graph === "missed") params.set("graph", "missed");
  const res = await fetch(`/api/layout?${params}`, { signal });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }

  /* Stream the body when possible so large budgets show live download
   * progress instead of a silent stall. */
  if (!res.body || !onProgress) {
    return res.json();
  }

  const lengthHeader = res.headers.get("content-length");
  const totalBytes = lengthHeader ? parseInt(lengthHeader, 10) || null : null;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let receivedBytes = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    receivedBytes += value.length;
    onProgress({ receivedBytes, totalBytes });
  }

  const merged = new Uint8Array(receivedBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder().decode(merged));
}

const NO_PROGRESS: LoadProgress = { receivedBytes: 0, totalBytes: null };

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

export function useGraphData(): UseGraphDataResult {
  const [data, setData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<LoadProgress>(NO_PROGRESS);
  const request = useRef({ generation: 0, controller: null as AbortController | null });

  useEffect(() => {
    return () => {
      request.current.generation += 1;
      request.current.controller?.abort();
      request.current.controller = null;
    };
  }, []);

  const load = useCallback(
    async (requestLayout: (signal: AbortSignal) => Promise<GraphData>) => {
      request.current.controller?.abort();
      const controller = new AbortController();
      const generation = request.current.generation + 1;
      request.current = { generation, controller };
      const isCurrent = () =>
        request.current.generation === generation &&
        request.current.controller === controller;

      setLoading(true);
      setError(null);
      setProgress(NO_PROGRESS);
      try {
        const result = await requestLayout(controller.signal);
        if (isCurrent()) setData(result);
      } catch (cause) {
        if (isCurrent() && !isAbortError(cause)) {
          setError(cause instanceof Error ? cause.message : "Failed to fetch layout");
        }
      } finally {
        if (isCurrent()) {
          setLoading(false);
          request.current.controller = null;
        }
      }
    },
    [],
  );

  const fetchOverview = useCallback(
    async (project: string, maxNodes?: number, graph: GraphVariant = "code") => {
      await load((signal) =>
        fetchLayout(
          project,
          maxNodes,
          (nextProgress) => {
            if (request.current.controller?.signal === signal) {
              setProgress(nextProgress);
            }
          },
          graph,
          signal,
        ),
      );
    },
    [load],
  );

  const fetchDetail = useCallback(
    async (project: string, _centerNode: string) => {
      await load((signal) =>
        /* TODO: detail level with center_node filtering */
        fetchLayout(
          project,
          undefined,
          (nextProgress) => {
            if (request.current.controller?.signal === signal) {
              setProgress(nextProgress);
            }
          },
          "code",
          signal,
        ),
      );
    },
    [load],
  );

  return { data, loading, error, progress, fetchOverview, fetchDetail };
}
