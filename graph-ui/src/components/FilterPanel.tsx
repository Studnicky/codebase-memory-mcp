import { useMemo } from 'react';

import { ScrollArea } from '@/components/ui/scroll-area';

import type { GraphData } from '../lib/types';

import {
  colorForLabel, STATUS_LEGEND
} from '../lib/colors';

interface FilterPanelProps {
  'data': GraphData;
  /* Dead-code view */
  'deadCodeView': boolean;
  'enabledEdgeTypes': Set<string>;
  'enabledLabels': Set<string>;
  'hideEntryPoints': boolean;
  'hideTests': boolean;
  'missedCount': number;
  /* Missed skeleton (#963): white satellite of not-fully-indexed files */
  'missedView': boolean;
  'onDisableAll': () => void;
  'onEnableAll': () => void;
  'onToggleDeadCodeView': () => void;
  'onToggleEdgeType': (type: string) => void;
  'onToggleHideEntryPoints': () => void;
  'onToggleHideTests': () => void;
  'onToggleLabel': (label: string) => void;
  'onToggleMissedView': () => void;
  'onToggleShowLabels': () => void;
  'onToggleShowOnlyDead': () => void;
  'showLabels': boolean;
  'showOnlyDead': boolean;
}

/* Checkbox row matching the existing "Show labels" toggle style */
function CheckRow({
  checked,
  count,
  label,
  onToggle
}: {
  'checked': boolean;
  'count'?: number;
  'label': string;
  'onToggle': () => void;
}) {
  return (
    <button
      aria-checked={checked}
      className={`flex items-center gap-1.5 text-[11px] font-medium transition-all focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
        checked ? 'text-primary' : 'text-foreground/40'
      }`}
      onClick={onToggle}
      role="checkbox"
    >
      <span
        className={`w-3.5 h-3.5 rounded border flex items-center justify-center transition-all ${
          checked ? 'border-primary bg-primary/20' : 'border-foreground/15'
        }`}
      >
        {checked && <span className="text-primary text-[9px]">✓</span>}
      </span>
      {label}
      {count !== undefined && (
        <span className="text-foreground/25 tabular-nums">{count.toLocaleString()}</span>
      )}
    </button>
  );
}

export function FilterPanel({
  data,
  deadCodeView,
  enabledEdgeTypes,
  enabledLabels,
  hideEntryPoints,
  hideTests,
  missedCount,
  missedView,
  onDisableAll,
  onEnableAll,
  onToggleDeadCodeView,
  onToggleEdgeType,
  onToggleHideEntryPoints,
  onToggleHideTests,
  onToggleLabel,
  onToggleMissedView,
  onToggleShowLabels,
  onToggleShowOnlyDead,
  showLabels,
  showOnlyDead
}: FilterPanelProps) {
  const {
    edgeTypeCounts, labelCounts, statusCounts
  } = useMemo(() => {
    const lc = new Map<string, number>();

    for (const n of data.nodes) {
      lc.set(n.label, (lc.get(n.label) ?? 0) + 1);
    }
    const ec = new Map<string, number>();

    for (const e of data.edges) {
      ec.set(e.type, (ec.get(e.type) ?? 0) + 1);
    }
    const sc = new Map<string, number>();

    for (const n of data.nodes) {
      if (n.status) {
        sc.set(n.status, (sc.get(n.status) ?? 0) + 1);
      }
    }

    return {
      'edgeTypeCounts': [...ec.entries()].sort((a, b) => {
        return b[1] - a[1];
      }),
      'labelCounts': [...lc.entries()].sort((a, b) => {
        return b[1] - a[1];
      }),
      'statusCounts': sc
    };
  }, [data]);

  const deadCount = statusCounts.get('dead') ?? 0;

  return (
    <div className="flex flex-col shrink-0 max-h-[45%] border-b border-border/40">
      {/* Header row — always visible */}
      <div className="flex items-center justify-between px-4 pt-3 pb-2 shrink-0">
        <span className="text-[11px] font-medium text-foreground/50 uppercase tracking-widest">
          Filters
        </span>
        <div className="flex items-center gap-2">
          <button className="text-[10px] text-primary/70 hover:text-primary transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary" onClick={onEnableAll}>All</button>
          <span className="text-foreground/15">|</span>
          <button className="text-[10px] text-primary/70 hover:text-primary transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary" onClick={onDisableAll}>None</button>
        </div>
      </div>

      {/* Scrollable filter groups */}
      <ScrollArea className="flex-1 min-h-0">
        <div className="px-4 pb-3 space-y-3">
          {/* Node types */}
          {labelCounts.length > 0 && (
            <div>
              <p className="text-[10px] font-medium text-foreground/40 mb-1.5 uppercase tracking-wider">Node types</p>
              <div className="flex flex-wrap gap-1">
                {labelCounts.map(([
                  label,
                  count
                ]) => {
                  const on = enabledLabels.has(label);
                  const c = colorForLabel(label);

                  return (
                    <button
                      aria-pressed={on}
                      className={`inline-flex items-center gap-1 px-1.5 py-[3px] rounded-md text-[10px] font-medium transition-all border focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                        on ? 'border-white/[0.08] bg-white/[0.04]' : 'border-transparent opacity-25'
                      }`}
                      key={label}
                      onClick={() => {
                        const result = onToggleLabel(label);

                        return result;
                      }}
                    >
                      <span className="w-[5px] h-[5px] rounded-full" style={{ 'backgroundColor': on ? c : '#444' }} />
                      <span style={{ 'color': on ? c : '#555' }}>{label}</span>
                      <span className="text-foreground/20 tabular-nums">{count.toLocaleString()}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Relationships */}
          {edgeTypeCounts.length > 0 && (
            <div>
              <p className="text-[10px] font-medium text-foreground/40 mb-1.5 uppercase tracking-wider">Relationships</p>
              <div className="flex flex-wrap gap-1">
                {edgeTypeCounts.map(([
                  type,
                  count
                ]) => {
                  const on = enabledEdgeTypes.has(type);

                  return (
                    <button
                      aria-pressed={on}
                      className={`inline-flex items-center gap-1 px-1.5 py-[3px] rounded-md text-[10px] font-medium transition-all border focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
                        on ? 'border-white/[0.06] bg-white/[0.03] text-foreground/60' : 'border-transparent opacity-20 text-foreground/30'
                      }`}
                      key={type}
                      onClick={() => {
                        const result = onToggleEdgeType(type);

                        return result;
                      }}
                    >
                      {type.replace(/_/g, ' ').toLowerCase()}
                      <span className="text-foreground/15 tabular-nums">{count.toLocaleString()}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Missed skeleton (#963): white satellite cluster of files the indexer
          could not fully cover, shown beside the code galaxy. Click it to
          focus; click the code galaxy to come back. */}
      <div className="px-4 pt-2 border-t border-border/30 space-y-2 shrink-0">
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-foreground/30 uppercase tracking-widest">
            Missed files
          </span>
          {missedCount > 0 && (
            <span className="text-[10px] text-foreground/50 tabular-nums">
              {missedCount.toLocaleString()} files
            </span>
          )}
        </div>
        <CheckRow
          checked={missedView}
          label="Show missed skeleton"
          onToggle={onToggleMissedView}
        />
        <p className="text-[9px] leading-snug text-foreground/30">
          {missedCount > 0
            ? 'White satellite = files not fully indexed (best-effort). Click it to focus, click the galaxy to return.'
            : 'No known misses (best-effort — not a completeness guarantee).'}
        </p>
      </div>

      {/* Dead-code view */}
      <div className="px-4 pt-2 border-t border-border/30 space-y-2 shrink-0">
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-foreground/30 uppercase tracking-widest">
            Dead code
          </span>
          <span className="text-[10px] text-red-400/80 tabular-nums">
            {deadCount.toLocaleString()} dead
          </span>
        </div>

        <CheckRow
          checked={deadCodeView}
          label="Color by status"
          onToggle={onToggleDeadCodeView}
        />
        <CheckRow
          checked={showOnlyDead}
          label="Show only dead code"
          onToggle={onToggleShowOnlyDead}
        />
        <CheckRow
          checked={hideEntryPoints}
          label="Hide entry points"
          onToggle={onToggleHideEntryPoints}
        />
        <CheckRow checked={hideTests} label="Hide tests" onToggle={onToggleHideTests} />

        {/* Legend (only meaningful while colored by status) */}
        {deadCodeView && (
          <div className="flex flex-wrap gap-x-2 gap-y-1 pt-1">
            {STATUS_LEGEND.map((s) => {
              return (
                <span
                  className="inline-flex items-center gap-1 text-[9px] text-foreground/40"
                  key={s.status}
                >
                  <span
                    className="w-[6px] h-[6px] rounded-full"
                    style={{ 'backgroundColor': s.color }}
                  />
                  {s.label}
                </span>
              );
            })}
          </div>
        )}
      </div>

      {/* Display options — pinned footer */}
      <div className="px-4 py-2.5 border-t border-border/20 shrink-0">
        <button
          aria-pressed={showLabels}
          className={`inline-flex items-center gap-1.5 text-[11px] font-medium transition-all focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${
            showLabels ? 'text-primary' : 'text-foreground/30'
          }`}
          onClick={onToggleShowLabels}
        >
          <span className={`w-3.5 h-3.5 rounded border flex items-center justify-center transition-all ${
            showLabels ? 'border-primary bg-primary/20' : 'border-foreground/15'
          }`}>
            {showLabels && <span className="text-primary text-[9px]">✓</span>}
          </span>
          Show labels
        </button>
      </div>
    </div>
  );
}
