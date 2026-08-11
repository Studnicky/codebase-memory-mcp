import { useCallback, useRef } from "react";

interface ResizeHandleProps {
  side: "left" | "right"; /* which side the panel is on */
  onResize: (delta: number) => void;
}

const KEYBOARD_RESIZE_STEP = 10;

export function ResizeHandle({ side, onResize }: ResizeHandleProps) {
  const dragging = useRef(false);
  const lastX = useRef(0);

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      dragging.current = true;
      lastX.current = e.clientX;
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
    },
    [],
  );

  const onPointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (!dragging.current) return;
      const delta = e.clientX - lastX.current;
      lastX.current = e.clientX;
      /* Left panel: drag right = bigger (positive delta).
       * Right panel: drag left = bigger (negative delta → invert). */
      onResize(side === "left" ? delta : -delta);
    },
    [onResize, side],
  );

  const onPointerUp = useCallback(() => {
    dragging.current = false;
  }, []);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;

      e.preventDefault();
      const direction = e.key === "ArrowRight" ? 1 : -1;
      onResize((side === "left" ? direction : -direction) * KEYBOARD_RESIZE_STEP);
    },
    [onResize, side],
  );

  return (
    <div
      role="separator"
      aria-label={`Resize ${side} panel`}
      aria-orientation="vertical"
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onKeyDown={onKeyDown}
      className="w-1 cursor-col-resize hover:bg-primary/30 active:bg-primary/50 transition-colors shrink-0 focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-primary"
    />
  );
}
