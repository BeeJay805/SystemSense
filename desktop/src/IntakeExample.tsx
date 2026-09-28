import { useEffect, useState } from "react";

const examples = [
  "My game keeps freezing…",
  "Chrome can’t open webpages…",
  "My computer has become slow…",
  "An app stops responding…",
];
type Frame = {
  index: number;
  length: number;
  phase: "typing" | "reading" | "erasing" | "waiting";
};
const first: Frame = { index: 0, length: 0, phase: "waiting" };

export function IntakeExample({
  paused,
  reducedMotion,
  hidden,
}: {
  paused: boolean;
  reducedMotion: boolean;
  hidden: boolean;
}) {
  const [frame, setFrame] = useState<Frame>(first);
  useEffect(() => {
    if (paused || reducedMotion) return;
    const delay =
      frame.phase === "reading"
        ? 14000
        : frame.phase === "waiting"
          ? 1400
          : frame.phase === "typing"
            ? 90
            : 40;
    const timer = setTimeout(
      () =>
        setFrame((current) => {
          if (current.phase === "waiting")
            return { ...current, phase: "typing", length: 1 };
          if (current.phase === "reading")
            return { ...current, phase: "erasing", length: current.length - 1 };
          if (current.phase === "erasing")
            return current.length > 0
              ? { ...current, length: current.length - 1 }
              : {
                  index: (current.index + 1) % examples.length,
                  length: 0,
                  phase: "waiting",
                };
          const length = current.length + 1;
          return {
            ...current,
            length,
            phase:
              length >= examples[current.index].length ? "reading" : "typing",
          };
        }),
      delay,
    );
    return () => clearTimeout(timer);
  }, [frame, paused, reducedMotion]);
  return (
    <span className="intake-example" aria-hidden="true" hidden={hidden}>
      {reducedMotion
        ? examples[0]
        : examples[frame.index].slice(0, frame.length)}
    </span>
  );
}
