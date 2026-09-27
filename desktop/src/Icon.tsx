export function Icon({
  name,
}: {
  name: "history" | "send" | "close" | "chevron" | "plus";
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="24"
      height="24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {name === "history" ? (
        <>
          <path d="M3 11a9 9 0 1 1 2.7 7" />
          <path d="M3 5v6h6M12 7v5l3 2" />
        </>
      ) : name === "send" ? (
        <>
          <path d="m5 4 15 8-15 8 3-8-3-8Z" fill="currentColor" stroke="none" />
          <path d="M8 12h7" stroke="#188d62" />
        </>
      ) : name === "close" ? (
        <path d="m6 6 12 12M18 6 6 18" />
      ) : name === "plus" ? (
        <path d="M12 5v14M5 12h14" />
      ) : (
        <path d="m6 9 6 6 6-6" />
      )}
    </svg>
  );
}
