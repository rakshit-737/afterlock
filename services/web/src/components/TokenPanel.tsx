import { useState } from "react";

/**
 * Bearer-token entry. The token lives only in React state (memory). It is never
 * written to web storage, cookies, or the URL, and is lost on reload by design.
 */
export function TokenPanel({ hasToken, onSet, onClear }: { hasToken: boolean; onSet: (t: string) => void; onClear: () => void }) {
  const [draft, setDraft] = useState("");
  if (hasToken) {
    return (
      <form
        className="token"
        onSubmit={(e) => {
          e.preventDefault();
          onClear();
        }}
      >
        <span>API token set (held in memory for this tab only).</span>
        <button type="submit">Forget token</button>
      </form>
    );
  }
  return (
    <form
      className="token"
      onSubmit={(e) => {
        e.preventDefault();
        const t = draft.trim();
        if (t) {
          onSet(t);
          setDraft("");
        }
      }}
    >
      <label htmlFor="token">API bearer token</label>
      <input
        id="token"
        type="password"
        autoComplete="off"
        spellCheck={false}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        aria-describedby="token-help"
      />
      <button type="submit" disabled={!draft.trim()}>
        Use token
      </button>
      <p id="token-help" className="muted small">
        Kept in memory only; reloading the page forgets it.
      </p>
    </form>
  );
}
