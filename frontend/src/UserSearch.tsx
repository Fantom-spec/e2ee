import { FormEvent, useState } from "react";
import { api, ApiError, User } from "./api";

export default function UserSearch({ token, onSelect }: { token: string; onSelect: (user: User) => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<User[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setResults(await api.search(token, query.trim()));
    } catch (e) {
      setResults(null);
      setError(e instanceof ApiError ? e.message : "Search failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card">
      <h2>Find people</h2>
      <form onSubmit={(e) => void submit(e)} className="row">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Start of a username"
          aria-label="Username prefix"
          autoCapitalize="none"
          required
          minLength={2}
          maxLength={32}
        />
        <button type="submit" disabled={busy}>
          Search
        </button>
      </form>
      {error && (
        <p className="err" role="alert">
          {error}
        </p>
      )}
      {results !== null && results.length === 0 && <p>No matching users.</p>}
      {results !== null && results.length > 0 && (
        <ul className="list">
          {results.map((u) => (
            <li key={u.id}>
              <button type="button" className="link" onClick={() => onSelect(u)}>
                <strong>{u.display_name}</strong> <span className="muted">@{u.username}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="hint">Choose a person to open an end-to-end encrypted conversation. They must have logged in once.</p>
    </section>
  );
}
