import { FormEvent, useState } from "react";
import { api, ApiError, LoginResult } from "./api";

interface Props {
  onLoggedIn: (result: LoginResult, password: string) => void;
}

export default function AuthScreen({ onLoggedIn }: Props) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "register") {
        await api.register(username, displayName, password);
      }
      const result = await api.login(username, password);
      setPassword("");
      onLoggedIn(result, password);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  const register = mode === "register";
  return (
    <section className="card">
      <h2>{register ? "Create account" : "Log in"}</h2>
      <form onSubmit={(e) => void submit(e)}>
        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            required
            minLength={3}
            maxLength={32}
            pattern="[A-Za-z0-9_]+"
            title="Letters, digits and underscore"
          />
        </label>
        {register && (
          <label>
            Display name
            <input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              autoComplete="nickname"
              required
              maxLength={64}
            />
          </label>
        )}
        <label>
          Password{register ? " (at least 10 characters)" : ""}
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={register ? "new-password" : "current-password"}
            required
            minLength={register ? 10 : 1}
            maxLength={128}
          />
        </label>
        {error && (
          <p className="err" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy}>
          {busy ? "Please wait..." : register ? "Register and log in" : "Log in"}
        </button>
      </form>
      <p>
        <button
          type="button"
          className="link"
          onClick={() => {
            setMode(register ? "login" : "register");
            setError(null);
          }}
        >
          {register ? "I already have an account" : "Create a new account"}
        </button>
      </p>
      <p className="hint">
        Your password logs you in AND unlocks the encryption keys stored in this browser, so the
        server sees it at login. Choose a password you use nowhere else. Forgetting it means the
        stored keys and message history cannot be recovered.
      </p>
    </section>
  );
}

