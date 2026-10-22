import { useCallback, useState } from "react";
import { api, LoginResult, User } from "./api";
import AuthScreen from "./AuthScreen";
import ChatApp from "./ChatApp";

interface Auth {
  token: string;
  user: User;
  password: string; // kept in memory only, to unlock the key vault; never stored
}

export default function App() {
  const [auth, setAuth] = useState<Auth | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const handleLoggedIn = useCallback((result: LoginResult, password: string) => {
    setNotice(null);
    setAuth({ token: result.token, user: result.user, password });
  }, []);

  const handleSessionEnded = useCallback(() => {
    setAuth(null);
    setNotice("Your session ended. Please log in again.");
  }, []);

  const handleLogout = useCallback(() => {
    const token = auth?.token;
    setAuth(null);
    setNotice(null);
    if (token) void api.logout(token).catch(() => undefined);
  }, [auth]);

  return (
    <main className="shell">
      <h1>SecureChat</h1>
      <details className="banner intro">
        <summary>Messages are end-to-end encrypted in this browser</summary>
        <p>
          Encryption uses the Signal protocol (X3DH and Double Ratchet) through an unaudited
          third-party library. The server could still serve modified page code, and it cannot
          stop someone replacing a contact's key, so compare safety numbers with your contacts.
          Reloading the page requires logging in again.
        </p>
      </details>
      {notice && <p className="banner">{notice}</p>}
      {auth ? (
        <ChatApp token={auth.token} user={auth.user} password={auth.password} onLogout={handleLogout} onSessionEnded={handleSessionEnded} />
      ) : (
        <AuthScreen onLoggedIn={handleLoggedIn} />
      )}
    </main>
  );
}
