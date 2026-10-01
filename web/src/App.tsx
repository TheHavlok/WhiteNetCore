import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";

import { api, setUnauthorizedHandler } from "./api";
import type { Admin } from "./types";
import { Spinner } from "./components/ui";
import Login from "./pages/Login";
import Setup from "./pages/Setup";
import Dashboard from "./pages/Dashboard";
import Nodes from "./pages/Nodes";
import NodeDetail from "./pages/NodeDetail";
import Templates from "./pages/Templates";
import Users from "./pages/Users";
import UserDetail from "./pages/UserDetail";
import Groups from "./pages/Groups";
import Journal from "./pages/Journal";
import SettingsPage from "./pages/Settings";
import Account from "./pages/Account";

type Session =
  | { state: "loading" }
  | { state: "setup" }
  | { state: "anonymous" }
  | { state: "signed-in"; admin: Admin };

export default function App(): ReactNode {
  const [session, setSession] = useState<Session>({ state: "loading" });
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (localStorage.getItem("wn-theme") as "dark" | "light") ?? "dark",
  );
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("wn-theme", theme);
  }, [theme]);

  // Any request that finds the session gone drops the whole app back to the
  // login, rather than leaving a page half-loaded with an error.
  useEffect(() => {
    setUnauthorizedHandler(() => setSession({ state: "anonymous" }));
  }, []);

  const refresh = useCallback(async () => {
    try {
      const admin = await api.me();
      setSession({ state: "signed-in", admin });
      return;
    } catch {
      // Not signed in; find out whether this panel has an account at all.
    }
    try {
      const { setup_needed } = await api.setupNeeded();
      setSession({ state: setup_needed ? "setup" : "anonymous" });
    } catch {
      // The panel is unreachable. Showing the login is the honest answer: it
      // is what the user has to get past anyway once it is back.
      setSession({ state: "anonymous" });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Navigating closes the menu on a phone, where it covers the page.
  useEffect(() => setMenuOpen(false), [location.pathname]);

  if (session.state === "loading") {
    return (
      <div className="auth">
        <Spinner />
      </div>
    );
  }
  if (session.state === "setup") {
    return <Setup onDone={refresh} />;
  }
  if (session.state === "anonymous") {
    return <Login onSignedIn={refresh} />;
  }

  const signOut = async () => {
    try {
      await api.logout();
    } finally {
      setSession({ state: "anonymous" });
    }
  };

  return (
    <div className="shell">
      {menuOpen && <div className="scrim" onClick={() => setMenuOpen(false)} />}
      <nav className={menuOpen ? "sidebar open" : "sidebar"}>
        <div className="brand">
          <div className="mark">W</div>
          <div className="name">WhiteNet</div>
        </div>

        <NavLink to="/" end className={navClass}>
          Dashboard
        </NavLink>
        <NavLink to="/nodes" className={navClass}>
          Nodes
        </NavLink>
        <NavLink to="/inbounds" className={navClass}>
          Inbounds
        </NavLink>
        <NavLink to="/users" className={navClass}>
          Users
        </NavLink>
        <NavLink to="/groups" className={navClass}>
          Groups
        </NavLink>
        <NavLink to="/journal" className={navClass}>
          Journal
        </NavLink>
        <NavLink to="/settings" className={navClass}>
          Settings
        </NavLink>

        <div className="sidebar-foot">
          <NavLink to="/account" className={navClass}>
            {session.admin.username}
          </NavLink>
          <button
            className="ghost"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </button>
          <button className="ghost" onClick={signOut}>
            Sign out
          </button>
        </div>
      </nav>

      <main className="main">
        <button className="menu-button ghost" onClick={() => setMenuOpen(true)}>
          ☰ Menu
        </button>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/nodes" element={<Nodes />} />
          <Route path="/nodes/:id" element={<NodeDetail />} />
          <Route path="/inbounds" element={<Templates />} />
          <Route path="/users" element={<Users />} />
          <Route path="/users/:id" element={<UserDetail />} />
          <Route path="/groups" element={<Groups />} />
          <Route path="/journal" element={<Journal />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/account" element={<Account admin={session.admin} onChange={refresh} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function navClass({ isActive }: { isActive: boolean }): string {
  return isActive ? "nav-link active" : "nav-link";
}
