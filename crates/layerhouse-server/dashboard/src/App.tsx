import { createEffect, createSignal, Show, type Component } from "solid-js";
import { HashRouter, Route, A } from "@solidjs/router";
import type { RouteSectionProps } from "@solidjs/router";
import { lazy } from "solid-js";
import {
  locale,
  LOCALES,
  LOCALE_LABELS,
  setLocale,
  syncLocaleDocument,
  t,
  type Locale,
} from "./lib/i18n";
import { resolvedTheme, setTheme, theme, THEMES, type ThemePreference } from "./lib/theme";
import { fetchSession, logoutSession, redirectToSignIn } from "./lib/api";
import type { DashboardSession } from "./lib/types";

const Overview = lazy(() => import("./pages/Overview"));
const Repositories = lazy(() => import("./pages/Repositories"));
const RepoDetail = lazy(() => import("./pages/RepoDetail"));
const TagDiff = lazy(() => import("./pages/TagDiff"));
const Access = lazy(() => import("./pages/Access"));
const Admin = lazy(() => import("./pages/Admin"));
const Policies = lazy(() => import("./pages/Policies"));
const Mirror = lazy(() => import("./pages/Mirror"));
const ProxyCache = lazy(() => import("./pages/ProxyCache"));
const Cluster = lazy(() => import("./pages/Cluster"));
const OAuth2Error = lazy(() => import("./pages/OAuth2Error"));
const NotFound = lazy(() => import("./pages/NotFound"));

const OAuth2Start: Component = () => {
  createEffect(() => {
    window.location.assign("/oauth2/start");
  });
  return null;
};

const NAV_ITEMS = [
  { href: "/overview", label: "app.nav.overview" },
  { href: "/repos", label: "app.nav.repositories" },
  { href: "/admin", label: "app.nav.admin", adminOnly: true },
  { href: "/mirror", label: "app.nav.mirror" },
  { href: "/proxy-cache", label: "app.nav.proxyCache" },
  { href: "/cluster", label: "app.nav.cluster" },
];

const AppShell: Component<RouteSectionProps> = (props) => {
  const [session, setSession] = createSignal<DashboardSession | null>(null);
  const [showAccountMenu, setShowAccountMenu] = createSignal(false);
  const [showTokens, setShowTokens] = createSignal(false);

  createEffect(() => {
    syncLocaleDocument();
  });

  createEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme();
    document.documentElement.dataset.themePreference = theme();
  });

  createEffect(() => {
    fetchSession()
      .then(setSession)
      .catch(() => setSession(null));
  });

  function signOut() {
    setShowAccountMenu(false);
    logoutSession();
  }

  const displayUser = () =>
    session()?.display_name ||
    session()?.username ||
    session()?.email ||
    session()?.subject ||
    t("access.account");
  const secondaryUser = () => {
    const current = session();
    if (!current) return null;
    if (current.username && current.username !== displayUser()) return current.username;
    if (current.email && current.email !== displayUser()) return current.email;
    return current.subject && current.subject !== displayUser() ? current.subject : null;
  };
  const userInitials = () => {
    const user = displayUser().trim();
    if (!user) return "ID";
    const parts = user.split(/[\s@._-]+/).filter(Boolean);
    return (parts[0]?.[0] ?? "I").concat(parts[1]?.[0] ?? "").toUpperCase();
  };

  return (
    <div class="page">
      <header class="topbar">
        <div class="nav-shell">
          <A
            class="brand"
            href="/overview"
            activeClass=""
            inactiveClass=""
            aria-label={t("app.productName")}
            title={t("app.productName")}
          >
            <span class="brand-mark" aria-hidden="true">
              <img
                class="brand-mark-image brand-mark-light"
                src="/brand/layerhouse-mark-light.svg"
                alt=""
              />
              <img
                class="brand-mark-image brand-mark-dark"
                src="/brand/layerhouse-mark-dark.svg"
                alt=""
              />
            </span>
            <span class="brand-label">{t("app.brandName")}</span>
          </A>
          <nav class="nav">
            {NAV_ITEMS.filter((item) => !item.adminOnly || session()?.is_admin).map((item) => (
              <A href={item.href} activeClass="active" inactiveClass="">
                {t(item.label)}
              </A>
            ))}
          </nav>
          <div class="topbar-controls" aria-label={`${t("app.locale")} / ${t("app.theme")}`}>
            <label class="locale-control">
              <span class="control-icon" aria-hidden="true">
                Aa
              </span>
              <span class="sr-only">{t("app.locale")}</span>
              <select
                aria-label={t("app.locale")}
                value={locale()}
                onChange={(event) => setLocale(event.currentTarget.value as Locale)}
              >
                {LOCALES.map((code) => (
                  <option value={code}>{LOCALE_LABELS[code]}</option>
                ))}
              </select>
            </label>
            <div class="theme-toggle" role="group" aria-label={t("app.theme")}>
              {THEMES.map((value) => (
                <button
                  type="button"
                  class={theme() === value ? "active" : ""}
                  aria-pressed={theme() === value}
                  onClick={() => setTheme(value as ThemePreference)}
                >
                  {t(`theme.${value}`)}
                </button>
              ))}
            </div>
            <Show when={session()?.auth_enabled && !session()?.subject}>
              <button type="button" class="btn" onClick={redirectToSignIn}>
                {t("access.signInWithOidc")}
              </button>
            </Show>
            <Show when={session()?.auth_enabled && session()?.subject}>
              <div class="account-control">
                <button
                  type="button"
                  class="account-chip"
                  aria-expanded={showAccountMenu()}
                  onClick={() => setShowAccountMenu((open) => !open)}
                >
                  <span class="account-avatar">{userInitials()}</span>
                  <span>{displayUser()}</span>
                </button>
                <Show when={showAccountMenu()}>
                  <div class="account-menu">
                    <div class="account-menu-header">
                      <span class="account-avatar">{userInitials()}</span>
                      <div>
                        <strong>{displayUser()}</strong>
                        <span>{secondaryUser() || t("access.sessionActive")}</span>
                      </div>
                    </div>
                    <button
                      type="button"
                      class="account-menu-row"
                      onClick={() => {
                        setShowAccountMenu(false);
                        setShowTokens(true);
                      }}
                    >
                      {t("access.personalTokens")}
                    </button>
                    <button type="button" class="account-menu-row" onClick={signOut}>
                      {t("access.signOut")}
                    </button>
                  </div>
                </Show>
              </div>
            </Show>
          </div>
        </div>
      </header>
      <main class="main">
        <div class="shell">
          <Show when={session()?.auth_enabled && !session()?.subject} fallback={props.children}>
            <section class="access-signin card">
              <div>
                <p class="eyebrow">{t("access.signIn")}</p>
                <h2>{t("access.signInTitle")}</h2>
                <p>{t("access.signInDesc")}</p>
                <p class="hint">{t("access.dockerClientsUsePat")}</p>
              </div>
              <button type="button" class="btn btn-primary" onClick={redirectToSignIn}>
                {t("access.signInWithOidc")}
              </button>
            </section>
          </Show>
        </div>
      </main>

      <Show when={showTokens()}>
        <Access onClose={() => setShowTokens(false)} />
      </Show>
    </div>
  );
};

export default function App() {
  return (
    <HashRouter root={AppShell}>
      <Route path="/" component={Overview} />
      <Route path="/overview" component={Overview} />
      <Route path="/repos" component={Repositories} />
      <Route path="/repos/*name" component={RepoDetail} />
      <Route path="/diff/:name/:a/:b" component={TagDiff} />
      <Route path="/admin" component={Admin} />
      <Route path="/policies" component={Policies} />
      <Route path="/mirror" component={Mirror} />
      <Route path="/proxy-cache" component={ProxyCache} />
      <Route path="/cluster" component={Cluster} />
      <Route path="/oauth2/start" component={OAuth2Start} />
      <Route path="/oauth2/error" component={OAuth2Error} />
      <Route path="*" component={NotFound} />
    </HashRouter>
  );
}
