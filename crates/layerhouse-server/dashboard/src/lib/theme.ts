import { createSignal } from "solid-js";

export const THEMES = ["system", "light", "dark"] as const;
export type ThemePreference = (typeof THEMES)[number];
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "layerhouse.theme";

function isTheme(value: string | null | undefined): value is ThemePreference {
  return !!value && (THEMES as readonly string[]).includes(value);
}

function initialTheme(): ThemePreference {
  if (typeof localStorage === "undefined") return "system";
  const stored = localStorage.getItem(STORAGE_KEY);
  return isTheme(stored) ? stored : "system";
}

function systemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "dark";
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

const [themeSignal, setThemeSignal] = createSignal<ThemePreference>(initialTheme());
const [systemSignal, setSystemSignal] = createSignal<ResolvedTheme>(systemTheme());

if (typeof window !== "undefined" && window.matchMedia) {
  const media = window.matchMedia("(prefers-color-scheme: light)");
  const update = () => setSystemSignal(media.matches ? "light" : "dark");
  media.addEventListener?.("change", update);
}

export const theme = themeSignal;
export const resolvedTheme = () =>
  themeSignal() === "system" ? systemSignal() : (themeSignal() as ResolvedTheme);

export function setTheme(next: ThemePreference) {
  setThemeSignal(next);
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Ignore storage failures in private or locked-down browser contexts.
  }
}

export function syncThemeDocument() {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = resolvedTheme();
  document.documentElement.dataset.themePreference = themeSignal();
}
