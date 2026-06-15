import type { ManifestSummary, MirrorStrategy } from "./types";
import { t } from "./i18n";

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatAgo(epochSeconds: number | null | undefined): string {
  if (!epochSeconds) return t("time.never");
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - epochSeconds);
  if (delta < 60) return t("time.secondsAgo", { count: delta });
  if (delta < 3600) return t("time.minutesAgo", { count: Math.floor(delta / 60) });
  if (delta < 86400) return t("time.hoursAgo", { count: Math.floor(delta / 3600) });
  return t("time.daysAgo", { count: Math.floor(delta / 86400) });
}

export function formatTime(epochSeconds: number | null | undefined): string {
  if (!epochSeconds) return t("time.never");
  return new Date(epochSeconds * 1000).toLocaleString();
}

export function digestShort(digest: string): string {
  const [algo, value] = digest.split(":");
  if (!algo || !value) return digest;
  return `${algo}:${value.slice(0, 12)}`;
}

export function strategyLabel(strategy: MirrorStrategy): string {
  if (strategy.type === "all") return t("mirror.allTags");
  if (strategy.type === "latest") return t("mirror.latestCount", { count: strategy.count });
  return strategy.pattern;
}

function trimBoundarySlashes(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && value[start] === "/") start += 1;
  while (end > start && value[end - 1] === "/") end -= 1;
  return value.slice(start, end);
}

export function normalizeOptionalPrefix(prefix: string | null | undefined): string | null {
  const trimmed = prefix?.trim();
  if (!trimmed) return null;
  const withoutBoundarySlashes = trimBoundarySlashes(trimmed).trim();
  return withoutBoundarySlashes ? withoutBoundarySlashes : null;
}

export function normalizeRegistry(registry: string): string {
  let normalized = registry.trim();
  while (normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

export function upstreamLabel(registry: string, prefix: string | null | undefined): string {
  const normalizedRegistry = normalizeRegistry(registry);
  const normalizedPrefix = normalizeOptionalPrefix(prefix);
  return normalizedPrefix ? `${normalizedRegistry}/${normalizedPrefix}` : normalizedRegistry;
}

export function prefixLabel(prefix: string | null | undefined, emptyLabel = "-"): string {
  return normalizeOptionalPrefix(prefix) ?? emptyLabel;
}

export function manifestKind(manifest: Pick<ManifestSummary, "media_type" | "artifact_type">): {
  label: string;
  className: string;
  kind: "helm" | "image" | "wasm" | "artifact" | "unknown";
} {
  const artifact = manifest.artifact_type ?? "";
  const media = manifest.media_type ?? "";
  if (artifact.includes("helm.config")) {
    return { label: `🪽 ${t("repo.type.helm")}`, className: "badge-blue", kind: "helm" };
  }
  if (artifact.includes("wasm.config")) {
    return { label: `⬡ ${t("repo.type.wasm")}`, className: "badge-amber", kind: "wasm" };
  }
  if (artifact.includes("image.config")) {
    return { label: `🐳 ${t("repo.type.image")}`, className: "badge-teal", kind: "image" };
  }
  if (artifact.includes("artifact.manifest") || media.includes("artifact.manifest")) {
    return { label: `📦 ${t("repo.type.artifact")}`, className: "badge-purple", kind: "artifact" };
  }
  return {
    label: artifact || media || t("repo.type.unknown"),
    className: "badge-gray",
    kind: "unknown",
  };
}

export async function copyToClipboard(text: string): Promise<boolean> {
  if (!navigator.clipboard?.writeText) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
