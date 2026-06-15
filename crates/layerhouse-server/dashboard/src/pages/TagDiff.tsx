import { createEffect, createSignal } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import { fetchManifest } from "../lib/api";
import type { ManifestResponse } from "../lib/types";
import LoadingSpinner from "../components/LoadingSpinner";
import ErrorBanner from "../components/ErrorBanner";

export default function TagDiff() {
  const params = useParams<{ name: string; a: string; b: string }>();
  const navigate = useNavigate();
  const [manifestA, setManifestA] = createSignal<ManifestResponse | null>(null);
  const [manifestB, setManifestB] = createSignal<ManifestResponse | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  const repo = () => decodeURIComponent(params.name);
  const tagA = () => decodeURIComponent(params.a);
  const tagB = () => decodeURIComponent(params.b);

  createEffect(() => {
    Promise.all([fetchManifest(repo(), tagA()), fetchManifest(repo(), tagB())])
      .then(([a, b]) => {
        setManifestA(a);
        setManifestB(b);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to fetch manifests"))
      .finally(() => setLoading(false));
  });

  return (
    <div>
      <div class="page-header">
        <h1>Diff: {repo()}</h1>
        <button class="btn" onClick={() => navigate(`/repos/${encodeURIComponent(repo())}`)}>
          Back
        </button>
      </div>

      {error() && <ErrorBanner message={error()!} />}

      {loading() ? (
        <LoadingSpinner label="Fetching manifests..." />
      ) : (
        <div class="diff-container">
          <div>
            <h3>
              {tagA()}{" "}
              <code style="font-size:0.75rem">{manifestA()?.digest.slice(0, 12) ?? ""}</code>
            </h3>
            <pre>{manifestA() ? JSON.stringify(manifestA()!.body, null, 2) : "not found"}</pre>
          </div>
          <div>
            <h3>
              {tagB()}{" "}
              <code style="font-size:0.75rem">{manifestB()?.digest.slice(0, 12) ?? ""}</code>
            </h3>
            <pre>{manifestB() ? JSON.stringify(manifestB()!.body, null, 2) : "not found"}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
