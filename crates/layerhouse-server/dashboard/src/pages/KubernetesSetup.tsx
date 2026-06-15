import { createMemo, createSignal, For } from "solid-js";
import { copyToClipboard } from "../lib/format";
import { t } from "../lib/i18n";

type Snippet = {
  title: string;
  note: string;
  body: string;
};

function defaultEndpoint(): string {
  const host = window.location.host || "registry.internal.example.com:32000";
  return host.includes("localhost") ? "registry.internal.example.com:32000" : host;
}

function registryHost(endpoint: string): string {
  const trimmed = endpoint.trim();
  if (!trimmed.includes(":")) return trimmed;
  if (trimmed.startsWith("[") && trimmed.includes("]")) {
    return trimmed.slice(1, trimmed.indexOf("]"));
  }
  return trimmed.split(":")[0];
}

export default function KubernetesSetup() {
  const [endpoint, setEndpoint] = createSignal(defaultEndpoint());
  const [namespace, setNamespace] = createSignal("layerhouse");
  const [serverSecret, setServerSecret] = createSignal("layerhouse-server-tls");
  const [raftSecret, setRaftSecret] = createSignal("layerhouse-raft-mtls");
  const [copied, setCopied] = createSignal<string | null>(null);

  async function copy(key: string, value: string) {
    if (await copyToClipboard(value)) {
      setCopied(key);
      window.setTimeout(() => setCopied((current) => (current === key ? null : current)), 1600);
    }
  }

  const snippets = createMemo<Snippet[]>(() => {
    const ep = endpoint().trim() || "registry.internal.example.com:32000";
    const host = registryHost(ep);
    const ns = namespace().trim() || "layerhouse";
    const serverTlsSecret = serverSecret().trim() || "layerhouse-server-tls";
    const raftTlsSecret = raftSecret().trim() || "layerhouse-raft-mtls";

    return [
      {
        title: t("setup.snippet.cert"),
        note: t("setup.snippet.certNote"),
        body: `layerhouse-ctl air-gapped cert init \\
  --registry-host ${host} \\
  --namespace ${ns} \\
  --statefulset-name layerhouse \\
  --headless-service layerhouse-headless \\
  --replicas 3 \\
  --out ./layerhouse-airgap`,
      },
      {
        title: t("setup.snippet.bundle"),
        note: t("setup.snippet.bundleNote"),
        body: `layerhouse-ctl air-gapped k8s bundle-generate \\
  --registry-endpoint ${ep} \\
  --cert-dir ./layerhouse-airgap/certs \\
  --namespace ${ns} \\
  --server-tls-secret ${serverTlsSecret} \\
  --raft-tls-secret ${raftTlsSecret} \\
  --out ./layerhouse-airgap`,
      },
      {
        title: t("setup.snippet.helm"),
        note: t("setup.snippet.helmNote"),
        body: `helm upgrade --install layerhouse ./charts/layerhouse \\
  --namespace ${ns} \\
  --create-namespace \\
  -f ./layerhouse-airgap/helm/values-air-gapped.yaml`,
      },
      {
        title: t("setup.snippet.containerd"),
        note: t("setup.snippet.containerdNote"),
        body: `install -d /etc/containerd/certs.d/${ep}
install -m 0644 ./layerhouse-airgap/containerd/ca.crt /etc/containerd/certs.d/${ep}/ca.crt
install -m 0644 ./layerhouse-airgap/containerd/hosts.toml /etc/containerd/certs.d/${ep}/hosts.toml
systemctl restart containerd`,
      },
      {
        title: t("setup.snippet.pullSecret"),
        note: t("setup.snippet.pullSecretNote"),
        body: `kubectl -n ${ns} create secret docker-registry layerhouse-pull \\
  --docker-server=${ep} \\
  --docker-username=USERNAME \\
  --docker-password=TOKEN`,
      },
      {
        title: t("setup.snippet.verify"),
        note: t("setup.snippet.verifyNote"),
        body: `curl --cacert ./layerhouse-airgap/certs/ca.crt https://${ep}/v2/
crictl pull ${ep}/qa/alpine:v1
kubectl run layerhouse-pull-test --image=${ep}/qa/alpine:v1 --restart=Never`,
      },
    ];
  });

  return (
    <div>
      <div class="page-header">
        <div>
          <p class="eyebrow">{t("setup.eyebrow")}</p>
          <h1>{t("setup.title")}</h1>
          <p class="page-copy">{t("setup.copy")}</p>
        </div>
      </div>

      <div class="setup-grid">
        <section class="card setup-panel">
          <h2>{t("setup.inputs")}</h2>
          <div class="form-group">
            <label>{t("setup.endpoint")}</label>
            <input value={endpoint()} onInput={(e) => setEndpoint(e.currentTarget.value)} />
          </div>
          <div class="form-grid">
            <div class="form-group">
              <label>{t("setup.namespace")}</label>
              <input value={namespace()} onInput={(e) => setNamespace(e.currentTarget.value)} />
            </div>
            <div class="form-group">
              <label>{t("setup.serverTlsSecret")}</label>
              <input
                value={serverSecret()}
                onInput={(e) => setServerSecret(e.currentTarget.value)}
              />
            </div>
            <div class="form-group">
              <label>{t("setup.raftTlsSecret")}</label>
              <input value={raftSecret()} onInput={(e) => setRaftSecret(e.currentTarget.value)} />
            </div>
          </div>
          <div class="setup-runtime">
            <span class="badge badge-blue">containerd</span>
            <p>{t("setup.runtimeNote")}</p>
          </div>
        </section>

        <section class="card setup-panel">
          <h2>{t("setup.boundary")}</h2>
          <p>{t("setup.boundaryCopy")}</p>
          <ul class="setup-list">
            <li>{t("setup.boundaryAuth")}</li>
            <li>{t("setup.boundaryNode")}</li>
            <li>{t("setup.boundaryCa")}</li>
          </ul>
        </section>
      </div>

      <div class="setup-snippets">
        <For each={snippets()}>
          {(snippet, index) => (
            <section class="card setup-snippet">
              <div class="setup-snippet-header">
                <div>
                  <h2>{snippet.title}</h2>
                  <p>{snippet.note}</p>
                </div>
                <button
                  class="btn btn-compact"
                  onClick={() => copy(`snippet-${index()}`, snippet.body)}
                >
                  {copied() === `snippet-${index()}` ? t("common.copied") : t("common.copy")}
                </button>
              </div>
              <pre>{snippet.body}</pre>
            </section>
          )}
        </For>
      </div>
    </div>
  );
}
