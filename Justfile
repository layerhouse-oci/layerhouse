set dotenv-load := true

dashboard_dir := "crates/orb-chrysa-server/dashboard"

default:
    @just --list

fmt:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

coverage-nextest:
    cargo llvm-cov nextest --workspace --lcov --output-path coverage/lcov.info

dashboard-build:
    cd {{dashboard_dir}} && vp build

check: fmt clippy test dashboard-build

helm-check:
    helm lint deploy/kubernetes/helm -f deploy/kubernetes/helm/test-values/minimal.yaml
    helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/minimal.yaml >/dev/null
    helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/auth-enabled.yaml >/dev/null
    helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/cert-manager.yaml >/dev/null
    helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/air-gapped.yaml >/dev/null
    bash -euo pipefail -c 'out="$(mktemp)"; helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/minimal.yaml > "$out"; grep -q "listen = \"0.0.0.0:5050\"" "$out"; grep -q "listen = \"0.0.0.0:5051\"" "$out"; rm -f "$out"'
    bash -euo pipefail -c 'out="$(mktemp)"; helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/cert-manager.yaml > "$out"; grep -q "registry.example.internal" "$out"; grep -q "orb-chrysa-nodeport.example.internal" "$out"; rm -f "$out"'
    bash -euo pipefail -c 'out="$(mktemp)"; helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/minimal.yaml --set replicaCount=1 > "$out"; grep -q "minAvailable: 1" "$out"; rm -f "$out"'
    bash -euo pipefail -c 'out="$(mktemp)"; helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/minimal.yaml --set replicaCount=3 > "$out"; grep -q "minAvailable: 2" "$out"; rm -f "$out"'
    bash -euo pipefail -c 'if helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/minimal.yaml --set replicaCount=0 >/tmp/orb-chrysa-replica-zero.out 2>&1; then cat /tmp/orb-chrysa-replica-zero.out; exit 1; fi; grep -q "replicaCount must be at least 1" /tmp/orb-chrysa-replica-zero.out; rm -f /tmp/orb-chrysa-replica-zero.out'
    bash -euo pipefail -c 'out="$(mktemp)"; helm template orb-chrysa deploy/kubernetes/helm --namespace orb-chrysa -f deploy/kubernetes/helm/test-values/minimal.yaml > "$out"; grep -q "\\[raft.kubernetes\\]" "$out"; grep -q "statefulset_name = \"orb-chrysa\"" "$out"; grep -q "kind: Role" "$out"; grep -q "statefulsets" "$out"; grep -q "preStop:" "$out"; rm -f "$out"'

# ── Binary deployment tarball ──────────────────────────────────────────

pack_version := "0.1.0"
pack_target := "x86_64-unknown-linux-gnu"
pack_out_dir := "dist"
rustfs_version := "1.0.0-beta.6"

# Build orb-chrysa for the target platform and download RustFS + OxMgr,
# then pack everything into a self-contained tarball.
#
#   just pack-binary                          # defaults: linux/amd64
#   just pack-binary pack_target=aarch64-unknown-linux-gnu
pack-binary: pack-build pack-deps pack-tarball

# Build orb-chrysa-server for the target platform.
# Uses cargo-zigbuild for cross-compilation if available, falls back to cargo build.
# Install: cargo install cargo-zigbuild
pack-build:
    @mkdir -p {{pack_out_dir}}/bin
    @if which cargo-zigbuild > /dev/null 2>&1; then \
        echo "Building with cargo-zigbuild for {{pack_target}}"; \
        cargo zigbuild --release -p orb-chrysa-server --target {{pack_target}}; \
    elif rustup target list --installed | grep -q {{pack_target}}; then \
        echo "Building with cargo for {{pack_target}}"; \
        cargo build --release -p orb-chrysa-server --target {{pack_target}}; \
    else \
        echo "Target {{pack_target}} not installed. Either:"; \
        echo "  cargo install cargo-zigbuild  (recommended, handles C deps)"; \
        echo "  rustup target add {{pack_target}} && apt install gcc-{{pack_target}}"; \
        exit 1; \
    fi
    cp target/{{pack_target}}/release/orb-chrysa-server {{pack_out_dir}}/bin/

# Download RustFS and OxMgr binaries for the target platform.
pack-deps: pack-deps-rustfs pack-deps-oxmgr

# Download RustFS from GitHub releases (version {{rustfs_version}}).
# Override: RUSTFS_URL=... just pack-deps-rustfs
pack-deps-rustfs:
    @mkdir -p {{pack_out_dir}}/bin
    @url="$${RUSTFS_URL:-https://github.com/rustfs/rustfs/releases/download/{{rustfs_version}}/rustfs-linux-x86_64-gnu-v{{rustfs_version}}.zip}"; \
    echo "Downloading RustFS {{rustfs_version}} from $$url"; \
    tmp="$$(mktemp -d)"; \
    curl -fsSL "$$url" -o "$$tmp/rustfs.zip"; \
    unzip -qo "$$tmp/rustfs.zip" -d "$$tmp"; \
    find "$$tmp" -name rustfs -type f -exec cp {} {{pack_out_dir}}/bin/rustfs \;; \
    chmod +x {{pack_out_dir}}/bin/rustfs; \
    rm -rf "$$tmp"

# Download OxMgr. Override URL with OXMGR_URL env var.
pack-deps-oxmgr:
    @mkdir -p {{pack_out_dir}}/bin
    @if [ -n "$$OXMGR_URL" ]; then \
        echo "Downloading OxMgr from $$OXMGR_URL"; \
        curl -fsSL "$$OXMGR_URL" -o {{pack_out_dir}}/bin/oxmgr && chmod +x {{pack_out_dir}}/bin/oxmgr; \
    else \
        echo "OXMGR_URL not set — skipping OxMgr download."; \
        echo "Set OXMGR_URL or place oxmgr binary in {{pack_out_dir}}/bin/ manually."; \
    fi

# Pack the tarball.
pack-tarball: pack-copy-configs pack-write-readme
    @mkdir -p {{pack_out_dir}}
    @tar -czf {{pack_out_dir}}/orb-chrysa-{{pack_version}}-{{pack_target}}.tar.gz \
        -C {{pack_out_dir}} bin config oxfile.toml README
    @echo "Tarball: {{pack_out_dir}}/orb-chrysa-{{pack_version}}-{{pack_target}}.tar.gz"

pack-copy-configs:
    mkdir -p {{pack_out_dir}}/config
    cp deploy/binary/config/standalone.toml {{pack_out_dir}}/config/
    cp deploy/binary/oxmgr/oxfile.toml {{pack_out_dir}}/

pack-write-readme:
    @echo 'orb-chrysa {{pack_version}} — binary deployment' > {{pack_out_dir}}/README
    @echo '' >> {{pack_out_dir}}/README
    @echo 'Quick start:' >> {{pack_out_dir}}/README
    @echo '  1. Start RustFS on port 9000' >> {{pack_out_dir}}/README
    @echo '  2. ./bin/orb-chrysa-server --config config/standalone.toml' >> {{pack_out_dir}}/README
    @echo '' >> {{pack_out_dir}}/README
    @echo 'With OxMgr:' >> {{pack_out_dir}}/README
    @echo '  ./bin/oxmgr apply oxfile.toml' >> {{pack_out_dir}}/README

pack-clean:
    rm -rf {{pack_out_dir}}/bin {{pack_out_dir}}/config {{pack_out_dir}}/oxfile.toml {{pack_out_dir}}/README
    rm -f {{pack_out_dir}}/orb-chrysa-*.tar.gz

# ── Compose ────────────────────────────────────────────────────────────

compose-up:
    docker compose -f deploy/compose/cluster.yml up -d

compose-auth-up:
    docker compose -f deploy/compose/auth-cluster.yml up -d

compose-auth-down:
    docker compose -f deploy/compose/auth-cluster.yml down -v

cluster-status:
    curl -fsS http://localhost:5050/api/v1/admin/cluster/status | jq '{leader_id, quorum, healthy_voters}'

production-smoke:
    tests/production/run-all.sh

production-oci:
    tests/production/oci-workflow.sh

production-mirror-proxy:
    tests/production/mirror-proxy-workflow.sh

auth-smoke:
    tests/production/auth-workflow.sh

tilt-up:
    tests/k8s/tilt/kind-up.sh
    tilt up --context kind-orb-chrysa-tilt

tilt-ci:
    tests/k8s/tilt/kind-up.sh
    tilt ci --context kind-orb-chrysa-tilt

tilt-ci-host-docker:
    tests/k8s/tilt/kind-up.sh
    tilt ci --context kind-orb-chrysa-tilt -- --host_docker_trust

tilt-smoke:
    tests/k8s/tilt-full-smoke.sh

tilt-smoke-host-docker:
    REQUIRE_HOST_DOCKER_PUSH=1 tests/k8s/tilt-full-smoke.sh

tilt-failure-smoke:
    tests/k8s/tilt-failure-smoke.sh

tilt-recovery-smoke:
    tests/k8s/tilt-recovery-smoke.sh

tilt-scale-smoke:
    tests/k8s/tilt-scale-smoke.sh

tilt-host-docker-trust *ARGS:
    tests/k8s/tilt/host-docker-trust.sh {{ARGS}}

tilt-down:
    tests/k8s/tilt/kind-down.sh

release-dry-run:
    tests/release/dry-run.sh

conformance:
    tests/conformance/run.sh

docs-check:
    cd docs/mdbook && mdbook build

book:
    just docs-check

book-serve:
    cd docs/mdbook && mdbook serve --open
