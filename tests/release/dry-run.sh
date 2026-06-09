#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.0.3}"
WORK="${WORK:-target/release-dry-run/$VERSION}"
SKIP_CHECK="${RELEASE_DRY_RUN_SKIP_CHECK:-0}"

umask 077
mkdir -p "$WORK/dist"
chmod -R go-rwx "$WORK"

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1" >&2
        exit 127
    fi
}

record() {
    "$@" 2>&1 | tee -a "$WORK/commands.log"
}

need grep
need helm
need just
need tar

{
    echo "VERSION=$VERSION"
    echo "WORK=$WORK"
    echo "RELEASE_DRY_RUN_SKIP_CHECK=$SKIP_CHECK"
} > "$WORK/summary.env"

if [ "$SKIP_CHECK" != "1" ]; then
    record just check
fi

record just helm-check
record helm package deploy/kubernetes/helm \
    --version "$VERSION" \
    --app-version "$VERSION" \
    --destination "$WORK/dist"

CHART="$WORK/dist/layerhouse-$VERSION.tgz"
if [ ! -s "$CHART" ]; then
    echo "ERROR: expected chart archive was not created: $CHART" >&2
    exit 1
fi

tar -xOf "$CHART" layerhouse/Chart.yaml > "$WORK/Chart.yaml"
grep -q "^version: $VERSION$" "$WORK/Chart.yaml"
grep -q "^appVersion: $VERSION$" "$WORK/Chart.yaml"

record helm template layerhouse "$CHART" \
    --namespace layerhouse \
    -f deploy/kubernetes/helm/test-values/minimal.yaml \
    > "$WORK/render-default.yaml"
grep -q "image: \"ghcr.io/adamcavendish/layerhouse-server:$VERSION\"" "$WORK/render-default.yaml"

record helm template layerhouse "$CHART" \
    --namespace layerhouse \
    -f deploy/kubernetes/helm/test-values/minimal.yaml \
    --set image.tag=tilt \
    > "$WORK/render-override.yaml"
grep -q 'image: "ghcr.io/adamcavendish/layerhouse-server:tilt"' "$WORK/render-override.yaml"

echo "PASS release dry run. Evidence: $WORK"
