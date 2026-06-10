# TLS Rotation

## Public Registry TLS

1. Issue a new certificate for the public registry endpoint. Public ACME
   issuers must only receive public DNS names, not Kubernetes `.svc` names.
2. Update the Secret referenced by `server.tls.existingSecret`.
3. Restart the StatefulSet pods one at a time:

   ```bash
   kubectl -n layerhouse rollout restart statefulset/layerhouse
   kubectl -n layerhouse rollout status statefulset/layerhouse
   ```

4. Update node container runtime trust if the issuing CA changed.

## Raft mTLS

Raft mTLS certs are loaded at process start. Rotate by updating the Secret
referenced by `raft.tls.existingSecret`, then rolling the StatefulSet.

`layerhouse-raft-mtls` is the active Raft mTLS Secret name. It is not legacy:
manual air-gapped installs provide `server-ca.crt` and `client-ca.crt`, while
cert-manager installs provide `ca.crt` and the Helm chart maps it to both trust
paths.

If the Raft CA changes, use a staged CA bundle:

1. Add both old and new CA certificates to `server-ca.crt` and `client-ca.crt`.
2. Roll all pods so every peer trusts both CAs.
3. Replace the Raft leaf certificate/key with certs signed by the new CA.
4. Roll all pods again.
5. Remove the old CA from both bundles.
6. Roll all pods a final time.

This avoids splitting the cluster between peers that trust different CAs.
