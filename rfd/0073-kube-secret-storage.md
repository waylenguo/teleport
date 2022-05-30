---
authors: Tiago Silva (tiago.silva@goteleport.com)
state: draft
---

# RFD 73 - Teleport Kube-Agent credential storage in Kubernetes Native Secrets

## What

Teleport Kubernetes Agent support for dynamic short-lived tokens relying only on native Kubernetes Secrets for identity storage.

### Related issues

- [#5585](https://github.com/gravitational/teleport/issues/5585)

## Why

When a Teleport Agent wants to join a Teleport Cluster, it needs to share the invite token with the cluster for initial authentication. The invite token can be:

- Short-lived token (the token will expire after a low TTL and cannot be reused after that time).
- Long-lived/static token (the usage of long-lived tokens is discouraging for security reasons).

After sharing the invite token with the Teleport cluster, the agent receives its identity from the Auth service. Identity certificates are mandatory for accessing the Teleport Cluster and must be stored for accesses without reusing the invite token.

Kubernetes Pods are, by definition, expected to be stateless. This means that each time a Pod is recycled because it was restarted, deleted, upgraded, or moved to another node, the state that was written to its filesystem is lost.

One way to overcome this problem is to use Persistent Volumes. PV is a Kubernetes feature that mounts a storage volume in the container filesystem, whose lifecycle is independent of the Pod that mounts it. Kubernetes’ PV storage has its own drawbacks. Persistent Volumes are very distinct between different cloud vendors. Some providers lock volumes to be mounted in the same zone they were created, meaning that if Teleport agent Pod is recycled, it must be maintained in the same zone it was created. This creates operational issues and for on-premises deployments might be difficult to manage.

Another possibility is that the Kube Agent might use the invite token each time the pod is recycled, meaning that it issues a join request to the cluster every time it starts and receives a new identity from the Auth service. This means that the invite token must be a static/long-lived token, otherwise after a while the agent could not register himself in the cluster because the invite token expired. This approach is not recommended and might cause security flaws because the join token can be stolen or guessed.

One solution that might address all the issues referenced above is to allow the Kube agent to use Kubernetes secrets as storage backend. This allows not only that the agent is able to run stateless depending only on native objects generally available in any Kubernetes cluster, but also that the agent might support dynamic short-lived invite tokens with no dependency on external storage.

## Details

### Limitations

High availability can only be achieved using Statefulsets and not deployments. This means that if the desired number of replicas is bigger than one, i.e, `replicas > 1`, the [Helm chart](https://github.com/gravitational/teleport/tree/master/examples/chart/teleport-kube-agent) has to switch to Statefulset objects instead of Deployments. This change is required because some Kubernetes invariant must be kept between restarts in order to correctly map each agent pod to its identity stored in the secret. The invariant used is the Statefulset pod names `{{ .Release.Name }}-{0...replicas}}`.

Given this, it is required to expose the `$TELEPORT_REPLICA_NAME` environment variable to each pod in order to the backend storage be able to write the identity separately. The values for `$TELEPORT_REPLICA_NAME` are dependent on the object type:

- Deployment: `TELEPORT_REPLICA_NAME` is a constant string `{{ .Release.Name }}`.
- Statefulset: `TELEPORT_REPLICA_NAME` is a dynamic value provided by Kubernetes `fieldPath: metadata.name`.

When an operator wants to upgrade from an old chart to the Helm chart that implements this RFD and his setup has no storage, it's running as Deployment, and the replica number was bigger than 1, it will lead into a switch from Deployment to a Statefulset. 
This change is managed by Helm by destroying the Deployment object and creating the new Statefulset. During this transition, even if the operator has the PodDisruptionBudget object enabled, the Kubernetes cluster might become inaccessible from Teleport because there is no guarantee that the system has at least one agent replica running.

Another limitation that appears when the operator wants to change the number of replicas is that this process must necessarily be executed through Helm. If the operator decides to do a manual increase of replicas by editing the Kubernetes objects, it will have the following limitations, depending on the object type:

- `Deployment`: all agents will use the exact same identity when accessing the cluster.
- `Statefulset`: some replicas will fail to start. They will try to join the cluster again because they cannot read their secrets. This happens because each replica will have its own identity secret and RBAC only lists access rules to some of them, resulting in pods not being able to read the secrets for newest replicas and, eventually, the new replicas will trigger the cluster invitation process.

### Secret creation and lifecycle

Secrets are created, read and updated by the agent.
The agent will never issue a delete request to destroy the secret. This is achieved by Helm's `post-delete` hook once `helm uninstall` is executed.

#### Secret content

Once Kube Agent updates the secret, it will have the following structure:

```yaml
apiVersion: v1
data: |
        {{.Values.kubeClusterName}}:
            {
            "kind": "identity",
            "version": "v2",
            "metadata": {
                "name": "current"
            },
            "spec": {
                "key": "{key_content}",
                "ssh_cert": "{ssh_cert_content}",
                "tls_cert": "{tls_cert_content}",
                "tls_ca_certs": ["tls_ca_certs"],
                "ssh_ca_certs": ["ssh_ca_certs"]
            }
            }
    
kind: Secret
metadata:
  name: {.Release.Name}-identity-{{$TELEPORT_REPLICA_NAME}}
  namespace: {.Release.Namespace}
```

Where:

- `ssh_cert` is a PEM encoded SSH host cert.
- `key` is a PEM encoded private key.
- `tls_cert` is a PEM encoded x509 client certificate.
- `tls_ca_certs` is a list of PEM encoded x509 certificate of the certificate authority of the cluster.
- `ssh_ca_certs` is a list of SSH certificate authorities encoded in the authorized_keys format.
- `TELEPORT_REPLICA_NAME` is the teleport agent replica name. Constant when using Deployments, `TELEPORT_REPLICA_NAME={{ .Release.Name}}` or dynamic when using Statefulsets, `TELEPORT_REPLICA_NAME=metadata.name`.

#### RBAC Changes

The Teleport Kube Agent service account must be able to create, read and update secrets within the namespace, therefore, one must create a new namespace role and attach it to the Kube Agent service account with the following content:

```yaml
- apiGroups: [""]
  # objects is "secrets"
  resources: ["secrets"]
  verbs: ["create"] # create must have a special case in RBAC since we cannot block creation of the secret based on resource name.
- apiGroups: [""]
  # objects is "secrets"
  resources: ["secrets"]
  resourcesNames: 
  - "{.Release.Name}-identity-{{$TELEPORT_REPLICA_NAME}}" # initial secrets
  - ... # other identities if # replicas is higher than 1
  verbs: ["get", "update","watch", "list"]
```

The RBAC only allows the service account to read and update the secrets listed under `resourceNames` entry. The `create` verb must be handled in a separate case because during the authorization of the request, Kubernetes does not know the resource name and cannot allow the resource creation [[1](#Links)].

### Teleport Changes

#### Kube Secret as storage backend

If secret storage is enabled, the Teleport Kube agent initializes with Kubernetes secret [backend storage](https://goteleport.com/docs/setup/reference/backends/). The backend storage availability for Teleport will be the following:

| Data type | Description | Supported storage backends |
|---|---|---|
| core cluster state | Cluster configuration (e.g. users, roles, auth connectors) and identity (e.g. certificate authorities, registered nodes, trusted clusters). | Local directory (SQLite), etcd, AWS DynamoDB, GCP Firestore, self-hosted PostgreSQL/CockroachDB (Preview) |
| audit events | JSON-encoded events from the audit log (e.g. user logins, RBAC changes) | Local directory, AWS DynamoDB, GCP Firestore |
| session recordings | Raw terminal recordings of interactive user sessions | Local directory, AWS S3 (and any S3-compatible product), GCP Cloud Storage |
| teleport instance state | ID and credentials of a non-auth teleport instance (e.g. node, proxy, kube) | Local directory, Kube Secret (only available for role=kube) |

The storage backend will be responsible for managing the Kubernetes secret, i.e. reading and updating its contents, in order to create a transparent storage backend.

If the identity secret exists in Kubernetes and has the node identity on it (entry for `$TELEPORT_REPLICA_NAME`), the storage engine will parse and return the keys to the Agent, so it can use them to authenticate in the Teleport Cluster. If the cluster access operation is successful, the agent will be available for usage, but if the access operation fails because the Teleport Auth does not validate the node credentials, the Agent will log an error providing insightful information about the failure cause.

In case of the identity secret does not exist or is empty, the Kube Agent will try to join the cluster with the invite token provided. If the invite token is valid (has details in the Teleport Cluster and did not expire yet), Teleport Cluster will reply with the agent identity. Given the identity, the Kube Agent will issue a write request to the storage backend that results in the update of the content in the secret `{{ .Release.Name }}-identity`.

If the invite token is not valid or has expired, the Agent could not join the cluster, and it will stop and log a meaningful error message.

The following diagram demonstrates the behavior when using Kubernetes' Secret backend storage.

```text
                                                              ┌─────────┐                                        ┌────────┐          ┌──────────┐                    
                                                              │KubeAgent│                                        │Teleport│          │Kubernetes│                    
                                                              └────┬────┘                                        └───┬────┘          └────┬─────┘                    
                                                                   ────┐                                             │                    │                          
                                                                       │ init procedure                              │                    │                          
                                                                   <───┘                                             │                    │                          
                                                                   │                                                 │                    │                          
                                                                   │                          Get Secret Data        │                   ┌┴┐                         
                                                                   │────────────────────────────────────────────────────────────────────>│ │                         
                                                                   │                                                 │                   │ │                         
                                                                   │                                                 │                   │ │                         
         ╔══════╤══════════════════════════════════════════════════╪═════════════════════════════════════════════════╪═══════════════════╪═╪════════════════════════╗
         ║ ALT  │  Identity data is present in Secret              │                                                 │                   │ │                        ║
         ╟──────┘                                                  │                                                 │                   │ │                        ║
         ║                                                         │                        returns secret data      │                   │ │                        ║
         ║                                                         │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ │                        ║
         ║                                                         │                                                 │                   │ │                        ║
         ║                                                         │ Joining the cluster with identity from secret  ┌┴┐                  │ │                        ║
         ║                                                         │───────────────────────────────────────────────>│ │                  │ │                        ║
         ║                                                         │                                                │ │                  │ │                        ║
         ║                                                         │                                                │ │                  │ │                        ║
         ║                   ╔══════╤══════════════════════════════╪════════════════════════════════════════════════╪═╪═════════════╗    │ │                        ║
         ║                   ║ ALT  │  successful case             │                                                │ │             ║    │ │                        ║
         ║                   ╟──────┘                              │                                                │ │             ║    │ │                        ║
         ║                   ║                                     │Node successfully authenticated and registered  │ │             ║    │ │                        ║
         ║                   ║                                     │in the cluster                                  │ │             ║    │ │                        ║
         ║                   ║                                     │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│ │             ║    │ │                        ║
         ║                   ╠═════════════════════════════════════╪════════════════════════════════════════════════╪═╪═════════════╣    │ │                        ║
         ║                   ║ [identity signed by a different Auth server]                                         │ │             ║    │ │                        ║
         ║                   ║                                     │Node identity signed by a different Auth Server │ │             ║    │ │                        ║
         ║                   ║                                     │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│ │             ║    │ │                        ║
         ║                   ║                                     │                                                │ │             ║    │ │                        ║
         ║                   ║      ╔════════════════════════════╗ ────┐                                            │ │             ║    │ │                        ║
         ║                   ║      ║unable to join the cluster ░║     │ failure state.                             │ │             ║    │ │                        ║
         ║                   ║      ║logs the error              ║ <───┘                                            │ │             ║    │ │                        ║
         ║                   ╚══════╚════════════════════════════╝═╪════════════════════════════════════════════════╪═╪═════════════╝    │ │                        ║
         ╠═════════════════════════════════════════════════════════╪═════════════════════════════════════════════════════════════════════╪═╪════════════════════════╣
         ║ [Identity data is not present in Secret]                │                                                 │                   │ │                        ║
         ║                                                         │                           returns error         │                   │ │                        ║
         ║                                                         │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ │                        ║
         ║                                                         │                                                 │                   │ │                        ║
         ║                                                         │               Sends invite code                ┌┴┐                  │ │                        ║
         ║                                                         │───────────────────────────────────────────────>│ │                  │ │                        ║
         ║                                                         │                                                │ │                  │ │                        ║
         ║                                                         │                                                │ │                  │ │                        ║
         ║         ╔══════╤════════════════════════════════════════╪════════════════════════════════════════════════╪═╪══════════════════╪═╪══════════════╗         ║
         ║         ║ ALT  │  successful case                       │                                                │ │                  │ │              ║         ║
         ║         ╟──────┘                                        │                                                │ │                  │ │              ║         ║
         ║         ║                                               │             returns node identity              │ │                  │ │              ║         ║
         ║         ║                                               │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│ │                  │ │              ║         ║
         ║         ║                                               │                                                │ │                  └┬┘              ║         ║
         ║         ║                                               │                  Updates secret data with Identity                   │               ║         ║
         ║         ║                                               │─────────────────────────────────────────────────────────────────────>│               ║         ║
         ║         ║                                               │                                                │ │                   │               ║         ║
         ║         ║                                               │               joins the cluster                │ │                   │               ║         ║
         ║         ║                                               │───────────────────────────────────────────────>│ │                   │               ║         ║
         ║         ╠═══════════════════════════════════════════════╪════════════════════════════════════════════════╪═╪═══════════════════╪═══════════════╣         ║
         ║         ║ [invite code expired]                         │                                                │ │                   │               ║         ║
         ║         ║                                               │          invalid invite token error            │ │                   │               ║         ║
         ║         ║                                               │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│ │                   │               ║         ║
         ║         ║                                               │                                                │ │                   │               ║         ║
         ║         ║      ╔══════════════════════════════════════╗ ────┐                                            │ │                   │               ║         ║
         ║         ║      ║unable to join the cluster           ░║     │ failure state.                             │ │                   │               ║         ║
         ║         ║      ║because the invite might be expired.  ║ <───┘                                            │ │                   │               ║         ║
         ║         ║      ║logs the error                        ║ │                                                │ │                   │               ║         ║
         ║         ╚══════╚══════════════════════════════════════╝═╪════════════════════════════════════════════════╪═╪═══════════════════╪═══════════════╝         ║
         ╚═════════════════════════════════════════════════════════╪══════════════════════════════════════════════════════════════════════╪═════════════════════════╝
                                                                   │                                                 │                    │                          
                                                                   │                                                 │                    │                          
                                                    ╔═══════╤══════╪═════════════════════════════════════════════════╪════════════════════╪═══════════════╗          
                                                    ║ LOOP  │  CA  rotation                                          │                    │               ║          
                                                    ╟───────┘      │                                                 │                    │               ║          
                                                    ║              │              Rotate certificates                │                    │               ║          
                                                    ║              │<───────────────────────────────────────────────>│                    │               ║          
                                                    ║              │                                                 │                    │               ║          
                                                    ║              │                New certificates                 │                    │               ║          
                                                    ║              │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │                    │               ║          
                                                    ║              │                                                 │                    │               ║          
                                                    ║              │                     Update secret content       │                    │               ║          
                                                    ║              │─────────────────────────────────────────────────────────────────────>│               ║          
                                                    ╚══════════════╪═════════════════════════════════════════════════╪════════════════════╪═══════════════╝          
                                                              ┌────┴────┐                                        ┌───┴────┐          ┌────┴─────┐                    
                                                              │KubeAgent│                                        │Teleport│          │Kubernetes│                    
                                                              └─────────┘                                        └────────┘          └──────────┘                    
```

### Backend storage

Kubernetes Secret backend storage must satisfy the `Backend` interface.

```go
// Backend implements abstraction over local or remote storage backend.
// Item keys are assumed to be valid UTF8, which may be enforced by the
// various Backend implementations.
type Backend interface {
    // Create creates item if it does not exist
    Create(ctx context.Context, i Item) (*Lease, error)

    // Put puts value into backend (creates if it does not
    // exists, updates it otherwise)
    Put(ctx context.Context, i Item) (*Lease, error)

    // CompareAndSwap compares item with existing item
    // and replaces is with replaceWith item
    CompareAndSwap(ctx context.Context, expected Item, replaceWith Item) (*Lease, error)

    // Update updates value in the backend
    Update(ctx context.Context, i Item) (*Lease, error)

    // Get returns a single item or not found error
    Get(ctx context.Context, key []byte) (*Item, error)

    // GetRange returns query range
    GetRange(ctx context.Context, startKey []byte, endKey []byte, limit int) (*GetResult, error)

    // Delete deletes item by key, returns NotFound error
    // if item does not exist
    Delete(ctx context.Context, key []byte) error

    // DeleteRange deletes range of items with keys between startKey and endKey
    DeleteRange(ctx context.Context, startKey, endKey []byte) error

    // KeepAlive keeps object from expiring, updates lease on the existing object,
    // expires contains the new expiry to set on the lease,
    // some backends may ignore expires based on the implementation
    // in case if the lease managed server side
    KeepAlive(ctx context.Context, lease Lease, expires time.Time) error

    // NewWatcher returns a new event watcher
    NewWatcher(ctx context.Context, watch Watch) (Watcher, error)

    // Close closes backend and all associated resources
    Close() error

    // Clock returns clock used by this backend
    Clock() clockwork.Clock

    // CloseWatchers closes all the watchers
    // without closing the backend
    CloseWatchers()
}
```

During the startup procedure, the backend instantiates a Kubernetes client with configuration provided by `restclient.InClusterConfig()`. This configuration uses the credentials for the service account configured for the pod.

For each method defined in the backend interface, one must use the Kubernetes client in order to operate the secret.

The storage must, for now, skip the writing requests for events of type `kind=state` and each time an identity write request is issued it must replace the content of its entry in the secret with the fresh content. Storage engine might use resource lock feature from Kubernetes (`resourceVersion`) to implement optimistic locking in order to prevent different agents to race while writing into the secret.

### CA Rotation

CA rotation feature allows the cluster operator to force the cluster to recreate and re-issue certificates for users and agents. During this procedure, agents and users receive the new keys signed by the newest CA from Teleport Auth.

While the cluster is transitioning, the keys signed by the old CA are considered valid, so the agent is able to receive its new identity certificates from Teleport Auth. Once this happens it will replace the identity stored in Kubernetes secret with the fresh ones and will immediately start using the new credentials to re-register in the cluster.

### Helm Chart Differences

#### File *templates/config.yaml*

```diff
{{- $logLevel := (coalesce .Values.logLevel .Values.log.level "INFO") -}}
{{- if .Values.teleportVersionOverride -}}
  {{- $_ := set . "teleportVersion" .Values.teleportVersionOverride -}}
{{- else -}}
  {{- $_ := set . "teleportVersion" .Chart.Version -}}
{{- end -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
  namespace: {{ .Release.Namespace }}
{{- if .Values.extraLabels.config }}
  labels:
  {{- toYaml .Values.extraLabels.config | nindent 4 }}
{{- end }}
  {{- if .Values.annotations.config }}
  annotations:
    {{- toYaml .Values.annotations.config | nindent 4 }}
  {{- end }}
data:
  teleport.yaml: |
    teleport:
+{{- if not (.Values.storage.enabled) }}
+     storage:
+       type: kubernetes_secret
+       secret_name: {{ .Release.Name }}-identity
+{{- end }}
      auth_token: "/etc/teleport-secrets/auth-token"
      auth_servers: ["{{ required "proxyAddr is required in chart values" .Values.proxyAddr }}"]
```

#### File *templates/deployment.yaml*

```diff
#
# Warning to maintainers, any changes to this file that are not specific to the Deployment need to also be duplicated
# in the statefulset.yaml file.
#
-{{- if not .Values.storage.enabled }}
{{- $replicaCount := (coalesce .Values.replicaCount .Values.highAvailability.replicaCount "1") }}
+{{- if and (not .Values.storage.enabled) (eq $replicaCount 1) }}
...
-        {{- if .Values.extraEnv }}
-        env:
-          {{- toYaml .Values.extraEnv | nindent 8 }}
-        {{- end }}
+        env:
+          - name: TELEPORT_REPLICA_NAME
+            value: {{ .Release.Name }}
+         {{- if .Values.extraEnv }}
+          {{- toYaml .Values.extraEnv | nindent 8 }}
+        {{- end }}
```

#### File *templates/statefulset.yaml*

```diff
#
# Warning to maintainers, any changes to this file that are not specific to the StatefulSet need to also be duplicated
# in the deployment.yaml file.
#
-{{- if .Values.storage.enabled }}
{{- $replicaCount := (coalesce .Values.replicaCount .Values.highAvailability.replicaCount "1") }}
+{{- if or (.Values.storage.enabled) (ne $replicaCount 1) }}
...
-        {{- if .Values.extraEnv }}
-        env:
-          {{- toYaml .Values.extraEnv | nindent 8 }}
-        {{- end }}
+        env:
+          - name: TELEPORT_REPLICA_NAME
+            valueFrom:
+              fieldRef:
+                 fieldPath: metadata.name
+         {{- if .Values.extraEnv }}
+          {{- toYaml .Values.extraEnv | nindent 10 }}
+        {{- end }}

# remove PV storage if storage is not enabled
...
+{{- if .Values.storage.enabled }}
        - mountPath: /var/lib/teleport
          name: "{{ .Release.Name }}-teleport-data"
+{{- end }}
...
+{{- if .Values.storage.enabled }}
  volumeClaimTemplates:
  - metadata:
      name: "{{ .Release.Name }}-teleport-data"
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: {{ .Values.storage.storageClassName }}
      resources:
        requests:
          storage: {{ .Values.storage.requests }}
+{{- end }}
{{- end }}
```

#### File *values.yaml*

Change storage comments

## Installation

If the user does not provide `storage.enabled=true`, Teleport Kube Agent enables, by default, the Kube secret storage. This means that there is no change to the end user.

```bash
$ helm install teleport-kube-agent . \
  --create-namespace \
  --namespace teleport \
  --set roles=kube \
  --set proxyAddr=${PROXY_ENDPOINT?} \
  --set authToken=${JOIN_TOKEN?} \
  --set kubeClusterName=${KUBERNETES_CLUSTER_NAME?}
```

# Links

- 1: https://kubernetes.io/docs/reference/access-authn-authz/rbac/

<!-- Plant UML diagrams -->
<!--

```plantuml
@startuml
participant KubeAgent 
participant Teleport
participant Kubernetes
KubeAgent -> KubeAgent: init procedure
KubeAgent -> Kubernetes: Get Secret Data
activate Kubernetes
alt Identity data is present in Secret
Kubernetes -> KubeAgent: returns secret data
    KubeAgent -> Teleport: Joining the cluster with identity from secret
    activate Teleport
    alt successful case
       Teleport->KubeAgent: Node successfully authenticated and registered\nin the cluster
       
    else identity signed by a different Auth server
        Teleport ->KubeAgent: Node identity signed by a different Auth Server 

    KubeAgent -> KubeAgent: failure state.
    note left
        unable to join the cluster
        logs the error
    end note

    end
deactivate Teleport
else Identity data is not present in Secret
Kubernetes -> KubeAgent: returns error
    KubeAgent -> Teleport: Sends invite code

activate Teleport
    alt successful case
        Teleport -> KubeAgent: returns node identity

        KubeAgent -> Kubernetes: Updates secret data with Identity
    deactivate Kubernetes
        KubeAgent -> Teleport: joins the cluster
    else invite code expired
    Teleport->KubeAgent: invalid invite token error

    KubeAgent -> KubeAgent: failure state.
    note left
        unable to join the cluster
        because the invite might be expired.
        logs the error
    end note
    end
       deactivate Teleport
       
end
  loop CA rotation
      KubeAgent<->Teleport: Rotate certificates
      Teleport -> KubeAgent: New certificates
      KubeAgent->Kubernetes: Update secret content
  end
@enduml
```
-->