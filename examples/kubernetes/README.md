# tunmgr with Kustomize

Here's an example of installing tunmgr using Kustomize with your own overrides. We recommend proxying all traffic through an [Ingress Controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/) or a [Gateway](https://kubernetes.io/docs/concepts/services-networking/gateway/) for maximum flexibility.

Create a `kustomization.yaml` file like the following:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
# We recommend pinning a specific commit SHA instead of main
- https://github.com/picosh/tunmgr//examples/kubernetes?ref=main
# Bring your own secret
- secret.yaml
namespace: tunmgr
patches:
- patch: |-
    - op: add
      path: /spec/template/spec/containers/0/args/-
      value: -tunnel=mysite.example.com:80:traefik.traefik.svc.cluster.local:80
```

Also create a `secret.yaml` file:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ssh-key
type: Opaque
stringData:
  id_ed25519: PUT_YOUR_PRIVATE_KEY_HERE
```

Then you can install it with `kubectl apply -k .`
