# Helm/Kubernetes documentation for API

## Tiller

In order to use Helm, we first need to install Tiller:

```
$ kubectl create -f misc/helm-rbac-config.yaml
$ helm init --service-account tiller
```

## CloudSQL Proxy

CloudSQL Proxy is used to bridge the Kubernetes cluster with the CloudSQL instance.

```
$ kubectl create ns sqlproxy
$ helm upgrade psql0 stable/gcloud-sqlproxy --namespace sqlproxy \
    --set serviceAccountKey="$(cat service-account.json | base64)" \
    --set "cloudsql.instances[0].instance=psql0" \
    --set "cloudsql.instances[0].project=wott-prod" \
    --set "cloudsql.instances[0].region=us-central1" \
    --set "cloudsql.instances[0].port=5432" -i
```

## Nginx


```
$ kubectl create ns nginx
$ helm install stable/nginx-ingress \
    --name nginx0 \
    --namespace nginx \
    --set controller.service.externalTrafficPolicy=Local \
    --set controller.metrics.enabled=true \
    --set controller.stats.enabled=true
```

## Cert-manager

CertManager is used to facilitate Let's Encrypt certificate management. The installation instructions can be found [here](https://docs.cert-manager.io/en/latest/getting-started/install.html), but in short, here's what we need to do to install it:

```
# Install the CustomResourceDefinition resources separately
$ kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.6/deploy/manifests/00-crds.yaml

# Create the namespace for cert-manager
$ kubectl create namespace cert-manager

# Label the cert-manager namespace to disable resource validation
$ kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

# Update your local Helm chart repository cache
$ helm repo update

# Install the cert-manager Helm chart
$ helm install \
  --name cert-manager \
  --namespace cert-manager \
  --version v0.6.0 \
  stable/cert-manager
```
## API

Create the namespace and inject the secrets:

```
$ kubectl create ns api
$ kubectl create -f misc/{ENV}-secrets.yaml
$ kubectl create secret generic wott-ca -n api --from-file=ca.crt=backend/files/cert-bundle.crt
$ k8sec set api-secrets --base64 datastoreKey=$(cat ~/Downloads/wott-prod-[...].json| base64 -w0)  -n api
```



Once the secrets are live, you can deploy the actual app using:

```
$ helm upgrade -i api api\
    --set image.tag="$GITHASH" \
    --set releaseTimeStamp="$(date +%s)"
```
