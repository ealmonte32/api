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

## Redis

For Redis, we use Google MemoryStore, which is a hosted Redis. This needs to be manually created.

If the cluster was created using legacy networking (i.e. without IP Alias), the [following steps](https://cloud.google.com/memorystore/docs/redis/connect-redis-instance-gke) need to be taken:

## Prometheus
```
helm upgrade \
       -i prom0 \
        stable/prometheus \
        --set "server.persistentVolume.size=20Gi" \
        --namespace="prom"
```

### Get the reserved IP range:

```
$ gcloud beta \
    --project=wott-(prod|stage) \
    redis instances describe redis0 \
    --region=us-central1 | grep reservedIpRange
```

### Setting up NAT'ing

```
$ git clone https://github.com/bowei/k8s-custom-iptables.git
$ cd k8s-custom-iptables/
$ TARGETS="RESERVED_IP_RANGE" ./install.sh
```


## Nginx

```
$ kubectl create ns nginx
$ helm install \
    stable/nginx-ingress \
    --name nginx0  \
    --namespace=nginx
    -f nginx-values.yaml
```

## Cert-manager

CertManager is used to facilitate Let's Encrypt certificate management. The installation instructions can be found [here](https://docs.cert-manager.io/en/latest/getting-started/install/kubernetes.html), but in short, here's what we need to do to install it:

```
# Install the CustomResourceDefinition resources separately
kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.10/deploy/manifests/00-crds.yaml

# Create the namespace for cert-manager
kubectl create namespace cert-manager

# Label the cert-manager namespace to disable resource validation
kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

# Add the Jetstack Helm repository
helm repo add jetstack https://charts.jetstack.io

# Update your local Helm chart repository cache
helm repo update

# Install the cert-manager Helm chart
helm install \
  --name cert-manager \
  --namespace cert-manager \
  --version v0.10.0 \
  jetstack/cert-manager
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
