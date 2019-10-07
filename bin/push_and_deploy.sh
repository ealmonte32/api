#!/bin/bash

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

GITBRANCH=$(git rev-parse --abbrev-ref HEAD)
GITHASH="git-$(git rev-parse --short HEAD)"

docker-compose build

docker tag wott-api gcr.io/wott-prod/wott-api:${GITHASH}
docker tag wott-api gcr.io/wott-prod/wott-api:latest
docker tag wott-static gcr.io/wott-prod/wott-static:${GITHASH}
docker tag wott-static gcr.io/wott-prod/wott-static:latest

docker push gcr.io/wott-prod/wott-api:${GITHASH}
docker push gcr.io/wott-prod/wott-api:latest
docker push gcr.io/wott-prod/wott-static:${GITHASH}
docker push gcr.io/wott-prod/wott-static:latest

helm upgrade \
    -i api helm/api \
    --set image.tag=${GITHASH} \
    --set releaseTimeStamp="$(date +%s)"
