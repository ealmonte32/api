#!/bin/bash

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

GITBRANCH=$(git rev-parse --abbrev-ref HEAD)
GITHASH="git-$(git rev-parse --short HEAD)"

docker build . -t wott-api

docker tag wott-api gcr.io/wott-prod/wott-api:${GITHASH}
docker tag wott-api gcr.io/wott-prod/wott-api:latest
docker push gcr.io/wott-prod/wott-api:${GITHASH}
docker push gcr.io/wott-prod/wott-api:latest
