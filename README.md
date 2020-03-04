# WoTT Backend/API
[![CircleCI](https://circleci.com/gh/WoTTsecurity/api.svg?style=svg&circle-token=e0dc7fa4c2ca6e748dec621be90da21e0a4ef8a6)](https://circleci.com/gh/WoTTsecurity/api)

## Development server

On the first run, run:
```
$ docker network create wott
```

Then:
```
$ docker-compose build
$ docker-compose up
```

You should now have three servers up and running:

 * localhost:8000 - dashboard
 * localhost:8001 - api
 * localhost:8002 - mtls-api

## Tests

```
$ docker-compose -f ./docker-compose.tests.yml up
```
Testing PR logic
