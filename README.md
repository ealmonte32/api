# WoTT Backend/API

[![CircleCI](https://circleci.com/gh/WoTTsecurity/api.svg?style=svg)](https://circleci.com/gh/WoTTsecurity/api)

## Development server

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
