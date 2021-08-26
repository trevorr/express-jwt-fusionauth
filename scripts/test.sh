#!/bin/bash

set -e

docker-compose up --build -d
rm -rf coverage test-results
docker exec -t express-jwt-fusionauth_app ./scripts/run.sh || true
docker cp express-jwt-fusionauth_app:/home/node/app/coverage coverage
docker cp express-jwt-fusionauth_app:/home/node/app/test-results test-results
