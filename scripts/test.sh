#!/bin/bash

set -e

docker-compose up --build -d
docker exec -t express-jwt-fusionauth_app ./scripts/run.sh
rm -rf coverage test-results
docker cp express-jwt-fusionauth_app:/home/node/app/coverage coverage
docker cp express-jwt-fusionauth_app:/home/node/app/test-results test-results
