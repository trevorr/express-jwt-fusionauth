#!/bin/bash

set -e

docker-compose up --build -d
rm -rf coverage test-results

saveResults() {
  docker cp express-jwt-fusionauth_app:/home/node/app/coverage coverage
  docker cp express-jwt-fusionauth_app:/home/node/app/test-results test-results
}

trap saveResults EXIT
docker exec -t express-jwt-fusionauth_app ./scripts/run.sh
