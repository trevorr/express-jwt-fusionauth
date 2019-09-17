#!/bin/bash

set -e

docker-compose up --build -d
docker exec -t express-jwt-fusionauth_app ./scripts/configure-and-test.sh
