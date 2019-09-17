#!/bin/bash

set -e

docker-compose up --build -d

while ! curl --output /dev/null --silent --head --fail http://localhost:9011; do
  echo "Waiting for FusionAuth"
  sleep 1
done

$(dirname $BASH_SOURCE)/configure.sh

npm test
