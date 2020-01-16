#!/bin/bash

set -e

echo "Waiting for FusionAuth"
curl -sS -o /dev/null --retry 10 --retry-connrefused http://fusionauth:9011

echo "Configuring FusionAuth"
$(dirname $BASH_SOURCE)/configure.sh

echo "Running npm test"
npm test

echo "Stopping test server"
kill -INT $(cat app.pid)

echo "Generating coverage report"
./node_modules/.bin/nyc report --check-coverage
