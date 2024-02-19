#!/bin/bash

set -e

echo "Waiting for FusionAuth"
curl -sS -o /dev/null --retry 10 --retry-connrefused -H "Authorization: ${FUSIONAUTH_API_KEY}" "${FUSIONAUTH_URL}/api/user/${FUSIONAUTH_ADMIN_USER_ID}"

echo "Waiting for test server"
curl -sS -o /dev/null --retry 10 --retry-connrefused http://app:3000

echo "Giving FusionAuth a little more time to finish startup"
sleep 10

echo "Running npm test"
npm test || true

echo "Stopping test server"
kill -INT $(cat app.pid)

echo "Generating coverage report"
./node_modules/.bin/nyc report --check-coverage
