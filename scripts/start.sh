#!/bin/bash

while true; do
  echo "Starting test server"
  ./node_modules/.bin/nyc --silent --no-clean ./node_modules/.bin/ts-node test/app.ts &
  PID=$!
  echo "$PID" > app.pid
  wait "$PID"
done
