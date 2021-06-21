#!/bin/bash

set -e

docker compose down -v
rm -rf $(dirname $BASH_SOURCE)/../tmp
