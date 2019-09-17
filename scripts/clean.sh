#!/bin/bash

set -e

docker-compose down
docker volume prune -f
rm -rf $(dirname $BASH_SOURCE)/../tmp
