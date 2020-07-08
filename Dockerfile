ARG NODE_VERSION=12.18.2

FROM node:${NODE_VERSION}

RUN apt-get update && apt-get -y install jq

USER node
RUN mkdir /home/node/app /home/node/app/src /home/node/app/test
WORKDIR /home/node/app

COPY --chown=node:node package*.json ./
COPY --chown=node:node tsconfig.json ./
COPY --chown=node:node src ./src/
COPY --chown=node:node jsdoc2md ./jsdoc2md/
RUN npm install

COPY --chown=node:node scripts ./scripts/
COPY --chown=node:node test ./test/
COPY --chown=node:node .mocha* ./
COPY --chown=node:node .nyc* ./
CMD ["./scripts/start.sh"]
