ARG NODE_VERSION=12.7.0

FROM node:${NODE_VERSION}-alpine

USER node
RUN mkdir /home/node/app /home/node/app/src /home/node/app/test
WORKDIR /home/node/app

COPY --chown=node:node package*.json ./
RUN npm install

COPY --chown=node:node tsconfig.json ./
COPY --chown=node:node src ./src/
COPY --chown=node:node test ./test/
CMD ["./node_modules/.bin/ts-node", "test/app.ts"]
