FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

FROM node:20-alpine AS production

WORKDIR /usr/src/app

ENV NODE_ENV production


COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/ ./

EXPOSE 3000

USER node

CMD ["node", "server.js"]
