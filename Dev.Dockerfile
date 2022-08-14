FROM node:12.21.0-alpine3.10 as builder
WORKDIR /usr/app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
# develop branch only
COPY .dev.env ./
RUN npm install --production

EXPOSE 3000
CMD node dist/main.js
