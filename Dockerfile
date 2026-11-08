# Members app (app/server.mjs). Plain Node, no dependencies.
FROM node:22.21-alpine
WORKDIR /srv
COPY app ./app
COPY members ./members
COPY fonts ./fonts
COPY brand ./brand
ENV PORT=8080
EXPOSE 8080
USER node
CMD ["node", "app/server.mjs"]
