# Members app (app/server.mjs). Plain Node, no dependencies.
FROM node:22.21-alpine
WORKDIR /srv
COPY app ./app
COPY members ./members
COPY fonts ./fonts
COPY brand ./brand
ENV PORT=8080
EXPOSE 8080
# Starts as root only to hand the /data volume (bookings.json) to the node user, then runs as node.
CMD ["sh", "-c", "mkdir -p /data && chown node:node /data && exec su node -s /bin/sh -c 'exec node app/server.mjs'"]
