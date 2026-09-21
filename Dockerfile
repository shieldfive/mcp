# For directory inspection (Glama and similar): runs the server on stdio with
# one empty root, so the local tools and vault_connect can be listed. Real use
# is `npx -y @shieldfive/mcp <folders>` on your own machine; a container cannot
# reach your files or your keychain.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY src ./src
RUN mkdir -p /data
USER node
ENTRYPOINT ["node", "src/server.mjs", "/data"]
