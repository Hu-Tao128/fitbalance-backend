# syntax = docker/dockerfile:1

# Adjust NODE_VERSION as desired
ARG NODE_VERSION=20.18.0
FROM node:${NODE_VERSION}-slim AS base

LABEL fly_launch_runtime="Node.js"

# Node.js app lives here
WORKDIR /app

# Set production environment
ENV NODE_ENV="production"


# Throw-away build stage to reduce size of final image
FROM base AS build

# Build needs devDependencies (typescript, ts-node-dev, etc.)
ENV NODE_ENV="development"

# Install packages needed to build node modules
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential node-gyp pkg-config python-is-python3

# Install all dependencies (including dev for TypeScript)
COPY package.json package-lock.json ./
RUN npm ci

# Copy application code
COPY . .

# Build application
RUN npm run build


# Final stage for app image
FROM base

# Copy only what runtime needs
COPY --from=build /app/package.json /app/package-lock.json /app/
COPY --from=build /app/node_modules /app/node_modules
RUN npm prune --omit=dev
COPY --from=build /app/dist /app/dist

# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD [ "npm", "start" ]
