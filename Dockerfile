# Dockerfile for MindStep app: Node + OpenJDK 17 + Python 3
FROM node:18-bullseye

# Install OpenJDK 17 AND Python 3
RUN apt-get update \
  && apt-get install -y openjdk-17-jdk-headless python3 ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy package files first for caching
COPY package*.json ./

# Install dependencies
# NOTE: Use 'npm install' if package-lock.json might be missing
RUN npm install --production

# Copy app
COPY . .

# Ensure temp directory exists
RUN mkdir -p /usr/src/app/temp

# Set JAVA_HOME
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Expose port
EXPOSE 10000

# Start the app
CMD ["node", "server.js"]

# Docker healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD curl -f http://localhost:10000/health || exit 1