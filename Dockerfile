# Production Dockerfile for VulnSight Security Platform
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package manifests
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy application source code
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY docs/ ./docs/

# Create persistent reports directory
RUN mkdir -p /app/reports

# Expose HTTP port
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Start server
CMD ["node", "backend/server.js"]
