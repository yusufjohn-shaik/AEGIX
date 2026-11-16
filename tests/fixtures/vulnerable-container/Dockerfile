FROM node:latest
ENV API_KEY="SuperSecretKey123"
RUN curl -sSL https://get.docker.com | sh
ADD server.js /app/server.js
USER root
CMD ["node", "/app/server.js"]
