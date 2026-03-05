FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y curl iproute2 procps && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 8080

CMD ["node", "server.js"]
