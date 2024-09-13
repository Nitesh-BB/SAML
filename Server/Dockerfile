FROM node:20-alpine

WORKDIR /app

COPY package.json .

COPY yarn.lock .

RUN apk update
RUN apk fetch openjdk8
RUN apk add openjdk8
ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk
ENV PATH="$JAVA_HOME/bin:${PATH}"

RUN java -version
RUN javac -version

RUN yarn add rimraf

RUN yarn install --immutable --immutable-cache --check-cache

COPY . .

RUN yarn build


CMD ["node", "dist/main.js"]

