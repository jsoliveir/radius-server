FROM node:latest as base
WORKDIR /app
COPY package-lock.json .
COPY package.json .
COPY src/ src/

FROM base as restore
RUN npm install

FROM restore as final
ENV ENVIRONMENT=azure
ENTRYPOINT [ "npm" ]
CMD ["start"]