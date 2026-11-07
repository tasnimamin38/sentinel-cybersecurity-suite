FROM node:25-alpine AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:1.30.6-alpine
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
RUN nginx -t
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
USER 101:101
