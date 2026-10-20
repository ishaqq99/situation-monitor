# Stage 1 compiles React/Vite. VITE_* values are public compile-time settings,
# never put a password, API key, or tunnel token in them.
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html ./
COPY public ./public
COPY src ./src
COPY tsconfig*.json vite.config.ts ./
ARG VITE_PUBLIC_DEMO=true
ARG VITE_API_BASE_URL=
ENV VITE_PUBLIC_DEMO=${VITE_PUBLIC_DEMO} \
    VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

# Stage 2 serves only the compiled static files, not Node or source files.
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
