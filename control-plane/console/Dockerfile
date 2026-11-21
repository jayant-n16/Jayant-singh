# OPLIA console image: static single-page app served by nginx (Red Hat UBI 9), non-root (UID 1001),
# works with a read-only root filesystem (writes only to /tmp). Configure with OPLIA_CONSOLE_*
# environment variables (see container/start.sh). Pin both base images by digest in your pipeline.
FROM registry.access.redhat.com/ubi9/nodejs-22 AS build
WORKDIR /opt/app-root/src
COPY --chown=1001:0 package.json package-lock.json ./
RUN npx -y npm@11.21.1 ci --no-fund --no-audit
COPY --chown=1001:0 tsconfig.json vite.config.ts index.html ./
COPY --chown=1001:0 public ./public
COPY --chown=1001:0 src ./src
# the runtime /config.json is generated at start-up; drop the development copy
RUN npx vite build && rm -f dist/config.json

FROM registry.access.redhat.com/ubi9/nginx-124
USER 0
COPY container/nginx.conf /etc/oplia-console/nginx.conf
COPY container/start.sh /usr/local/bin/oplia-console-start
COPY --from=build /opt/app-root/src/dist /opt/oplia-console/html
RUN chmod 0755 /usr/local/bin/oplia-console-start \
 && chmod -R a+rX /etc/oplia-console /opt/oplia-console
USER 1001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/oplia-console-start"]
