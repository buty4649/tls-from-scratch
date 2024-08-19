FROM ubuntu:24.04 as mkcert

RUN <<COMMAND
    apt-get install -y -U mkcert
    mkcert example.test localhost 127.0.0.1
COMMAND

FROM nginx:1.27

COPY --from=mkcert /example.test+2-key.pem /etc/ssl/private/example.test+2-key.pem
COPY --from=mkcert /example.test+2.pem /etc/ssl/certs/example.test+2.pem
COPY ./nginx_default.conf /etc/nginx/conf.d/default.conf

EXPOSE 443
