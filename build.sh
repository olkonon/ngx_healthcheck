#!/bin/bash -x

DIR="$(pwd)"

NGINX_VERSION="1.27.3"

echo "Directory: $DIR"


mkdir -p $DIR/buildnginx/modules/ngx_healthcheck/

wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf nginx-${NGINX_VERSION}.tar.gz
mv nginx-${NGINX_VERSION}/* $DIR/buildnginx/
mv src  $DIR/buildnginx/modules/ngx_healthcheck/
mv config  $DIR/buildnginx/modules/ngx_healthcheck/
cd $DIR/buildnginx
ls -la ./
ls -la ./modules/
ls -la ./modules/ngx_healthcheck/
./conifure --with-pcre --with-http_ssl_module --add-module=./modules/ngx_healthcheck/
make -j8