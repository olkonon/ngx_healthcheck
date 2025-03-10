#!/bin/bash -x

DIR="$(pwd)"

NGINX_VERSION="1.27.3"


mkdir -p build/

wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
ls -la

tar -xzf nginx-${NGINX_VERSION}.tar.gz
mv nginx-${NGINX_VERSION}/* build/
mkdir build/modules/ngx_healthcheck/
mv src  build/modules/ngx_healthcheck/
mv config  build/modules/ngx_healthcheck/
cd build/
ls -la ./
ls -la ./modules/
ls -la ./modules/ngx_healthcheck/
./conifure --with-pcre --with-http_ssl_module --add-module=./modules/ngx_healthcheck/
make -j8