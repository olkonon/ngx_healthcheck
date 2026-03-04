#!/bin/bash

DIR="$(pwd)"

echo "Nginx version $NGINX_VERSION"
echo "Directory: $DIR"

mkdir -p $DIR/buildnginx/modules/ngx_healthcheck/
wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf nginx-${NGINX_VERSION}.tar.gz
mv nginx-${NGINX_VERSION}/* $DIR/buildnginx/
mv src  $DIR/buildnginx/modules/ngx_healthcheck/
mv config  $DIR/buildnginx/modules/ngx_healthcheck/
cd $DIR/buildnginx
./configure --with-debug --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security' --with-pcre --with-stream --with-http_ssl_module --add-module=./modules/ngx_healthcheck/
make -j12
