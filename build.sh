#!/bin/bash -x

DIR="$(pwd)"

NGINX_VERSION="1.27.3"

wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
ls -la

tar -xvzf nginx-${NGINX_VERSION}.tar.gz -C build/
cd build/
ls -la ./
ls -la ./modules/