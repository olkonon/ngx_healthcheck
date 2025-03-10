#!/bin/bash -x

# Copyright, Aleksey Konovkin (alkon2000@mail.ru)
# BSD license type

download=0
if [ "$1" == "1" ]; then
  download=1
fi
build_deps=0

DIR="$(pwd)"

VERSION="1.27.3"
PCRE2_VERSION="10.37"
ZLIB_VERSION="1.2.11"

SUFFIX=""

BASE_PREFIX="$DIR/build"
INSTALL_PREFIX="$DIR/install"

export PCRE_SOURCES="$DIR/build/pcre2-$PCRE2_VERSION"
export ZLIB_SOURCES="$DIR/build/zlib-$ZLIB_VERSION"

EMBEDDED_OPTS="--with-pcre=$PCRE_SOURCES --with-zlib=$ZLIB_SOURCES"

function clean() {
  rm -rf install  2>/dev/null
  rm -rf $(ls -1d build/* 2>/dev/null | grep -v deps)    2>/dev/null
  if [ $download -eq 1 ]; then
    rm -rf download 2>/dev/null
  fi
}

if [ "$1" == "clean" ]; then
  clean
  exit 0
fi

function build_debug() {
  cd nginx-$VERSION$SUFFIX
  echo "Configuring debug nginx-$VERSION$SUFFIX"
  ./configure --prefix="$INSTALL_PREFIX/nginx-$VERSION$SUFFIX" \
              $EMBEDDED_OPTS \
              --with-stream \
              --with-debug \
              --with-cc-opt="-O0" \
              --add-module=../

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi

  echo "Build debug nginx-$VERSION$SUFFIX"
  make -j4 > /dev/null

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install > /dev/null

  mv "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/sbin/nginx" "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/sbin/nginx.debug"

  cd ..
}

function build_release() {
  cd nginx-$VERSION$SUFFIX
  echo "Configuring release nginx-$VERSION$SUFFIX"
  ./configure --prefix="$INSTALL_PREFIX/nginx-$VERSION$SUFFIX" \
              $EMBEDDED_OPTS \
              --with-stream \
              --add-module=../../../ngx_dynamic_healthcheck \
              --add-module=../

  download_dep http://zlib.net                                 zlib      $ZLIB_VERSION      tar.gz

  cd ..
}

function install_file() {
  echo "Install $1"
  if [ ! -e "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$2" ]; then
    mkdir -p "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$2"
  fi
  cp -r $3 $1 "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$2/"
}

function install_files() {
  for f in $(ls $1)
  do
    install_file $f $2 $3
  done
}

function build() {
  cd build

  make clean > /dev/null 2>&1
  build_debug

#  make clean > /dev/null 2>&1
#  build_release

  cd ..
}

clean
download
extract_downloads
build

install_file scripts/start.sh   .
install_file scripts/debug.sh   .
install_file scripts/restart.sh .
install_file scripts/stop.sh    .

cp LICENSE "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/LICENSE"

cd "$DIR"

kernel_name=$(uname -s)
kernel_version=$(uname -r)

cd install

tar zcvf nginx-$VERSION$SUFFIX-$kernel_name-$kernel_version.tar.gz nginx-$VERSION$SUFFIX
rm -rf nginx-$VERSION$SUFFIX

cd ..

exit $r
