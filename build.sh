#!/bin/bash

gomobile bind -v -androidapi 21 -trimpath -buildvcs=false -ldflags='-s -w -buildid=' . || exit 1
rm -r libcore-sources.jar

proj=../../app/libs
if [ -d $proj ]; then
  cp -f libcore.aar $proj
  echo ">> install $(realpath $proj)/libcore.aar"
fi
