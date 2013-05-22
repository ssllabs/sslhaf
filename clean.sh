#!/bin/sh

fullme=`readlink -f $0`

if [ -e .gitignore ]; then
  for f in `cat .gitignore`; do
    if [ -e $f ]; then
      rm -rf $f;
    fi
  done
fi


  for d in `ls -d -- */ 2>/dev/null`; do
    cd $d
    $fullme
    cd ../
  done
