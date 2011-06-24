#!/bin/sh

tarball=$1
if [ -z "$1" ] || [ ! -f $tarball ]; then
  echo "$0 <tarball>"
  exit
fi

# get absolute path of file if possible
if [ ! -z `which realpath` ]; then
  tarball=`realpath $tarball`
else
  echo "Warning: realpath not available - provide absolute path to tarball"
fi

version=`echo $tarball | sed -e 's/\.tar\.gz//'`

curr_dir=`pwd`
mkdir tmp.$$
cd tmp.$$
tar zxvf $tarball
dh-make-perl $version/
cd $version/
debuild
cd $curr_dir
/bin/echo -e "\n\n\n##########\n# Found debian packages:"
ls *.deb
/bin/echo -e "\n# Cleanup build directory with: rm -r tmp.$$\n##########"
