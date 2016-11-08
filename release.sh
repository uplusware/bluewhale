#!/bin/bash

if [ $# = 3 ]
then
	echo $1
else
	echo "release 0.1 rel-alias entos"
	exit 1	
fi

path=$(dirname $0)
oldpwd=$(pwd)
cd ${path}
path=$(pwd)

cd ${path}

#############################################################################
# Platform
m=`uname -m`
if uname -o | grep -i linux;
then
	o=linux
	cd src/
	make clean
    make
	cd ..
elif uname -o | grep -i solaris;
then
	o=solaris-`isainfo -b`bit
	cd src/
	gmake clean
	gmake SOLARIS=1
	cd ..
elif uname -o | grep -i freebsd;
then
	o=freebsd
	cd src/
	make clean
	make FREEBSD=1
	cd ..
elif uname -o | grep -i cygwin;
then
	o=cygwin
	cd src/
	make clean
	make CYGWIN=1
	cd ..
fi


rm -rf $3-bluewhale-bin-$2-${m}-${o}
mkdir $3-bluewhale-bin-$2-${m}-${o}

cp src/bwgated $3-bluewhale-bin-$2-${m}-${o}/bwgated

cp script/install.sh $3-bluewhale-bin-$2-${m}-${o}/
cp script/uninstall.sh $3-bluewhale-bin-$2-${m}-${o}/

cp script/bwgated.conf $3-bluewhale-bin-$2-${m}-${o}/bwgated.conf
cp script/permit.list $3-bluewhale-bin-$2-${m}-${o}/
cp script/reject.list $3-bluewhale-bin-$2-${m}-${o}/
cp script/services.xml $3-bluewhale-bin-$2-${m}-${o}/
cp script/backends.xml $3-bluewhale-bin-$2-${m}-${o}/

cp script/bwgated.sh $3-bluewhale-bin-$2-${m}-${o}/

cp ca/ca.crt $3-bluewhale-bin-$2-${m}-${o}/ca.crt

cp ca/server.p12 $3-bluewhale-bin-$2-${m}-${o}/server.p12
cp ca/server.crt $3-bluewhale-bin-$2-${m}-${o}/server.crt
cp ca/server.key $3-bluewhale-bin-$2-${m}-${o}/server.key

cp ca/client.p12 $3-bluewhale-bin-$2-${m}-${o}/client.p12
cp ca/client.crt $3-bluewhale-bin-$2-${m}-${o}/client.crt
cp ca/client.key $3-bluewhale-bin-$2-${m}-${o}/client.key

chmod a+x $3-bluewhale-bin-$2-${m}-${o}/*
tar zcf $3-bluewhale-bin-$2-${m}-${o}-$1.tar.gz $3-bluewhale-bin-$2-${m}-${o}
cd ${oldpwd}
