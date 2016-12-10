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

chmod a+x $3-bluewhale-bin-$2-${m}-${o}/*
tar zcf $3-bluewhale-bin-$2-${m}-${o}-$1.tar.gz $3-bluewhale-bin-$2-${m}-${o}
cd ${oldpwd}
