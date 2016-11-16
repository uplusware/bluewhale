#!/bin/bash
#
#	Copyright (c) openheap, uplusware
#	uplusware@gmail.com
#
if [ `id -u` -ne 0 ]; then
        echo "You need root privileges to run this script"
        exit 1
fi

#
# install the bwgated System
#

if uname -o | grep -i cygwin;
then
	test -x /usr/bin/bwgated && /usr/bin/bwgated stop
else
	test -x /etc/init.d/bwgated && /etc/init.d/bwgated stop
fi
sleep 3
killall bwgated >/dev/null 2>&1
sleep 1

path=$(dirname $0)
oldpwd=$(pwd)
cd ${path}
path=$(pwd)

echo "Copy the files to your system."


test -x /tmp/bwgated || mkdir /tmp/bwgated
test -x /etc/bwgated || mkdir /etc/bwgated
test -x /var/bwgated || mkdir /var/bwgated

test -x /etc/bwgated/bwgated.conf && mv /etc/bwgated/bwgated.conf /etc/bwgated/bwgated.conf.$((`date "+%Y%m%d%H%M%S"`))

cp -f ${path}/bwgated.conf /etc/bwgated/bwgated.conf
chmod 600 /etc/bwgated/bwgated.conf

test -x /etc/bwgated/permit.list || cp -f ${path}/permit.list /etc/bwgated/permit.list
chmod a-x /etc/bwgated/permit.list

test -x /etc/bwgated/reject.list || cp -f ${path}/reject.list /etc/bwgated/reject.list
chmod a-x /etc/bwgated/reject.list

test -x /etc/bwgated/services.xml || cp -f ${path}/services.xml /etc/bwgated/services.xml
chmod a-x /etc/bwgated/services.xml

test -x /etc/bwgated/backends.xml || cp -f ${path}/backends.xml /etc/bwgated/backends.xml
chmod a-x /etc/bwgated/backends.xml


cp -f ${path}/bwgated /usr/bin/bwgated
chmod a+x /usr/bin/bwgated

if uname -o | grep -i cygwin;
then
    echo "cygwin!"
else
  	cp -f ${path}/bwgated.sh  /etc/init.d/bwgated
	chmod a+x /etc/init.d/bwgated
fi

cp -f ${path}/uninstall.sh   /var/bwgated/uninstall.sh
chmod a-x  /var/bwgated/uninstall.sh

if uname -o | grep -i cygwin;
then
	echo "cygwin!"
else
	ln -s /etc/init.d/bwgated /etc/rc0.d/K60bwgated 2> /dev/null
	ln -s /etc/init.d/bwgated /etc/rc1.d/S60bwgated 2> /dev/null
	ln -s /etc/init.d/bwgated /etc/rc2.d/S60bwgated 2> /dev/null
	ln -s /etc/init.d/bwgated /etc/rc3.d/S60bwgated 2> /dev/null
	ln -s /etc/init.d/bwgated /etc/rc4.d/S60bwgated 2> /dev/null
	ln -s /etc/init.d/bwgated /etc/rc5.d/S60bwgated 2> /dev/null
	ln -s /etc/init.d/bwgated /etc/rc6.d/K60bwgated 2> /dev/null
fi
echo "Done."
echo "Please reference the document named INSTALL to go ahead."
cd ${oldpwd}
