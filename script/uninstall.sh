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
# uninstall the bwgated web server
#

echo "Sure to remove bwgated from you computer? [yes/no]"
read uack
if [ ${uack} = "yes" ]
then
	echo "Remove the bwgated...."
else
	exit 1
fi

/etc/init.d/bwgated stop

rm -rf /usr/bin/bwgated
rm -rf /etc/init.d/bwgated
rm -rf /etc/bwgated

rm -f /etc/rc0.d/K60bwgated
rm -f /etc/rc1.d/S60bwgated
rm -f /etc/rc2.d/S60bwgated
rm -f /etc/rc3.d/S60bwgated
rm -f /etc/rc4.d/S60bwgated
rm -f /etc/rc5.d/S60bwgated
rm -f /etc/rc6.d/K60bwgated

echo "Done"
