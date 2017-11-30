#!/bin/sh
# kFreeBSD do not accept scripts as interpreters, using #!/bin/sh and sourcing.
### BEGIN INIT INFO
# Provides:          uplusware
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: bwgated control script
# Description:       This file is copied from /etc/init.d/skeleton
### END INIT INFO
# Author: uplusware.org <uplusware@gmail.com>
#
DESC="bwgated control script"
DAEMON=/usr/bin/bwgated

test -x /usr/bin/bwgated || exit 0

SELF=$(cd $(dirname $0); pwd -P)/$(basename $0)

cd /
umask 0

bwgated_start()
{
	/usr/bin/bwgated start
}

bwgated_stop()
{
	/usr/bin/bwgated stop
}

bwgated_status()
{
	/usr/bin/bwgated status
}

bwgated_reload()
{
	/usr/bin/bwgated reload
}

bwgated_access()
{
	/usr/bin/bwgated access
}

bwgated_reject()
{
	/usr/bin/bwgated reject $1
}

bwgated_extension()
{
	/usr/bin/bwgated extension
}

bwgated_version()
{
	/usr/bin/bwgated version
}

bwgated_restart()
{
	bwgated_stop
    sleep 1
	bwgated_start
}

case "${1:-''}" in
	'start')
	bwgated_start
	;;
	
	'stop')
	bwgated_stop
	;;
	
	'restart')
	bwgated_restart
	;;
	
	'reload')
	bwgated_reload
	;;
	
	'access')
	bwgated_access
	;;

	'reject')
	bwgated_reject $2
	;;

    'extension')
	bwgated_extension
	;;

	'status')
	bwgated_status
	;;
	
	'version')
	bwgated_version
	;;
	
	*)
	echo "Usage: $SELF Usage:bwgated start | stop | status | reload | access | reject [ip] | extension | version"
	exit 1
	;;
esac

