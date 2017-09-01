#!/bin/sh

LIBTOOLIZE=`which glibtoolize 2>/dev/null`
case "$LIBTOOLIZE" in
	/* )	;;
	*  )	LIBTOOLIZE=`which libtoolize 2>/dev/null`
		case "$LIBTOOLIZE" in
			/* )	;;
			*  )	LIBTOOLIZE=libtoolize
				;;
		esac
		;;
esac

# aclocal uses -I ./m4 to overlay our AC_PYTHON_DEVEL macro.
$LIBTOOLIZE --force &&
aclocal -I ./m4 &&
automake -a &&
autoconf

