# ===========================================================================
#     ax_check_xmlsec1.m4
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_XMLSEC1([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for xmlsec1 in a number of default spots, or in a user-selected
#   spot (via --with-xmlsec1).  Sets
#
#     XMLSEC1_INCLUDES to the include directives required
#     XMLSEC1_LIBS to the -l directives required
#     XMLSEC1_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets XMLSEC1_INCLUDES such that source files should use the
#   xml/ directory in include directives:
#    ... <xmlsec/xmlsec.h>
#
#
AU_ALIAS([CHECK_XMLSEC1], [AX_CHECK_XMLSEC1])
AC_DEFUN([AX_CHECK_XMLSEC1], [
    found=false
    AC_ARG_WITH([xmlsec1],
        [AS_HELP_STRING([--with-xmlsec1=DIR],
            [root of the XMLSEC1 directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-xmlsec1 value])
              ;;
            *) xmlsec1dirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and xmlsec1 has installed a .pc file,
            # then use that information and don't search ssldirs
            AC_PATH_PROG([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                XMLSEC1_LDFLAGS=`$PKG_CONFIG xmlsec1 --libs --define-variable=crypto-default 2>/dev/null`
                if test $? = 0; then
                    XMLSEC1_LIBS=`$PKG_CONFIG xmlsec1 --libs --define-variable=crypto=default  2>/dev/null`
                    XMLSEC1_INCLUDES=`$PKG_CONFIG xmlsec1 --cflags --define-variable=crypto=default  2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default ssldirs
            if ! $found; then
                xmlsec1dirs="/usr/local /usr"
            fi
        ]
        )


    # XMLSEC1 headers have to be in libxml and xmlsec subdirectories
    # CFLAGS =-g -Wall `xmlsec1-config --cflags --crypto=default` `xml2-config --cflags`
    # LDFLAGS += `xml2-config --libs` `xmlsec1-config --libs --crypto=default` 

    if ! $found; then
        AC_PATH_PROG([XMLSEC1_CONFIG], [xmlsec1-config])
        if test x"$XMLSEC1_CONFIG" != x""; then
            for xmlsec1dir in $xmlsec1dirs; do
                AC_MSG_CHECKING([for xmlsec/xmlsec.h in $xmlsec1dir])
                if test -f "$xmlsec1dir/include/xmlsec1/xmlsec/xmlsec.h"; then
                    XMLSEC1_INCLUDES=`$XMLSEC1_CONFIG --cflags --crypto=default 2>/dev/null` 
                    XMLSEC1_LDFLAGS=`$XMLSEC1_CONFIG --libs --crypto=default 2>/dev/null` 
                    XMLSEC1_LIBS=`$XMLSEC1_CONFIG --libs --crypto=default 2>/dev/null` 
                    found=true
                    AC_MSG_RESULT([yes])
                    break;
                else
                    AC_MSG_RESULT([no])
                fi
            done
        else
            # cannot even find the xmlsec-config
            AC_MSG_ERROR([Cannot find xmlsec-config in your system path])
        fi

        # if the file wasn't found, well, go ahead and try the link anyway -- maybe
        # it will just work!
    fi

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against XMLSEC1 works])
    echo "Trying link with XMLSEC1_LDFLAGS=$XMLSEC1_LDFLAGS;" \
        "XMLSEC1_LIBS=$XMLSEC1_LIBS; XMLSEC1_INCLUDES=$XMLSEC1_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $XMLSEC1_LDFLAGS"
    LIBS="$XMLSEC1_LIBS $LIBS"
    CPPFLAGS="$XMLSEC1_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <xmlsec/xmlsec.h>], [xmlSecInit()])],
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([XMLSEC1_INCLUDES])
    AC_SUBST([XMLSEC1_LIBS])
    AC_SUBST([XMLSEC1_LDFLAGS])
])

