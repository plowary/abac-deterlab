# ===========================================================================
#     ax_check_xml2.m4
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_XML2([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for xml2in a number of default spots, or in a user-selected
#   spot (via --with-xml2).  Sets
#
#     XML2_INCLUDES to the include directives required
#     XML2_LIBS to the -l directives required
#     XML2_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets XML2_INCLUDES such that source files should use the
#   libxml2/ directory in include directives:
#    ... <libxml/tree.h>
#
AU_ALIAS([CHECK_XML2], [AX_CHECK_XML2])
AC_DEFUN([AX_CHECK_XML2], [
    found=false
    AC_ARG_WITH([xml2],
        [AS_HELP_STRING([--with-xml2=DIR],
            [root of the XML2 directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-xml2 value])
              ;;
            *) xml2dirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and xmlsec1 has installed a .pc file,
            # then use that information and don't search ssldirs
            AC_PATH_PROG([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                XML2_LDFLAGS=`$PKG_CONFIG xml2 --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    XML2_LIBS=`$PKG_CONFIG xml2 --libs-only-l 2>/dev/null`
                    XML2_INCLUDES=`$PKG_CONFIG xml2 --cflags 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default ssldirs
            if ! $found; then
                xml2dirs="/usr/local /usr"
            fi
        ]
        )


    # XML2 headers have to be in libxml and xml2dir subdirectories
    # CFLAGS =-g -Wall `xmlsec1-config --cflags --crypto=default` `xml2-config --cflags`
    # LDFLAGS += `xml2-config --libs` `xmlsec1-config --libs --crypto=default` 

    if ! $found; then
        AC_PATH_PROG([XML2_CONFIG], [xml2-config])
        if test x"$XML2_CONFIG" != x""; then
            for xml2dir in $xml2dirs; do
                AC_MSG_CHECKING([for libxml/tree.h in $xml2dir])
                if test -f "$xml2dir/include/libxml2/libxml/tree.h"; then
                    XML2_INCLUDES=`$XML2_CONFIG --cflags 2>/dev/null` 
                    XML2_LDFLAGS=`$XML2_CONFIG --libs 2>/dev/null` 
                    XML2_LIBS=`$XML2_CONFIG --libs 2>/dev/null` 
                    found=true
                    AC_MSG_RESULT([yes])
                    break
                else
                    AC_MSG_RESULT([no])
                fi
            done
        else
            # cannot even find the xml2-config
            AC_MSG_ERROR([Cannot find xml2-config in your system path])
        fi

        # if the file wasn't found, well, go ahead and try the link anyway -- maybe
        # it will just work!
    fi

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against XML2 works])
    echo "Trying link with XML2_LDFLAGS=$XML2_LDFLAGS;" \
        "XML2_LIBS=$XML2_LIBS; XML2_INCLUDES=$XML2_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $XML2_LDFLAGS"
    LIBS="$XML2_LIBS $LIBS"
    CPPFLAGS="$XML2_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE( 
        [AC_LANG_PROGRAM([#include <libxml/tree.h>], [xmlMalloc(1)])],
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

    AC_SUBST([XML2_INCLUDES])
    AC_SUBST([XML2_LIBS])
    AC_SUBST([XML2_LDFLAGS])
])

