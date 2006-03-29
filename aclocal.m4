dnl
dnl $Id: aclocal.m4,v 1.5 2006/03/29 10:32:36 raven Exp $
dnl
dnl --------------------------------------------------------------------------
dnl AF_PATH_INCLUDE:
dnl
dnl Like AC_PATH_PROGS, but add to the .h file as well
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_PATH_INCLUDE,
[AC_PATH_PROGS($1,$2,$3,$4)
if test -n "$$1"; then
  AC_DEFINE(HAVE_$1,1,[define if you have $1])
  AC_DEFINE_UNQUOTED(PATH_$1, "$$1", [define if you have $1])
  HAVE_$1=1
else
  HAVE_$1=0
fi
AC_SUBST(HAVE_$1)])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_PROG:
dnl
dnl Like AC_CHECK_PROG, but fail configure if not found
dnl and only define PATH_<name> variable
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CHECK_PROG,
[AC_PATH_PROGS($1,$2,$3,$4)
if test -n "$$1"; then
  AC_DEFINE_UNQUOTED(PATH_$1, "$$1", [define if you have $1])
  PATH_$1="$$1"
else
  AC_MSG_ERROR([required program $1 not found])
fi
AC_SUBST(PATH_$1)])

dnl --------------------------------------------------------------------------
dnl AF_SLOPPY_MOUNT
dnl
dnl Check to see if mount(8) supports the sloppy (-s) option, and define
dnl the cpp variable HAVE_SLOPPY_MOUNT if so.  This requires that MOUNT is
dnl already defined by a call to AF_PATH_INCLUDE or AC_PATH_PROGS.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_SLOPPY_MOUNT,
[if test -n "$MOUNT" ; then
  AC_MSG_CHECKING([if mount accepts the -s option])
  if "$MOUNT" -s > /dev/null 2>&1 ; then
    AC_DEFINE(HAVE_SLOPPY_MOUNT, 1, [define if the mount command supports the -s option])
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
fi])

dnl --------------------------------------------------------------------------
dnl AF_INIT_D
dnl
dnl Check the location of the init.d directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_INIT_D,
[if test -z "$initdir"; then
  AC_MSG_CHECKING([location of the init.d directory])
  for init_d in /etc/init.d /etc/rc.d/init.d; do
    if test -z "$initdir"; then
      if test -d "$init_d"; then
	initdir="$init_d"
	AC_MSG_RESULT($initdir)
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_CONF_D
dnl
dnl Check the location of the configuration defaults directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CONF_D,
[if test -z "$confdir"; then
  AC_MSG_CHECKING([location of the configuration defaults directory])
  for conf_d in /etc/sysconfig /etc/defaults /etc/conf.d; do
    if test -z "$confdir"; then
      if test -d "$conf_d"; then
	confdir="$conf_d"
	AC_MSG_RESULT($confdir)
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_MAP_D
dnl
dnl Check the location of the autofs maps directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_MAP_D,
[if test -z "$mapdir"; then
  AC_MSG_CHECKING([location of the autofs maps directory])
  for map_d in /etc/autofs /etc; do
    if test -z "$mapdir"; then
      if test -d "$map_d"; then
	mapdir="$map_d"
	AC_MSG_RESULT($mapdir)
      fi
    fi
  done
fi])

dnl ----------------------------------- ##                   -*- Autoconf -*-
dnl Check if --with-dmalloc was given.  ##
dnl From Franc,ois Pinard               ##
dnl ----------------------------------- ##
dnl
dnl Copyright (C) 1996, 1998, 1999, 2000, 2001, 2002, 2003, 2005
dnl Free Software Foundation, Inc.
dnl
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl serial 3

AC_DEFUN([AM_WITH_DMALLOC],
[AC_MSG_CHECKING([if malloc debugging is wanted])
AC_ARG_WITH(dmalloc,
[  --with-dmalloc          use dmalloc, as in
			  http://www.dmalloc.com/dmalloc.tar.gz],
[if test "$withval" = yes; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(WITH_DMALLOC,1,
	    [Define if using the dmalloc debugging malloc package])
  DMALLOCLIB="-ldmallocth"
  LDFLAGS="$LDFLAGS -g"
else
  AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)])
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_LIBXML
dnl
dnl Check for lib xml
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_LIBXML],
[AC_PATH_PROGS(XML_CONFIG, xml2-config, no)
AC_MSG_CHECKING(for libxml2)
if test "$XML_CONFIG" = "no"
then
  AC_MSG_RESULT(no)
  HAVE_LIBXML=0
else
  AC_MSG_RESULT(yes)
  HAVE_LIBXML=1
  XML_LIBS=`$XML_CONFIG --libs`
  XML_FLAGS=`$XML_CONFIG --cflags`
fi])

