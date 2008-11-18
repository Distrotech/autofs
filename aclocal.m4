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
dnl AF_LINUX_PROCFS
dnl
dnl Check for the Linux /proc filesystem
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_LINUX_PROCFS,
[AC_MSG_CHECKING(for Linux proc filesystem)
if test "x`cat /proc/sys/kernel/ostype 2>&-`" = "xLinux"
then
	linux_procfs=yes
else
	linux_procfs=no
fi
AC_MSG_RESULT($linux_procfs)
if test $linux_procfs = yes
then
	AC_DEFINE(HAVE_LINUX_PROCFS, 1,
		[Define if you have the Linux /proc filesystem.])
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
  for conf_d in /etc/sysconfig /etc/defaults /etc/conf.d /etc/default; do
    if test -z "$confdir"; then
      if test -d "$conf_d"; then
	confdir="$conf_d"
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
  for map_d in /etc/autofs /etc; do
    if test -z "$mapdir"; then
      if test -d "$map_d"; then
	mapdir="$map_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_FIFO_D
dnl
dnl Check the location of the autofs fifos directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_FIFO_D,
[if test -z "$fifodir"; then
  for fifo_d in /var/run /tmp; do
    if test -z "$fifodir"; then
      if test -d "$fifo_d"; then
        fifodir="$fifo_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_FLAG_D
dnl
dnl Check the location of the autofs flag file directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_FLAG_D,
[if test -z "$flagdir"; then
  for flag_d in /var/run /tmp; do
    if test -z "$flagdir"; then
      if test -d "$flag_d"; then
        flagdir="$flag_d"
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
  XML_VER=`$XML_CONFIG --version`
  XML_MAJOR=`echo $XML_VER|cut -d\. -f1`
  if test $XML_MAJOR -le 99
  then
    XML_MINOR=`echo $XML_VER|cut -d\. -f2`
    if test $XML_MINOR -le 99
    then
      XML_REV=`echo $XML_VER|cut -d\. -f3`
      if test $XML_REV -le 99; then
        AC_DEFINE(LIBXML2_WORKAROUND,1, [Use libxml2 tsd usage workaround])
      fi
    fi
  fi
fi])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_LIBHESIOD
dnl
dnl Check for lib hesiod
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_LIBHESIOD],
[AC_MSG_CHECKING(for libhesiod)

# save current ldflags
af_check_hesiod_save_ldflags="$LDFLAGS"
LDFLAGS="$LDFLAGS -lhesiod -lresolv"

AC_TRY_LINK(
  [ #include <hesiod.h> ],
  [ char *c; hesiod_init(&c); ],
  [ HAVE_HESIOD=1
    LIBHESIOD="$LIBHESIOD -lhesiod -lresolv"
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

# restore ldflags
LDFLAGS="$af_check_hesiod_save_ldflags"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL
dnl
dnl Check for function ldap_create_page_control
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL],
[AC_MSG_CHECKING(for ldap_create_page_control in -lldap)

# save current ldflags
af_check_ldap_create_page_control_save_ldflags="$LDFLAGS"
LDFLAGS="$LDFLAGS -lldap"

AC_TRY_LINK(
  [ #include <ldap.h> ],
  [ LDAP *ld;
    ber_int_t ps;
    struct berval *c;
    int ic, ret;
    LDAPControl **clp;
    ret = ldap_create_page_control(ld,ps,c,ic,clp); ],
  [ af_have_ldap_create_page_control=yes
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

if test "$af_have_ldap_create_page_control" = "yes"; then
  AC_DEFINE(HAVE_LDAP_CREATE_PAGE_CONTROL, 1,
        [Define to 1 if you have the `ldap_create_page_control' function.])
fi

# restore ldflags
LDFLAGS="$af_check_ldap_create_page_control_save_ldflags"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL
dnl
dnl Check for function ldap_parse_page_control
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL],
[AC_MSG_CHECKING(for ldap_parse_page_control in -lldap)

# save current ldflags
af_check_ldap_parse_page_control_save_ldflags="$LDFLAGS"
LDFLAGS="$LDFLAGS -lldap"

AC_TRY_LINK(
  [ #include <ldap.h> ],
  [ LDAP *ld;
    ber_int_t ct;
    struct berval *c;
    int ret;
    LDAPControl **clp;
    ret = ldap_parse_page_control(ld,clp,ct,c); ],
  [ af_have_ldap_parse_page_control=yes
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

if test "$af_have_ldap_create_page_control" = "yes"; then
  AC_DEFINE(HAVE_LDAP_PARSE_PAGE_CONTROL, 1,
        [Define to 1 if you have the `ldap_parse_page_control' function.])
fi

# restore ldflags
LDFLAGS="$af_check_ldap_parse_page_control_save_ldflags"
])

