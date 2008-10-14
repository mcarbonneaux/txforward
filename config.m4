dnl $Id$
dnl config.m4 for extension txforward

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(txforward, for txforward support,
dnl Make sure that the comment is aligned:
dnl [  --with-txforward             Include txforward support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(txforward, whether to enable txforward support,
dnl Make sure that the comment is aligned:
[  --enable-txforward           Enable txforward support], no)

if test "$PHP_TXFORWARD" != "no"; then
  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $TXFORWARD_DIR/lib, TXFORWARD_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_TXFORWARDLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong txforward lib version or lib not found])
  dnl ],[
  dnl   -L$TXFORWARD_DIR/lib -lm -ldl
  dnl ])
  dnl
  dnl PHP_SUBST(TXFORWARD_SHARED_LIBADD)

  PHP_NEW_EXTENSION(txforward, txforward.c, $ext_shared)
fi
