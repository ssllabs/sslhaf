dnl Check for HTTPD Headers
dnl CHECK_HTTPD()
dnl Sets:
dnl  HTTPD_CPPFLAGS

HTTPD_CONFIG=""
HTTPD_CPPFLAGS=""

AC_DEFUN([CHECK_HTTPD],
[

AC_ARG_WITH(
    apxs,
    [AC_HELP_STRING(
        [--with-apxs=EXEC],[Location of apxs])],
        [HTTPD_CONFIG="${with_apxs}"],
        [HTTPD_CONFIG="/usr/sbin/apxs"])

AC_MSG_CHECKING([for httpd apxs config script])

if test -x "${HTTPD_CONFIG}"; then
    HTTPD_CPPFLAGS="-I`${HTTPD_CONFIG} -q INCLUDEDIR`"
else
    AC_MSG_ERROR([httpd headers are required but not found])
fi

AC_SUBST(HTTPD_CPPFLAGS)

AC_MSG_RESULT([yes])
])
