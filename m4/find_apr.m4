dnl Check for APR Libraries
dnl CHECK_APR()
dnl Sets:
dnl  APR_VERSION
dnl  APR_CFLAGS
dnl  APR_CPPFLAGS
dnl  APR_LDFLAGS
dnl  APR_LDADD

APR_CONFIG=""
APR_VERSION=""
APR_CFLAGS=""
APR_CPPFLAGS=""
APR_LDFLAGS=""
APR_LDADD=""

AC_DEFUN([CHECK_APR],
[

AC_ARG_WITH(
    apr,
    [AC_HELP_STRING(
        [--with-apr=PATH],[Path to apr prefix or config script])],
        [test_paths="${with_apr}"],
        [test_paths="/usr/local/libapr /usr/local/apr /usr/local /opt/libapr /opt/apr /opt /usr"])

AC_MSG_CHECKING([for libapr config script])

for x in ${test_paths}; do
    dnl # Determine if the script was specified and use it directly
    if test ! -d "$x" -a -e "$x"; then
        APR_CONFIG=$x
        apr_path=no
        break
    fi

    dnl # Try known config script names/locations
    for APR_CONFIG in apr-1-mt-config apr-1-config apr-config-1 apr-mt-config-1 apr-mt-config apr-config; do
        if test -e "${x}/bin/${APR_CONFIG}"; then
            apr_path="${x}/bin"
            break
        elif test -e "${x}/${APR_CONFIG}"; then
            apr_path="${x}"
            break
        else
            apr_path=""
        fi
    done
    if test -n "$apr_path"; then
        break
    fi
done

if test -n "${apr_path}" -a "${apr_path}" != "no"; then
    APR_CONFIG="${apr_path}/${APR_CONFIG}"
    APR_VERSION="`${APR_CONFIG} --version`"
    APR_CFLAGS="`${APR_CONFIG} --cflags`"
    APR_CPPFLAGS="`${APR_CONFIG} --cppflags --includes`"
    APR_LDFLAGS="`${APR_CONFIG} --libs`"
    APR_LDADD="`${APR_CONFIG} --link-libtool`"
else
    AC_MSG_ERROR([apr library is required but not found])
fi

AC_SUBST(APR_VERSION)
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_CPPFLAGS)
AC_SUBST(APR_LDFLAGS)
AC_SUBST(APR_LDADD)

AC_MSG_RESULT([yes])
])
