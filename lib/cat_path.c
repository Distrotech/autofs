#include <alloca.h>
#include <string.h>
#include <limits.h>
#include <syslog.h>
#include <ctype.h>

/*
 * sum = "dir/base" with attention to buffer overflows, and multiple
 * slashes at the joint are avoided.
 */
int cat_path(char *buf, size_t len, const char *dir, const char *base)
{
	char *d = (char *) dir;
	char *b = (char *) base;
	char *s = buf;
	size_t left = len;

	if ((*s = *d))
		while ((*++s = *++d) && --left) ;
	
	if (!left) {
		*s = '\0';
		return 0;
	}

	/* Now we have at least 1 left in output buffer */

	while (*--s == '/' && (left++ < len))
		*s = '\0';

	*++s = '/';
	left--;

	if (*b == '/') 
		while (*++b == '/');

	while (--left && (*++s = *b++)) ;

	if (!left) {
		*s = '\0';
		return 0;
	}

	return 1;
}

int _strlen(const char *str, int max)
{
	char *s = (char *) str;

	while (isprint(*s++) && max--) ;

	if (max < 0)
		return 0;
	
	return s - str - 1;
}

/* 
 * sum = "dir/base" with attention to buffer overflows, and multiple
 * slashes at the joint are avoided.  The length of base is specified
 * explicitly.
 */
int ncat_path(char *buf, size_t len,
	      const char *dir, const char *base, size_t blen)
{
	char name[PATH_MAX+1];
	int alen = _strlen(base, blen);

	if (blen > PATH_MAX || !alen)
		return 0;
	
	strncpy(name, base, alen);
	name[alen] = '\0';

	return cat_path(buf, len, dir, name);
}

