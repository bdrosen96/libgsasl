/* Recode strings between character sets, using iconv.
   Copyright (C) 2002, 2003, 2004 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Get prototype. */
#include "iconvme.h"

/* Get malloc. */
#include <stdlib.h>

/* Get strcmp. */
#include <string.h>

/* Get errno. */
#include <errno.h>

/* Get iconv etc. */
#include <iconv.h>

char *
iconv_z (const char *to_codeset, const char *from_codeset, const char *str)

{
  iconv_t cd;
  char *dest;
  char *outp;
  ICONV_CONST char *p;
  size_t inbytes_remaining;
  size_t outbytes_remaining;
  size_t err;
  size_t outbuf_size;
  int have_error = 0;

  if (strcmp (to_codeset, from_codeset) == 0)
    {
      char *q;

      q = malloc (strlen (str) + 1);
      if (!q)
	return NULL;

      return strcpy (q, str);
    }

  cd = iconv_open (to_codeset, from_codeset);

  if (cd == (iconv_t) - 1)
    return NULL;

  p = (ICONV_CONST char *) str;

  inbytes_remaining = strlen (p);
  /* Guess the maximum length the output string can have.  */
  outbuf_size = (inbytes_remaining + 1) * 5;

  outp = dest = malloc (outbuf_size);
  if (dest == NULL)
    goto out;
  outbytes_remaining = outbuf_size - 1;	/* -1 for NUL */

 again:

  err = iconv (cd, (ICONV_CONST char **) &p, &inbytes_remaining,
	       &outp, &outbytes_remaining);

  if (err == (size_t) - 1)
    {
      switch (errno)
	{
	case EINVAL:
	  /* Incomplete text, do not report an error */
	  break;

	case E2BIG:
	  {
	    size_t used = outp - dest;
	    char *newdest;

	    outbuf_size *= 2;
	    newdest = realloc (dest, outbuf_size);
	    if (newdest == NULL)
	      {
		have_error = 1;
		goto out;
	      }
	    dest = newdest;

	    outp = dest + used;
	    outbytes_remaining = outbuf_size - used - 1;	/* -1 for NUL */

	    goto again;
	  }
	  break;

	case EILSEQ:
	  have_error = 1;
	  break;

	default:
	  have_error = 1;
	  break;
	}
    }

  *outp = '\0';

  if (*p != '\0')
    have_error = 1;

 out:
  iconv_close (cd);

  if (have_error)
    {
      free (dest);
      dest = NULL;
    }

  return dest;
}