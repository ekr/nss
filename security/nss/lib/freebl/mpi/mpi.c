/*
 *  mpi.c
 *
 *  Arbitrary precision integer arithmetic library
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is the MPI Arbitrary Precision Integer Arithmetic
 * library.
 *
 * The Initial Developer of the Original Code is Michael J. Fromberger.
 * Portions created by Michael J. Fromberger are 
 * Copyright (C) 1998, 1999, 2000 Michael J. Fromberger. 
 * All Rights Reserved.
 *
 * Contributor(s):
 *	Netscape Communications Corporation 
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the GPL.
 *
 *  $Id$
 */

#include "mpi-priv.h"

#if MP_LOGTAB
/*
  A table of the logs of 2 for various bases (the 0 and 1 entries of
  this table are meaningless and should not be referenced).  

  This table is used to compute output lengths for the mp_toradix()
  function.  Since a number n in radix r takes up about log_r(n)
  digits, we estimate the output size by taking the least integer
  greater than log_r(n), where:

  log_r(n) = log_2(n) * log_r(2)

  This table, therefore, is a table of log_r(2) for 2 <= r <= 36,
  which are the output bases supported.  
 */
#include "logtab.h"
#endif

/* {{{ Constant strings */

/* Constant strings returned by mp_strerror() */
static const char *mp_err_string[] = {
  "unknown result code",     /* say what?            */
  "boolean true",            /* MP_OKAY, MP_YES      */
  "boolean false",           /* MP_NO                */
  "out of memory",           /* MP_MEM               */
  "argument out of range",   /* MP_RANGE             */
  "invalid input parameter", /* MP_BADARG            */
  "result is undefined"      /* MP_UNDEF             */
};

/* Value to digit maps for radix conversion   */

/* s_dmap_1 - standard digits and letters */
static const char *s_dmap_1 = 
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

/* }}} */

unsigned long mp_allocs;
unsigned long mp_frees;
unsigned long mp_copies;

/* {{{ Default precision manipulation */

/* Default precision for newly created mp_int's      */
static mp_size s_mp_defprec = MP_DEFPREC;

mp_size mp_get_prec(void)
{
  return s_mp_defprec;

} /* end mp_get_prec() */

void         mp_set_prec(mp_size prec)
{
  if(prec == 0)
    s_mp_defprec = MP_DEFPREC;
  else
    s_mp_defprec = prec;

} /* end mp_set_prec() */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ mp_init(mp) */

/*
  mp_init(mp)

  Initialize a new zero-valued mp_int.  Returns MP_OKAY if successful,
  MP_MEM if memory could not be allocated for the structure.
 */

mp_err mp_init(mp_int *mp)
{
  return mp_init_size(mp, s_mp_defprec);

} /* end mp_init() */

/* }}} */

/* {{{ mp_init_size(mp, prec) */

/*
  mp_init_size(mp, prec)

  Initialize a new zero-valued mp_int with at least the given
  precision; returns MP_OKAY if successful, or MP_MEM if memory could
  not be allocated for the structure.
 */

mp_err mp_init_size(mp_int *mp, mp_size prec)
{
  ARGCHK(mp != NULL && prec > 0, MP_BADARG);

  prec = MP_ROUNDUP(prec, s_mp_defprec);
  if((DIGITS(mp) = s_mp_alloc(prec, sizeof(mp_digit))) == NULL)
    return MP_MEM;

  SIGN(mp) = ZPOS;
  USED(mp) = 1;
  ALLOC(mp) = prec;

  return MP_OKAY;

} /* end mp_init_size() */

/* }}} */

/* {{{ mp_init_copy(mp, from) */

/*
  mp_init_copy(mp, from)

  Initialize mp as an exact copy of from.  Returns MP_OKAY if
  successful, MP_MEM if memory could not be allocated for the new
  structure.
 */

mp_err mp_init_copy(mp_int *mp, const mp_int *from)
{
  ARGCHK(mp != NULL && from != NULL, MP_BADARG);

  if(mp == from)
    return MP_OKAY;

  if((DIGITS(mp) = s_mp_alloc(ALLOC(from), sizeof(mp_digit))) == NULL)
    return MP_MEM;

  s_mp_copy(DIGITS(from), DIGITS(mp), USED(from));
  USED(mp) = USED(from);
  ALLOC(mp) = ALLOC(from);
  SIGN(mp) = SIGN(from);

  return MP_OKAY;

} /* end mp_init_copy() */

/* }}} */

/* {{{ mp_copy(from, to) */

/*
  mp_copy(from, to)

  Copies the mp_int 'from' to the mp_int 'to'.  It is presumed that
  'to' has already been initialized (if not, use mp_init_copy()
  instead). If 'from' and 'to' are identical, nothing happens.
 */

mp_err mp_copy(const mp_int *from, mp_int *to)
{
  ARGCHK(from != NULL && to != NULL, MP_BADARG);

  if(from == to)
    return MP_OKAY;

  ++mp_copies;
  { /* copy */
    mp_digit   *tmp;

    /*
      If the allocated buffer in 'to' already has enough space to hold
      all the used digits of 'from', we'll re-use it to avoid hitting
      the memory allocater more than necessary; otherwise, we'd have
      to grow anyway, so we just allocate a hunk and make the copy as
      usual
     */
    if(ALLOC(to) >= USED(from)) {
      s_mp_setz(DIGITS(to) + USED(from), ALLOC(to) - USED(from));
      s_mp_copy(DIGITS(from), DIGITS(to), USED(from));
      
    } else {
      if((tmp = s_mp_alloc(ALLOC(from), sizeof(mp_digit))) == NULL)
	return MP_MEM;

      s_mp_copy(DIGITS(from), tmp, USED(from));

      if(DIGITS(to) != NULL) {
#if MP_CRYPTO
	s_mp_setz(DIGITS(to), ALLOC(to));
#endif
	s_mp_free(DIGITS(to));
      }

      DIGITS(to) = tmp;
      ALLOC(to) = ALLOC(from);
    }

    /* Copy the precision and sign from the original */
    USED(to) = USED(from);
    SIGN(to) = SIGN(from);
  } /* end copy */

  return MP_OKAY;

} /* end mp_copy() */

/* }}} */

/* {{{ mp_exch(mp1, mp2) */

/*
  mp_exch(mp1, mp2)

  Exchange mp1 and mp2 without allocating any intermediate memory
  (well, unless you count the stack space needed for this call and the
  locals it creates...).  This cannot fail.
 */

void mp_exch(mp_int *mp1, mp_int *mp2)
{
#if MP_ARGCHK == 2
  assert(mp1 != NULL && mp2 != NULL);
#else
  if(mp1 == NULL || mp2 == NULL)
    return;
#endif

  s_mp_exch(mp1, mp2);

} /* end mp_exch() */

/* }}} */

/* {{{ mp_clear(mp) */

/*
  mp_clear(mp)

  Release the storage used by an mp_int, and void its fields so that
  if someone calls mp_clear() again for the same int later, we won't
  get tollchocked.
 */

void   mp_clear(mp_int *mp)
{
  if(mp == NULL)
    return;

  if(DIGITS(mp) != NULL) {
#if MP_CRYPTO
    s_mp_setz(DIGITS(mp), ALLOC(mp));
#endif
    s_mp_free(DIGITS(mp));
    DIGITS(mp) = NULL;
  }

  USED(mp) = 0;
  ALLOC(mp) = 0;

} /* end mp_clear() */

/* }}} */

/* {{{ mp_zero(mp) */

/*
  mp_zero(mp) 

  Set mp to zero.  Does not change the allocated size of the structure,
  and therefore cannot fail (except on a bad argument, which we ignore)
 */
void   mp_zero(mp_int *mp)
{
  if(mp == NULL)
    return;

  s_mp_setz(DIGITS(mp), ALLOC(mp));
  USED(mp) = 1;
  SIGN(mp) = ZPOS;

} /* end mp_zero() */

/* }}} */

/* {{{ mp_set(mp, d) */

void   mp_set(mp_int *mp, mp_digit d)
{
  if(mp == NULL)
    return;

  mp_zero(mp);
  DIGIT(mp, 0) = d;

} /* end mp_set() */

/* }}} */

/* {{{ mp_set_int(mp, z) */

mp_err mp_set_int(mp_int *mp, long z)
{
  int            ix;
  unsigned long  v = abs(z);
  mp_err         res;

  ARGCHK(mp != NULL, MP_BADARG);

  mp_zero(mp);
  if(z == 0)
    return MP_OKAY;  /* shortcut for zero */

  if (sizeof v <= sizeof(mp_digit)) {
    DIGIT(mp,0) = v;
  } else {
    for (ix = sizeof(long) - 1; ix >= 0; ix--) {
      if ((res = s_mp_mul_d(mp, (UCHAR_MAX + 1))) != MP_OKAY)
	return res;

      res = s_mp_add_d(mp, (mp_digit)((v >> (ix * CHAR_BIT)) & UCHAR_MAX));
      if (res != MP_OKAY)
	return res;
    }
  }
  if(z < 0)
    SIGN(mp) = NEG;

  return MP_OKAY;

} /* end mp_set_int() */

/* }}} */

/* {{{ mp_set_ulong(mp, z) */

mp_err mp_set_ulong(mp_int *mp, unsigned long z)
{
  int            ix;
  mp_err         res;

  ARGCHK(mp != NULL, MP_BADARG);

  mp_zero(mp);
  if(z == 0)
    return MP_OKAY;  /* shortcut for zero */

  if (sizeof z <= sizeof(mp_digit)) {
    DIGIT(mp,0) = z;
  } else {
    for (ix = sizeof(long) - 1; ix >= 0; ix--) {
      if ((res = s_mp_mul_d(mp, (UCHAR_MAX + 1))) != MP_OKAY)
	return res;

      res = s_mp_add_d(mp, (mp_digit)((z >> (ix * CHAR_BIT)) & UCHAR_MAX));
      if (res != MP_OKAY)
	return res;
    }
  }
  return MP_OKAY;
} /* end mp_set_ulong() */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ Digit arithmetic */

/* {{{ mp_add_d(a, d, b) */

/*
  mp_add_d(a, d, b)

  Compute the sum b = a + d, for a single digit d.  Respects the sign of
  its primary addend (single digits are unsigned anyway).
 */

mp_err mp_add_d(const mp_int *a, mp_digit d, mp_int *b)
{
  mp_int   tmp;
  mp_err   res;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  if((res = mp_init_copy(&tmp, a)) != MP_OKAY)
    return res;

  if(SIGN(&tmp) == ZPOS) {
    if((res = s_mp_add_d(&tmp, d)) != MP_OKAY)
      goto CLEANUP;
  } else if(s_mp_cmp_d(&tmp, d) >= 0) {
    if((res = s_mp_sub_d(&tmp, d)) != MP_OKAY)
      goto CLEANUP;
  } else {
    mp_neg(&tmp, &tmp);

    DIGIT(&tmp, 0) = d - DIGIT(&tmp, 0);
  }

  if(s_mp_cmp_d(&tmp, 0) == 0)
    SIGN(&tmp) = ZPOS;

  s_mp_exch(&tmp, b);

CLEANUP:
  mp_clear(&tmp);
  return res;

} /* end mp_add_d() */

/* }}} */

/* {{{ mp_sub_d(a, d, b) */

/*
  mp_sub_d(a, d, b)

  Compute the difference b = a - d, for a single digit d.  Respects the
  sign of its subtrahend (single digits are unsigned anyway).
 */

mp_err mp_sub_d(const mp_int *a, mp_digit d, mp_int *b)
{
  mp_int   tmp;
  mp_err   res;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  if((res = mp_init_copy(&tmp, a)) != MP_OKAY)
    return res;

  if(SIGN(&tmp) == NEG) {
    if((res = s_mp_add_d(&tmp, d)) != MP_OKAY)
      goto CLEANUP;
  } else if(s_mp_cmp_d(&tmp, d) >= 0) {
    if((res = s_mp_sub_d(&tmp, d)) != MP_OKAY)
      goto CLEANUP;
  } else {
    mp_neg(&tmp, &tmp);

    DIGIT(&tmp, 0) = d - DIGIT(&tmp, 0);
    SIGN(&tmp) = NEG;
  }

  if(s_mp_cmp_d(&tmp, 0) == 0)
    SIGN(&tmp) = ZPOS;

  s_mp_exch(&tmp, b);

CLEANUP:
  mp_clear(&tmp);
  return res;

} /* end mp_sub_d() */

/* }}} */

/* {{{ mp_mul_d(a, d, b) */

/*
  mp_mul_d(a, d, b)

  Compute the product b = a * d, for a single digit d.  Respects the sign
  of its multiplicand (single digits are unsigned anyway)
 */

mp_err mp_mul_d(const mp_int *a, mp_digit d, mp_int *b)
{
  mp_err  res;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  if(d == 0) {
    mp_zero(b);
    return MP_OKAY;
  }

  if((res = mp_copy(a, b)) != MP_OKAY)
    return res;

  res = s_mp_mul_d(b, d);

  return res;

} /* end mp_mul_d() */

/* }}} */

/* {{{ mp_mul_2(a, c) */

mp_err mp_mul_2(const mp_int *a, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && c != NULL, MP_BADARG);

  if((res = mp_copy(a, c)) != MP_OKAY)
    return res;

  return s_mp_mul_2(c);

} /* end mp_mul_2() */

/* }}} */

/* {{{ mp_div_d(a, d, q, r) */

/*
  mp_div_d(a, d, q, r)

  Compute the quotient q = a / d and remainder r = a mod d, for a
  single digit d.  Respects the sign of its divisor (single digits are
  unsigned anyway).
 */

mp_err mp_div_d(const mp_int *a, mp_digit d, mp_int *q, mp_digit *r)
{
  mp_err   res;
  mp_int   qp;
  mp_digit rem;
  int      pow;

  ARGCHK(a != NULL, MP_BADARG);

  if(d == 0)
    return MP_RANGE;

  /* Shortcut for powers of two ... */
  if((pow = s_mp_ispow2d(d)) >= 0) {
    mp_digit  mask;

    mask = ((mp_digit)1 << pow) - 1;
    rem = DIGIT(a, 0) & mask;

    if(q) {
      mp_copy(a, q);
      s_mp_div_2d(q, pow);
    }

    if(r)
      *r = rem;

    return MP_OKAY;
  }

  if((res = mp_init_copy(&qp, a)) != MP_OKAY)
    return res;

  res = s_mp_div_d(&qp, d, &rem);

  if(s_mp_cmp_d(&qp, 0) == 0)
    SIGN(q) = ZPOS;

  if(r)
    *r = rem;

  if(q)
    s_mp_exch(&qp, q);

  mp_clear(&qp);
  return res;

} /* end mp_div_d() */

/* }}} */

/* {{{ mp_div_2(a, c) */

/*
  mp_div_2(a, c)

  Compute c = a / 2, disregarding the remainder.
 */

mp_err mp_div_2(const mp_int *a, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && c != NULL, MP_BADARG);

  if((res = mp_copy(a, c)) != MP_OKAY)
    return res;

  s_mp_div_2(c);

  return MP_OKAY;

} /* end mp_div_2() */

/* }}} */

/* {{{ mp_expt_d(a, d, b) */

mp_err mp_expt_d(const mp_int *a, mp_digit d, mp_int *c)
{
  mp_int   s, x;
  mp_err   res;

  ARGCHK(a != NULL && c != NULL, MP_BADARG);

  if((res = mp_init(&s)) != MP_OKAY)
    return res;
  if((res = mp_init_copy(&x, a)) != MP_OKAY)
    goto X;

  DIGIT(&s, 0) = 1;

  while(d != 0) {
    if(d & 1) {
      if((res = s_mp_mul(&s, &x)) != MP_OKAY)
	goto CLEANUP;
    }

    d /= 2;

    if((res = s_mp_sqr(&x)) != MP_OKAY)
      goto CLEANUP;
  }

  s_mp_exch(&s, c);

CLEANUP:
  mp_clear(&x);
X:
  mp_clear(&s);

  return res;

} /* end mp_expt_d() */

/* }}} */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ Full arithmetic */

/* {{{ mp_abs(a, b) */

/*
  mp_abs(a, b)

  Compute b = |a|.  'a' and 'b' may be identical.
 */

mp_err mp_abs(const mp_int *a, mp_int *b)
{
  mp_err   res;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  if((res = mp_copy(a, b)) != MP_OKAY)
    return res;

  SIGN(b) = ZPOS;

  return MP_OKAY;

} /* end mp_abs() */

/* }}} */

/* {{{ mp_neg(a, b) */

/*
  mp_neg(a, b)

  Compute b = -a.  'a' and 'b' may be identical.
 */

mp_err mp_neg(const mp_int *a, mp_int *b)
{
  mp_err   res;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  if((res = mp_copy(a, b)) != MP_OKAY)
    return res;

  if(s_mp_cmp_d(b, 0) == MP_EQ) 
    SIGN(b) = ZPOS;
  else 
    SIGN(b) = (SIGN(b) == NEG) ? ZPOS : NEG;

  return MP_OKAY;

} /* end mp_neg() */

/* }}} */

/* {{{ mp_add(a, b, c) */

/*
  mp_add(a, b, c)

  Compute c = a + b.  All parameters may be identical.
 */

mp_err mp_add(const mp_int *a, const mp_int *b, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  if(SIGN(a) == SIGN(b)) { /* same sign:  add values, keep sign */
    MP_CHECKOK( s_mp_add_3arg(a, b, c) );
  } else if(s_mp_cmp(a, b) >= 0) {  /* different sign: |a| >= |b|   */
    MP_CHECKOK( s_mp_sub_3arg(a, b, c) );
  } else {                          /* different sign: |a|  < |b|   */
    MP_CHECKOK( s_mp_sub_3arg(b, a, c) );
  }

  if (s_mp_cmp_d(c, 0) == MP_EQ)
    SIGN(c) = ZPOS;

CLEANUP:
  return res;

} /* end mp_add() */

/* }}} */

/* {{{ mp_sub(a, b, c) */

/*
  mp_sub(a, b, c)

  Compute c = a - b.  All parameters may be identical.
 */

mp_err mp_sub(const mp_int *a, const mp_int *b, mp_int *c)
{
  mp_err  res;
  int     magDiff;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  if (a == b) {
    mp_zero(c);
    return MP_OKAY;
  }

  if (MP_SIGN(a) != MP_SIGN(b)) {
    MP_CHECKOK( s_mp_add_3arg(a, b, c) );
  } else if (!(magDiff = s_mp_cmp(a, b))) {
    mp_zero(c);
    res = MP_OKAY;
  } else if (magDiff > 0) {
    MP_CHECKOK( s_mp_sub_3arg(a, b, c) );
  } else {
    MP_CHECKOK( s_mp_sub_3arg(b, a, c) );
    MP_SIGN(c) = !MP_SIGN(a);
  }

  if (s_mp_cmp_d(c, 0) == MP_EQ)
    MP_SIGN(c) = MP_ZPOS;

CLEANUP:
  return res;

} /* end mp_sub() */

/* }}} */

/* {{{ mp_mul(a, b, c) */

/*
  mp_mul(a, b, c)

  Compute c = a * b.  All parameters may be identical.
 */
mp_err   mp_mul(const mp_int *a, const mp_int *b, mp_int * c)
{
  mp_digit *pb;
  mp_int   tmp;
  mp_err   res;
  mp_size  ib;
  mp_size  useda, usedb;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  if (a == c) {
    if ((res = mp_init_copy(&tmp, a)) != MP_OKAY)
      return res;
    if (a == b) 
      b = &tmp;
    a = &tmp;
  } else if (b == c) {
    if ((res = mp_init_copy(&tmp, b)) != MP_OKAY)
      return res;
    b = &tmp;
  } else {
    MP_DIGITS(&tmp) = 0;
  }

  if (MP_USED(a) < MP_USED(b)) {
    const mp_int *xch = b;	/* switch a and b, to do fewer outer loops */
    b = a;
    a = xch;
  }

  MP_USED(c) = 1; MP_DIGIT(c, 0) = 0;
  if((res = s_mp_pad(c, USED(a) + USED(b))) != MP_OKAY)
    goto CLEANUP;

  pb = MP_DIGITS(b);
  s_mpv_mul_d(MP_DIGITS(a), MP_USED(a), *pb++, MP_DIGITS(c));

  /* Outer loop:  Digits of b */
  useda = MP_USED(a);
  usedb = MP_USED(b);
  for (ib = 1; ib < usedb; ib++) {
    mp_digit b_i    = *pb++;

    /* Inner product:  Digits of a */
    if (b_i)
      s_mpv_mul_d_add(MP_DIGITS(a), useda, b_i, MP_DIGITS(c) + ib);
    else
      MP_DIGIT(c, ib + useda) = b_i;
  }

  s_mp_clamp(c);

  if(SIGN(a) == SIGN(b) || s_mp_cmp_d(c, 0) == MP_EQ)
    SIGN(c) = ZPOS;
  else
    SIGN(c) = NEG;

CLEANUP:
  mp_clear(&tmp);
  return res;
} /* end mp_mul() */

/* }}} */

/* {{{ mp_sqr(a, sqr) */

#if MP_SQUARE
/*
  Computes the square of a.  This can be done more
  efficiently than a general multiplication, because many of the
  computation steps are redundant when squaring.  The inner product
  step is a bit more complicated, but we save a fair number of
  iterations of the multiplication loop.
 */

/* sqr = a^2;   Caller provides both a and tmp; */
mp_err   mp_sqr(const mp_int *a, mp_int *sqr)
{
  mp_digit *pa;
  mp_digit d;
  mp_err   res;
  mp_size  ix;
  mp_int   tmp;
  int      count;

  ARGCHK(a != NULL && sqr != NULL, MP_BADARG);

  if (a == sqr) {
    if((res = mp_init_copy(&tmp, a)) != MP_OKAY)
      return res;
    a = &tmp;
  } else {
    DIGITS(&tmp) = 0;
    res = MP_OKAY;
  }

  ix = 2 * MP_USED(a);
  if (ix > MP_ALLOC(sqr)) {
    MP_USED(sqr) = 1; 
    MP_CHECKOK( s_mp_grow(sqr, ix) );
  } 
  MP_USED(sqr) = ix;
  MP_DIGIT(sqr, 0) = 0;

  pa = MP_DIGITS(a);
  count = MP_USED(a) - 1;
  if (count > 0) {
    d = *pa++;
    s_mpv_mul_d(pa, count, d, MP_DIGITS(sqr) + 1);
    for (ix = 3; --count > 0; ix += 2) {
      d = *pa++;
      s_mpv_mul_d_add(pa, count, d, MP_DIGITS(sqr) + ix);
    } /* for(ix ...) */
    MP_DIGIT(sqr, MP_USED(sqr)-1) = 0; /* above loop stopped short of this. */

    /* now sqr *= 2 */
    s_mp_mul_2(sqr);
  } else {
    MP_DIGIT(sqr, 1) = 0;
  }

  /* now add the squares of the digits of a to sqr. */
  s_mpv_sqr_add_prop(MP_DIGITS(a), MP_USED(a), MP_DIGITS(sqr));

  SIGN(sqr) = ZPOS;
  s_mp_clamp(sqr);

CLEANUP:
  mp_clear(&tmp);
  return res;

} /* end mp_sqr() */
#endif

/* }}} */

/* {{{ mp_div(a, b, q, r) */

/*
  mp_div(a, b, q, r)

  Compute q = a / b and r = a mod b.  Input parameters may be re-used
  as output parameters.  If q or r is NULL, that portion of the
  computation will be discarded (although it will still be computed)

  Pay no attention to the hacker behind the curtain.
 */

mp_err mp_div(const mp_int *a, const mp_int *b, mp_int *q, mp_int *r)
{
  mp_err   res;
  mp_int   *pQ, *pR;
  mp_int   qtmp, rtmp;
  int      cmp;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  if(mp_cmp_z(b) == MP_EQ)
    return MP_RANGE;

  DIGITS(&qtmp) = 0;
  DIGITS(&rtmp) = 0;
  /* Set up some temporaries... */
  if (!q || q == a || q == b) {
    if((res = mp_init_copy(&qtmp, a)) != MP_OKAY)
      return res;
    pQ = &qtmp;
  } else {
    if((res = mp_copy(a, q)) != MP_OKAY)
      return res;
    pQ = q;
  }
  if (!r || r == a || r == b) {
    if((res = mp_init_copy(&rtmp, b)) != MP_OKAY)
      goto CLEANUP;
    pR = &rtmp;
  } else {
    if((res = mp_copy(b, r)) != MP_OKAY)
      goto CLEANUP;
    pR = r;
  }

  /*
    If a <= b, we can compute the solution without division;
    otherwise, we actually do the work required.
   */
  if((cmp = s_mp_cmp(pQ, pR)) < 0) {
    s_mp_exch(pQ, pR);
    mp_zero(pQ);
  } else if(cmp == 0) {
    mp_set(pQ, 1);
    mp_zero(pR);
  } else {
    if((res = s_mp_div(pQ, pR)) != MP_OKAY)
      goto CLEANUP;
  }

  /* Compute the signs for the output  */
  SIGN(pR) = SIGN(a); /* Sr = Sa              */
  if(SIGN(a) == SIGN(b))
    SIGN(pQ) = ZPOS;  /* Sq = ZPOS if Sa = Sb */
  else
    SIGN(pQ) = NEG;   /* Sq = NEG if Sa != Sb */

  if(s_mp_cmp_d(pQ, 0) == MP_EQ)
    SIGN(pQ) = ZPOS;
  if(s_mp_cmp_d(pR, 0) == MP_EQ)
    SIGN(pR) = ZPOS;

  /* Copy output, if it is needed      */
  if(q && q != pQ) 
    s_mp_exch(pQ, q);

  if(r && r != pR) 
    s_mp_exch(pR, r);

CLEANUP:
  mp_clear(&rtmp);
  mp_clear(&qtmp);

  return res;

} /* end mp_div() */

/* }}} */

/* {{{ mp_div_2d(a, d, q, r) */

mp_err mp_div_2d(const mp_int *a, mp_digit d, mp_int *q, mp_int *r)
{
  mp_err  res;

  ARGCHK(a != NULL, MP_BADARG);

  if(q) {
    if((res = mp_copy(a, q)) != MP_OKAY)
      return res;
  }
  if(r) {
    if((res = mp_copy(a, r)) != MP_OKAY)
      return res;
  }
  if(q) {
    s_mp_div_2d(q, d);
  }
  if(r) {
    s_mp_mod_2d(r, d);
  }

  return MP_OKAY;

} /* end mp_div_2d() */

/* }}} */

/* {{{ mp_expt(a, b, c) */

/*
  mp_expt(a, b, c)

  Compute c = a ** b, that is, raise a to the b power.  Uses a
  standard iterative square-and-multiply technique.
 */

mp_err mp_expt(mp_int *a, mp_int *b, mp_int *c)
{
  mp_int   s, x;
  mp_err   res;
  mp_digit d;
  int      dig, bit;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  if(mp_cmp_z(b) < 0)
    return MP_RANGE;

  if((res = mp_init(&s)) != MP_OKAY)
    return res;

  mp_set(&s, 1);

  if((res = mp_init_copy(&x, a)) != MP_OKAY)
    goto X;

  /* Loop over low-order digits in ascending order */
  for(dig = 0; dig < (USED(b) - 1); dig++) {
    d = DIGIT(b, dig);

    /* Loop over bits of each non-maximal digit */
    for(bit = 0; bit < DIGIT_BIT; bit++) {
      if(d & 1) {
	if((res = s_mp_mul(&s, &x)) != MP_OKAY) 
	  goto CLEANUP;
      }

      d >>= 1;
      
      if((res = s_mp_sqr(&x)) != MP_OKAY)
	goto CLEANUP;
    }
  }

  /* Consider now the last digit... */
  d = DIGIT(b, dig);

  while(d) {
    if(d & 1) {
      if((res = s_mp_mul(&s, &x)) != MP_OKAY)
	goto CLEANUP;
    }

    d >>= 1;

    if((res = s_mp_sqr(&x)) != MP_OKAY)
      goto CLEANUP;
  }
  
  if(mp_iseven(b))
    SIGN(&s) = SIGN(a);

  res = mp_copy(&s, c);

CLEANUP:
  mp_clear(&x);
X:
  mp_clear(&s);

  return res;

} /* end mp_expt() */

/* }}} */

/* {{{ mp_2expt(a, k) */

/* Compute a = 2^k */

mp_err mp_2expt(mp_int *a, mp_digit k)
{
  ARGCHK(a != NULL, MP_BADARG);

  return s_mp_2expt(a, k);

} /* end mp_2expt() */

/* }}} */

/* {{{ mp_mod(a, m, c) */

/*
  mp_mod(a, m, c)

  Compute c = a (mod m).  Result will always be 0 <= c < m.
 */

mp_err mp_mod(const mp_int *a, const mp_int *m, mp_int *c)
{
  mp_err  res;
  int     mag;

  ARGCHK(a != NULL && m != NULL && c != NULL, MP_BADARG);

  if(SIGN(m) == NEG)
    return MP_RANGE;

  /*
     If |a| > m, we need to divide to get the remainder and take the
     absolute value.  

     If |a| < m, we don't need to do any division, just copy and adjust
     the sign (if a is negative).

     If |a| == m, we can simply set the result to zero.

     This order is intended to minimize the average path length of the
     comparison chain on common workloads -- the most frequent cases are
     that |a| != m, so we do those first.
   */
  if((mag = s_mp_cmp(a, m)) > 0) {
    if((res = mp_div(a, m, NULL, c)) != MP_OKAY)
      return res;
    
    if(SIGN(c) == NEG) {
      if((res = mp_add(c, m, c)) != MP_OKAY)
	return res;
    }

  } else if(mag < 0) {
    if((res = mp_copy(a, c)) != MP_OKAY)
      return res;

    if(mp_cmp_z(a) < 0) {
      if((res = mp_add(c, m, c)) != MP_OKAY)
	return res;

    }
    
  } else {
    mp_zero(c);

  }

  return MP_OKAY;

} /* end mp_mod() */

/* }}} */

/* {{{ mp_mod_d(a, d, c) */

/*
  mp_mod_d(a, d, c)

  Compute c = a (mod d).  Result will always be 0 <= c < d
 */
mp_err mp_mod_d(const mp_int *a, mp_digit d, mp_digit *c)
{
  mp_err   res;
  mp_digit rem;

  ARGCHK(a != NULL && c != NULL, MP_BADARG);

  if(s_mp_cmp_d(a, d) > 0) {
    if((res = mp_div_d(a, d, NULL, &rem)) != MP_OKAY)
      return res;

  } else {
    if(SIGN(a) == NEG)
      rem = d - DIGIT(a, 0);
    else
      rem = DIGIT(a, 0);
  }

  if(c)
    *c = rem;

  return MP_OKAY;

} /* end mp_mod_d() */

/* }}} */

/* {{{ mp_sqrt(a, b) */

/*
  mp_sqrt(a, b)

  Compute the integer square root of a, and store the result in b.
  Uses an integer-arithmetic version of Newton's iterative linear
  approximation technique to determine this value; the result has the
  following two properties:

     b^2 <= a
     (b+1)^2 >= a

  It is a range error to pass a negative value.
 */
mp_err mp_sqrt(const mp_int *a, mp_int *b)
{
  mp_int   x, t;
  mp_err   res;
  mp_size  used;

  ARGCHK(a != NULL && b != NULL, MP_BADARG);

  /* Cannot take square root of a negative value */
  if(SIGN(a) == NEG)
    return MP_RANGE;

  /* Special cases for zero and one, trivial     */
  if(mp_cmp_d(a, 1) <= 0)
    return mp_copy(a, b);
    
  /* Initialize the temporaries we'll use below  */
  if((res = mp_init_size(&t, USED(a))) != MP_OKAY)
    return res;

  /* Compute an initial guess for the iteration as a itself */
  if((res = mp_init_copy(&x, a)) != MP_OKAY)
    goto X;

  used = MP_USED(&x);
  if (used > 1) {
    s_mp_rshd(&x, used / 2);
  }

  for(;;) {
    /* t = (x * x) - a */
    mp_copy(&x, &t);      /* can't fail, t is big enough for original x */
    if((res = mp_sqr(&t, &t)) != MP_OKAY ||
       (res = mp_sub(&t, a, &t)) != MP_OKAY)
      goto CLEANUP;

    /* t = t / 2x       */
    s_mp_mul_2(&x);
    if((res = mp_div(&t, &x, &t, NULL)) != MP_OKAY)
      goto CLEANUP;
    s_mp_div_2(&x);

    /* Terminate the loop, if the quotient is zero */
    if(mp_cmp_z(&t) == MP_EQ)
      break;

    /* x = x - t       */
    if((res = mp_sub(&x, &t, &x)) != MP_OKAY)
      goto CLEANUP;

  }

  /* Copy result to output parameter */
  mp_sub_d(&x, 1, &x);
  s_mp_exch(&x, b);

 CLEANUP:
  mp_clear(&x);
 X:
  mp_clear(&t); 

  return res;

} /* end mp_sqrt() */

/* }}} */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ Modular arithmetic */

#if MP_MODARITH
/* {{{ mp_addmod(a, b, m, c) */

/*
  mp_addmod(a, b, m, c)

  Compute c = (a + b) mod m
 */

mp_err mp_addmod(const mp_int *a, const mp_int *b, const mp_int *m, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && b != NULL && m != NULL && c != NULL, MP_BADARG);

  if((res = mp_add(a, b, c)) != MP_OKAY)
    return res;
  if((res = mp_mod(c, m, c)) != MP_OKAY)
    return res;

  return MP_OKAY;

}

/* }}} */

/* {{{ mp_submod(a, b, m, c) */

/*
  mp_submod(a, b, m, c)

  Compute c = (a - b) mod m
 */

mp_err mp_submod(const mp_int *a, const mp_int *b, const mp_int *m, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && b != NULL && m != NULL && c != NULL, MP_BADARG);

  if((res = mp_sub(a, b, c)) != MP_OKAY)
    return res;
  if((res = mp_mod(c, m, c)) != MP_OKAY)
    return res;

  return MP_OKAY;

}

/* }}} */

/* {{{ mp_mulmod(a, b, m, c) */

/*
  mp_mulmod(a, b, m, c)

  Compute c = (a * b) mod m
 */

mp_err mp_mulmod(const mp_int *a, const mp_int *b, const mp_int *m, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && b != NULL && m != NULL && c != NULL, MP_BADARG);

  if((res = mp_mul(a, b, c)) != MP_OKAY)
    return res;
  if((res = mp_mod(c, m, c)) != MP_OKAY)
    return res;

  return MP_OKAY;

}

/* }}} */

/* {{{ mp_sqrmod(a, m, c) */

#if MP_SQUARE
mp_err mp_sqrmod(const mp_int *a, const mp_int *m, mp_int *c)
{
  mp_err  res;

  ARGCHK(a != NULL && m != NULL && c != NULL, MP_BADARG);

  if((res = mp_sqr(a, c)) != MP_OKAY)
    return res;
  if((res = mp_mod(c, m, c)) != MP_OKAY)
    return res;

  return MP_OKAY;

} /* end mp_sqrmod() */
#endif

/* }}} */

/* {{{ s_mp_exptmod(a, b, m, c) */

/*
  s_mp_exptmod(a, b, m, c)

  Compute c = (a ** b) mod m.  Uses a standard square-and-multiply
  method with modular reductions at each step. (This is basically the
  same code as mp_expt(), except for the addition of the reductions)
  
  The modular reductions are done using Barrett's algorithm (see
  s_mp_reduce() below for details)
 */

mp_err s_mp_exptmod(const mp_int *a, const mp_int *b, const mp_int *m, mp_int *c)
{
  mp_int   s, x, mu;
  mp_err   res;
  mp_digit d;
  int      dig, bit;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  if(mp_cmp_z(b) < 0 || mp_cmp_z(m) <= 0)
    return MP_RANGE;

  if((res = mp_init(&s)) != MP_OKAY)
    return res;
  if((res = mp_init_copy(&x, a)) != MP_OKAY ||
     (res = mp_mod(&x, m, &x)) != MP_OKAY)
    goto X;
  if((res = mp_init(&mu)) != MP_OKAY)
    goto MU;

  mp_set(&s, 1);

  /* mu = b^2k / m */
  s_mp_add_d(&mu, 1); 
  s_mp_lshd(&mu, 2 * USED(m));
  if((res = mp_div(&mu, m, &mu, NULL)) != MP_OKAY)
    goto CLEANUP;

  /* Loop over digits of b in ascending order, except highest order */
  for(dig = 0; dig < (USED(b) - 1); dig++) {
    d = DIGIT(b, dig);

    /* Loop over the bits of the lower-order digits */
    for(bit = 0; bit < DIGIT_BIT; bit++) {
      if(d & 1) {
	if((res = s_mp_mul(&s, &x)) != MP_OKAY)
	  goto CLEANUP;
	if((res = s_mp_reduce(&s, m, &mu)) != MP_OKAY)
	  goto CLEANUP;
      }

      d >>= 1;

      if((res = s_mp_sqr(&x)) != MP_OKAY)
	goto CLEANUP;
      if((res = s_mp_reduce(&x, m, &mu)) != MP_OKAY)
	goto CLEANUP;
    }
  }

  /* Now do the last digit... */
  d = DIGIT(b, dig);

  while(d) {
    if(d & 1) {
      if((res = s_mp_mul(&s, &x)) != MP_OKAY)
	goto CLEANUP;
      if((res = s_mp_reduce(&s, m, &mu)) != MP_OKAY)
	goto CLEANUP;
    }

    d >>= 1;

    if((res = s_mp_sqr(&x)) != MP_OKAY)
      goto CLEANUP;
    if((res = s_mp_reduce(&x, m, &mu)) != MP_OKAY)
      goto CLEANUP;
  }

  s_mp_exch(&s, c);

 CLEANUP:
  mp_clear(&mu);
 MU:
  mp_clear(&x);
 X:
  mp_clear(&s);

  return res;

} /* end s_mp_exptmod() */

/* }}} */

/* {{{ mp_exptmod_d(a, d, m, c) */

mp_err mp_exptmod_d(const mp_int *a, mp_digit d, const mp_int *m, mp_int *c)
{
  mp_int   s, x;
  mp_err   res;

  ARGCHK(a != NULL && c != NULL, MP_BADARG);

  if((res = mp_init(&s)) != MP_OKAY)
    return res;
  if((res = mp_init_copy(&x, a)) != MP_OKAY)
    goto X;

  mp_set(&s, 1);

  while(d != 0) {
    if(d & 1) {
      if((res = s_mp_mul(&s, &x)) != MP_OKAY ||
	 (res = mp_mod(&s, m, &s)) != MP_OKAY)
	goto CLEANUP;
    }

    d /= 2;

    if((res = s_mp_sqr(&x)) != MP_OKAY ||
       (res = mp_mod(&x, m, &x)) != MP_OKAY)
      goto CLEANUP;
  }

  s_mp_exch(&s, c);

CLEANUP:
  mp_clear(&x);
X:
  mp_clear(&s);

  return res;

} /* end mp_exptmod_d() */

/* }}} */
#endif /* if MP_MODARITH */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ Comparison functions */

/* {{{ mp_cmp_z(a) */

/*
  mp_cmp_z(a)

  Compare a <=> 0.  Returns <0 if a<0, 0 if a=0, >0 if a>0.
 */

int    mp_cmp_z(const mp_int *a)
{
  if(SIGN(a) == NEG)
    return MP_LT;
  else if(USED(a) == 1 && DIGIT(a, 0) == 0)
    return MP_EQ;
  else
    return MP_GT;

} /* end mp_cmp_z() */

/* }}} */

/* {{{ mp_cmp_d(a, d) */

/*
  mp_cmp_d(a, d)

  Compare a <=> d.  Returns <0 if a<d, 0 if a=d, >0 if a>d
 */

int    mp_cmp_d(const mp_int *a, mp_digit d)
{
  ARGCHK(a != NULL, MP_EQ);

  if(SIGN(a) == NEG)
    return MP_LT;

  return s_mp_cmp_d(a, d);

} /* end mp_cmp_d() */

/* }}} */

/* {{{ mp_cmp(a, b) */

int    mp_cmp(const mp_int *a, const mp_int *b)
{
  ARGCHK(a != NULL && b != NULL, MP_EQ);

  if(SIGN(a) == SIGN(b)) {
    int  mag;

    if((mag = s_mp_cmp(a, b)) == MP_EQ)
      return MP_EQ;

    if(SIGN(a) == ZPOS)
      return mag;
    else
      return -mag;

  } else if(SIGN(a) == ZPOS) {
    return MP_GT;
  } else {
    return MP_LT;
  }

} /* end mp_cmp() */

/* }}} */

/* {{{ mp_cmp_mag(a, b) */

/*
  mp_cmp_mag(a, b)

  Compares |a| <=> |b|, and returns an appropriate comparison result
 */

int    mp_cmp_mag(mp_int *a, mp_int *b)
{
  ARGCHK(a != NULL && b != NULL, MP_EQ);

  return s_mp_cmp(a, b);

} /* end mp_cmp_mag() */

/* }}} */

/* {{{ mp_cmp_int(a, z) */

/*
  This just converts z to an mp_int, and uses the existing comparison
  routines.  This is sort of inefficient, but it's not clear to me how
  frequently this wil get used anyway.  For small positive constants,
  you can always use mp_cmp_d(), and for zero, there is mp_cmp_z().
 */
int    mp_cmp_int(const mp_int *a, long z)
{
  mp_int  tmp;
  int     out;

  ARGCHK(a != NULL, MP_EQ);
  
  mp_init(&tmp); mp_set_int(&tmp, z);
  out = mp_cmp(a, &tmp);
  mp_clear(&tmp);

  return out;

} /* end mp_cmp_int() */

/* }}} */

/* {{{ mp_isodd(a) */

/*
  mp_isodd(a)

  Returns a true (non-zero) value if a is odd, false (zero) otherwise.
 */
int    mp_isodd(const mp_int *a)
{
  ARGCHK(a != NULL, 0);

  return (int)(DIGIT(a, 0) & 1);

} /* end mp_isodd() */

/* }}} */

/* {{{ mp_iseven(a) */

int    mp_iseven(const mp_int *a)
{
  return !mp_isodd(a);

} /* end mp_iseven() */

/* }}} */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ Number theoretic functions */

#if MP_NUMTH
/* {{{ mp_gcd(a, b, c) */

/*
  Like the old mp_gcd() function, except computes the GCD using the
  binary algorithm due to Josef Stein in 1961 (via Knuth).
 */
mp_err mp_gcd(mp_int *a, mp_int *b, mp_int *c)
{
  mp_err   res;
  mp_int   u, v, t;
  mp_size  k = 0;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  if(mp_cmp_z(a) == MP_EQ && mp_cmp_z(b) == MP_EQ)
      return MP_RANGE;
  if(mp_cmp_z(a) == MP_EQ) {
    return mp_copy(b, c);
  } else if(mp_cmp_z(b) == MP_EQ) {
    return mp_copy(a, c);
  }

  if((res = mp_init(&t)) != MP_OKAY)
    return res;
  if((res = mp_init_copy(&u, a)) != MP_OKAY)
    goto U;
  if((res = mp_init_copy(&v, b)) != MP_OKAY)
    goto V;

  SIGN(&u) = ZPOS;
  SIGN(&v) = ZPOS;

  /* Divide out common factors of 2 until at least 1 of a, b is even */
  while(mp_iseven(&u) && mp_iseven(&v)) {
    s_mp_div_2(&u);
    s_mp_div_2(&v);
    ++k;
  }

  /* Initialize t */
  if(mp_isodd(&u)) {
    if((res = mp_copy(&v, &t)) != MP_OKAY)
      goto CLEANUP;
    
    /* t = -v */
    if(SIGN(&v) == ZPOS)
      SIGN(&t) = NEG;
    else
      SIGN(&t) = ZPOS;
    
  } else {
    if((res = mp_copy(&u, &t)) != MP_OKAY)
      goto CLEANUP;

  }

  for(;;) {
    while(mp_iseven(&t)) {
      s_mp_div_2(&t);
    }

    if(mp_cmp_z(&t) == MP_GT) {
      if((res = mp_copy(&t, &u)) != MP_OKAY)
	goto CLEANUP;

    } else {
      if((res = mp_copy(&t, &v)) != MP_OKAY)
	goto CLEANUP;

      /* v = -t */
      if(SIGN(&t) == ZPOS)
	SIGN(&v) = NEG;
      else
	SIGN(&v) = ZPOS;
    }

    if((res = mp_sub(&u, &v, &t)) != MP_OKAY)
      goto CLEANUP;

    if(s_mp_cmp_d(&t, 0) == MP_EQ)
      break;
  }

  s_mp_2expt(&v, k);       /* v = 2^k   */
  res = mp_mul(&u, &v, c); /* c = u * v */

 CLEANUP:
  mp_clear(&v);
 V:
  mp_clear(&u);
 U:
  mp_clear(&t);

  return res;

} /* end mp_gcd() */

/* }}} */

/* {{{ mp_lcm(a, b, c) */

/* We compute the least common multiple using the rule:

   ab = [a, b](a, b)

   ... by computing the product, and dividing out the gcd.
 */

mp_err mp_lcm(mp_int *a, mp_int *b, mp_int *c)
{
  mp_int  gcd, prod;
  mp_err  res;

  ARGCHK(a != NULL && b != NULL && c != NULL, MP_BADARG);

  /* Set up temporaries */
  if((res = mp_init(&gcd)) != MP_OKAY)
    return res;
  if((res = mp_init(&prod)) != MP_OKAY)
    goto GCD;

  if((res = mp_mul(a, b, &prod)) != MP_OKAY)
    goto CLEANUP;
  if((res = mp_gcd(a, b, &gcd)) != MP_OKAY)
    goto CLEANUP;

  res = mp_div(&prod, &gcd, c, NULL);

 CLEANUP:
  mp_clear(&prod);
 GCD:
  mp_clear(&gcd);

  return res;

} /* end mp_lcm() */

/* }}} */

/* {{{ mp_xgcd(a, b, g, x, y) */

/*
  mp_xgcd(a, b, g, x, y)

  Compute g = (a, b) and values x and y satisfying Bezout's identity
  (that is, ax + by = g).  This uses the extended binary GCD algorithm
  based on the Stein algorithm used for mp_gcd()
 */

mp_err mp_xgcd(mp_int *a, mp_int *b, mp_int *g, mp_int *x, mp_int *y)
{
  mp_int   gx, xc, yc, u, v, A, B, C, D;
  mp_int  *clean[9];
  mp_err   res;
  int      last = -1;

  if(mp_cmp_z(b) == 0)
    return MP_RANGE;

  /* Initialize all these variables we need */
  if((res = mp_init(&u)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &u;
  if((res = mp_init(&v)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &v;
  if((res = mp_init(&gx)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &gx;
  if((res = mp_init(&A)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &A;
  if((res = mp_init(&B)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &B;
  if((res = mp_init(&C)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &C;
  if((res = mp_init(&D)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &D;
  if((res = mp_init_copy(&xc, a)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &xc;
  mp_abs(&xc, &xc);
  if((res = mp_init_copy(&yc, b)) != MP_OKAY) goto CLEANUP;
  clean[++last] = &yc;
  mp_abs(&yc, &yc);

  mp_set(&gx, 1);

  /* Divide by two until at least one of them is even */
  while(mp_iseven(&xc) && mp_iseven(&yc)) {
    s_mp_div_2(&xc);
    s_mp_div_2(&yc);
    if((res = s_mp_mul_2(&gx)) != MP_OKAY)
      goto CLEANUP;
  }

  mp_copy(&xc, &u);
  mp_copy(&yc, &v);
  mp_set(&A, 1); mp_set(&D, 1);

  /* Loop through binary GCD algorithm */
  for(;;) {
    while(mp_iseven(&u)) {
      s_mp_div_2(&u);

      if(mp_iseven(&A) && mp_iseven(&B)) {
	s_mp_div_2(&A); s_mp_div_2(&B);
      } else {
	if((res = mp_add(&A, &yc, &A)) != MP_OKAY) goto CLEANUP;
	s_mp_div_2(&A);
	if((res = mp_sub(&B, &xc, &B)) != MP_OKAY) goto CLEANUP;
	s_mp_div_2(&B);
      }
    }

    while(mp_iseven(&v)) {
      s_mp_div_2(&v);

      if(mp_iseven(&C) && mp_iseven(&D)) {
	s_mp_div_2(&C); s_mp_div_2(&D);
      } else {
	if((res = mp_add(&C, &yc, &C)) != MP_OKAY) goto CLEANUP;
	s_mp_div_2(&C);
	if((res = mp_sub(&D, &xc, &D)) != MP_OKAY) goto CLEANUP;
	s_mp_div_2(&D);
      }
    }

    if(mp_cmp(&u, &v) >= 0) {
      if((res = mp_sub(&u, &v, &u)) != MP_OKAY) goto CLEANUP;
      if((res = mp_sub(&A, &C, &A)) != MP_OKAY) goto CLEANUP;
      if((res = mp_sub(&B, &D, &B)) != MP_OKAY) goto CLEANUP;

    } else {
      if((res = mp_sub(&v, &u, &v)) != MP_OKAY) goto CLEANUP;
      if((res = mp_sub(&C, &A, &C)) != MP_OKAY) goto CLEANUP;
      if((res = mp_sub(&D, &B, &D)) != MP_OKAY) goto CLEANUP;

    }

    /* If we're done, copy results to output */
    if(mp_cmp_z(&u) == 0) {
      if(x)
	if((res = mp_copy(&C, x)) != MP_OKAY) goto CLEANUP;

      if(y)
	if((res = mp_copy(&D, y)) != MP_OKAY) goto CLEANUP;
      
      if(g)
	if((res = mp_mul(&gx, &v, g)) != MP_OKAY) goto CLEANUP;

      break;
    }
  }

 CLEANUP:
  while(last >= 0)
    mp_clear(clean[last--]);

  return res;

} /* end mp_xgcd() */

/* }}} */

/* Given a and prime p, computes c and k such that a*c == 2**k (mod p).
** Returns k (positive) or error (negative).
** This technique from the paper "Fast Modular Reciprocals" (unpublished)
** by Richard Schroeppel (a.k.a. Captain Nemo).
*/
mp_err s_mp_almost_inverse(const mp_int *a, const mp_int *p, mp_int *c)
{
  mp_err res;
  mp_err k    = 0;
  mp_int d, f, g;

  ARGCHK(a && p && c, MP_BADARG);

  MP_DIGITS(&d) = 0;
  MP_DIGITS(&f) = 0;
  MP_DIGITS(&g) = 0;
  MP_CHECKOK( mp_init(&d) );
  MP_CHECKOK( mp_init_copy(&f, a) );	/* f = a */
  MP_CHECKOK( mp_init_copy(&g, p) );	/* g = p */

  mp_set(c, 1);
  mp_zero(&d);

  if (mp_cmp_z(&f) == 0) {
    res = MP_UNDEF;
  } else 
  for (;;) {
    int diff_sign;
    while (mp_iseven(&f)) {
      s_mp_div_2d(&f, 1);
      MP_CHECKOK( s_mp_mul_2d(&d, 1) );
      ++k;
    }
    if (mp_cmp_d(&f, 1) == MP_EQ) {	/* f == 1 */
      res = k;
      break;
    }
    diff_sign = mp_cmp(&f, &g);
    if (diff_sign < 0) {		/* f < g */
      s_mp_exch(&f, &g);
      s_mp_exch(c, &d);
    } else if (diff_sign == 0) {		/* f == g */
      res = MP_UNDEF;		/* a and p are not relatively prime */
      break;
    }
    if ((MP_DIGIT(&f,0) % 4) == (MP_DIGIT(&g,0) % 4)) {
      MP_CHECKOK( mp_sub(&f, &g, &f) );	/* f = f - g */
      MP_CHECKOK( mp_sub(c,  &d,  c) );	/* c = c - d */
    } else {
      MP_CHECKOK( mp_add(&f, &g, &f) );	/* f = f + g */
      MP_CHECKOK( mp_add(c,  &d,  c) );	/* c = c + d */
    }
  }
  if (res >= 0) {
    while (MP_SIGN(c) != MP_ZPOS) {
      MP_CHECKOK( mp_add(c, p, c) );
    }
    res = k;
  }

CLEANUP:
  mp_clear(&d);
  mp_clear(&f);
  mp_clear(&g);
  return res;
}

/* Compute T = (P ** -1) mod (2 ** 32).  Also works for 16-bit mp_digits.
** This technique from the paper "Fast Modular Reciprocals" (unpublished)
** by Richard Schroeppel (a.k.a. Captain Nemo).
*/
mp_digit  s_mp_invmod_radix(mp_digit P)
{
  mp_digit T = P;
  T *= 2 - (P * T);
  T *= 2 - (P * T);
  T *= 2 - (P * T);
  T *= 2 - (P * T);
#if MP_DIGIT_MAX > MP_32BIT_MAX
  T *= 2 - (P * T);
  T *= 2 - (P * T);
#endif
  return T;
}

/* Given c, k, and prime p, where a*c == 2**k (mod p), 
** Compute x = (a ** -1) mod p.  This is similar to Montgomery reduction.
** This technique from the paper "Fast Modular Reciprocals" (unpublished)
** by Richard Schroeppel (a.k.a. Captain Nemo).
*/
mp_err  s_mp_fixup_reciprocal(const mp_int *c, const mp_int *p, int k, mp_int *x)
{
  int      k_orig = k;
  mp_digit r;
  mp_size  ix;
  mp_err   res;

  if (mp_cmp_z(c) < 0) {		/* c < 0 */
    MP_CHECKOK( mp_add(c, p, x) );	/* x = c + p */
  } else {
    MP_CHECKOK( mp_copy(c, x) );	/* x = c */
  }

  /* make sure x is large enough */
  ix = MP_HOWMANY(k, MP_DIGIT_BIT) + MP_USED(p) + 1;
  ix = MP_MAX(ix, MP_USED(x));
  MP_CHECKOK( s_mp_pad(x, ix) );

  r = 0 - s_mp_invmod_radix(MP_DIGIT(p,0));

  for (ix = 0; k > 0; ix++) {
    int      j = MP_MIN(k, MP_DIGIT_BIT);
    mp_digit v = r * MP_DIGIT(x, ix);
    if (j < MP_DIGIT_BIT) {
      v &= ((mp_digit)1 << j) - 1;	/* v = v mod (2 ** j) */
    }
    s_mp_mul_d_add_offset(p, v, x, ix); /* x += p * v * (RADIX ** ix) */
    k -= j;
  }
  s_mp_clamp(x);
  s_mp_div_2d(x, k_orig);
  res = MP_OKAY;

CLEANUP:
  return res;
}

/* {{{ mp_invmod(a, m, c) */

/*
  mp_invmod(a, m, c)

  Compute c = a^-1 (mod m), if there is an inverse for a (mod m).
  This is equivalent to the question of whether (a, m) = 1.  If not,
  MP_UNDEF is returned, and there is no inverse.
 */

mp_err mp_invmod(mp_int *a, mp_int *m, mp_int *c)
{
  mp_int  g, x;
  mp_err  res;

  ARGCHK(a && m && c, MP_BADARG);

  if(mp_cmp_z(a) == 0 || mp_cmp_z(m) == 0)
    return MP_RANGE;

  MP_DIGITS(&g) = 0;
  MP_DIGITS(&x) = 0;

  if (mp_isodd(m)) {
    int k;

    if (a == c) {
      if ((res = mp_init_copy(&x, a)) != MP_OKAY)
	return res;
      if (a == m) 
	m = &x;
      a = &x;
    } else if (m == c) {
      if ((res = mp_init_copy(&x, m)) != MP_OKAY)
	return res;
      m = &x;
    } else {
      MP_DIGITS(&x) = 0;
    }

    MP_CHECKOK( s_mp_almost_inverse(a, m, c) );
    k = res;
    MP_CHECKOK( s_mp_fixup_reciprocal(c, m, k, c) );
    goto CLEANUP;
  }

  MP_CHECKOK( mp_init(&x) );
  MP_CHECKOK( mp_init(&g) );

  MP_CHECKOK( mp_xgcd(a, m, &g, &x, NULL) );

  if(mp_cmp_d(&g, 1) != MP_EQ) {
    res = MP_UNDEF;
    goto CLEANUP;
  }

  res = mp_mod(&x, m, c);
  SIGN(c) = SIGN(a);

CLEANUP:
  mp_clear(&x);
  mp_clear(&g);

  return res;

} /* end mp_invmod() */

/* }}} */
#endif /* if MP_NUMTH */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ mp_print(mp, ofp) */

#if MP_IOFUNC
/*
  mp_print(mp, ofp)

  Print a textual representation of the given mp_int on the output
  stream 'ofp'.  Output is generated using the internal radix.
 */

void   mp_print(mp_int *mp, FILE *ofp)
{
  int   ix;

  if(mp == NULL || ofp == NULL)
    return;

  fputc((SIGN(mp) == NEG) ? '-' : '+', ofp);

  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    fprintf(ofp, DIGIT_FMT, DIGIT(mp, ix));
  }

} /* end mp_print() */

#endif /* if MP_IOFUNC */

/* }}} */

/*------------------------------------------------------------------------*/
/* {{{ More I/O Functions */

/* {{{ mp_read_raw(mp, str, len) */

/* 
   mp_read_raw(mp, str, len)

   Read in a raw value (base 256) into the given mp_int
 */

mp_err  mp_read_raw(mp_int *mp, char *str, int len)
{
  int            ix;
  mp_err         res;
  unsigned char *ustr = (unsigned char *)str;

  ARGCHK(mp != NULL && str != NULL && len > 0, MP_BADARG);

  mp_zero(mp);

  /* Get sign from first byte */
  if(ustr[0])
    SIGN(mp) = NEG;
  else
    SIGN(mp) = ZPOS;

  /* Read the rest of the digits */
  for(ix = 1; ix < len; ix++) {
#if DIGIT_MAX < 256
    if((res = s_mp_lshd(mp, 1)) != MP_OKAY)
      return res;
#else
    if((res = mp_mul_d(mp, 256, mp)) != MP_OKAY)
      return res;
#endif
    if((res = mp_add_d(mp, ustr[ix], mp)) != MP_OKAY)
      return res;
  }

  return MP_OKAY;

} /* end mp_read_raw() */

/* }}} */

/* {{{ mp_raw_size(mp) */

int    mp_raw_size(mp_int *mp)
{
  ARGCHK(mp != NULL, 0);

  return (USED(mp) * sizeof(mp_digit)) + 1;

} /* end mp_raw_size() */

/* }}} */

/* {{{ mp_toraw(mp, str) */

mp_err mp_toraw(mp_int *mp, char *str)
{
  int  ix, jx, pos = 1;

  ARGCHK(mp != NULL && str != NULL, MP_BADARG);

  str[0] = (char)SIGN(mp);

  /* Iterate over each digit... */
  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    mp_digit  d = DIGIT(mp, ix);

    /* Unpack digit bytes, high order first */
    for(jx = sizeof(mp_digit) - 1; jx >= 0; jx--) {
      str[pos++] = (char)(d >> (jx * CHAR_BIT));
    }
  }

  return MP_OKAY;

} /* end mp_toraw() */

/* }}} */

/* {{{ mp_read_radix(mp, str, radix) */

/*
  mp_read_radix(mp, str, radix)

  Read an integer from the given string, and set mp to the resulting
  value.  The input is presumed to be in base 10.  Leading non-digit
  characters are ignored, and the function reads until a non-digit
  character or the end of the string.
 */

mp_err  mp_read_radix(mp_int *mp, char *str, int radix)
{
  int     ix = 0, val = 0;
  mp_err  res;
  mp_sign sig = ZPOS;

  ARGCHK(mp != NULL && str != NULL && radix >= 2 && radix <= MAX_RADIX, 
	 MP_BADARG);

  mp_zero(mp);

  /* Skip leading non-digit characters until a digit or '-' or '+' */
  while(str[ix] && 
	(s_mp_tovalue(str[ix], radix) < 0) && 
	str[ix] != '-' &&
	str[ix] != '+') {
    ++ix;
  }

  if(str[ix] == '-') {
    sig = NEG;
    ++ix;
  } else if(str[ix] == '+') {
    sig = ZPOS; /* this is the default anyway... */
    ++ix;
  }

  while((val = s_mp_tovalue(str[ix], radix)) >= 0) {
    if((res = s_mp_mul_d(mp, radix)) != MP_OKAY)
      return res;
    if((res = s_mp_add_d(mp, val)) != MP_OKAY)
      return res;
    ++ix;
  }

  if(s_mp_cmp_d(mp, 0) == MP_EQ)
    SIGN(mp) = ZPOS;
  else
    SIGN(mp) = sig;

  return MP_OKAY;

} /* end mp_read_radix() */

/* }}} */

/* {{{ mp_radix_size(mp, radix) */

int    mp_radix_size(mp_int *mp, int radix)
{
  int  bits;

  if(!mp || radix < 2 || radix > MAX_RADIX)
    return 0;

  bits = USED(mp) * DIGIT_BIT - 1;
 
  return s_mp_outlen(bits, radix);

} /* end mp_radix_size() */

/* }}} */

/* {{{ mp_toradix(mp, str, radix) */

mp_err mp_toradix(mp_int *mp, char *str, int radix)
{
  int  ix, pos = 0;

  ARGCHK(mp != NULL && str != NULL, MP_BADARG);
  ARGCHK(radix > 1 && radix <= MAX_RADIX, MP_RANGE);

  if(mp_cmp_z(mp) == MP_EQ) {
    str[0] = '0';
    str[1] = '\0';
  } else {
    mp_err   res;
    mp_int   tmp;
    mp_sign  sgn;
    mp_digit rem, rdx = (mp_digit)radix;
    char     ch;

    if((res = mp_init_copy(&tmp, mp)) != MP_OKAY)
      return res;

    /* Save sign for later, and take absolute value */
    sgn = SIGN(&tmp); SIGN(&tmp) = ZPOS;

    /* Generate output digits in reverse order      */
    while(mp_cmp_z(&tmp) != 0) {
      if((res = mp_div_d(&tmp, rdx, &tmp, &rem)) != MP_OKAY) {
	mp_clear(&tmp);
	return res;
      }

      /* Generate digits, use capital letters */
      ch = s_mp_todigit(rem, radix, 0);

      str[pos++] = ch;
    }

    /* Add - sign if original value was negative */
    if(sgn == NEG)
      str[pos++] = '-';

    /* Add trailing NUL to end the string        */
    str[pos--] = '\0';

    /* Reverse the digits and sign indicator     */
    ix = 0;
    while(ix < pos) {
      char tmp = str[ix];

      str[ix] = str[pos];
      str[pos] = tmp;
      ++ix;
      --pos;
    }
    
    mp_clear(&tmp);
  }

  return MP_OKAY;

} /* end mp_toradix() */

/* }}} */

/* {{{ mp_tovalue(ch, r) */

int    mp_tovalue(char ch, int r)
{
  return s_mp_tovalue(ch, r);

} /* end mp_tovalue() */

/* }}} */

/* }}} */

/* {{{ mp_strerror(ec) */

/*
  mp_strerror(ec)

  Return a string describing the meaning of error code 'ec'.  The
  string returned is allocated in static memory, so the caller should
  not attempt to modify or free the memory associated with this
  string.
 */
const char  *mp_strerror(mp_err ec)
{
  int   aec = (ec < 0) ? -ec : ec;

  /* Code values are negative, so the senses of these comparisons
     are accurate */
  if(ec < MP_LAST_CODE || ec > MP_OKAY) {
    return mp_err_string[0];  /* unknown error code */
  } else {
    return mp_err_string[aec + 1];
  }

} /* end mp_strerror() */

/* }}} */

/*========================================================================*/
/*------------------------------------------------------------------------*/
/* Static function definitions (internal use only)                        */

/* {{{ Memory management */

/* {{{ s_mp_grow(mp, min) */

/* Make sure there are at least 'min' digits allocated to mp              */
mp_err   s_mp_grow(mp_int *mp, mp_size min)
{
  if(min > ALLOC(mp)) {
    mp_digit   *tmp;

    /* Set min to next nearest default precision block size */
    min = MP_ROUNDUP(min, s_mp_defprec);

    if((tmp = s_mp_alloc(min, sizeof(mp_digit))) == NULL)
      return MP_MEM;

    s_mp_copy(DIGITS(mp), tmp, USED(mp));

#if MP_CRYPTO
    s_mp_setz(DIGITS(mp), ALLOC(mp));
#endif
    s_mp_free(DIGITS(mp));
    DIGITS(mp) = tmp;
    ALLOC(mp) = min;
  }

  return MP_OKAY;

} /* end s_mp_grow() */

/* }}} */

/* {{{ s_mp_pad(mp, min) */

/* Make sure the used size of mp is at least 'min', growing if needed     */
mp_err   s_mp_pad(mp_int *mp, mp_size min)
{
  if(min > USED(mp)) {
    mp_err  res;

    /* Make sure there is room to increase precision  */
    if (min > ALLOC(mp)) {
      if ((res = s_mp_grow(mp, min)) != MP_OKAY)
	return res;
    } else {
/*    s_mp_setz(DIGITS(mp) + USED(mp), min - USED(mp)); */
    }

    /* Increase precision; should already be 0-filled */
    USED(mp) = min;
  }

  return MP_OKAY;

} /* end s_mp_pad() */

/* }}} */

/* {{{ s_mp_setz(dp, count) */

#if MP_MACRO == 0
/* Set 'count' digits pointed to by dp to be zeroes                       */
void s_mp_setz(mp_digit *dp, mp_size count)
{
#if MP_MEMSET == 0
  int  ix;

  for(ix = 0; ix < count; ix++)
    dp[ix] = 0;
#else
  memset(dp, 0, count * sizeof(mp_digit));
#endif

} /* end s_mp_setz() */
#endif

/* }}} */

/* {{{ s_mp_copy(sp, dp, count) */

#if MP_MACRO == 0
/* Copy 'count' digits from sp to dp                                      */
void s_mp_copy(const mp_digit *sp, mp_digit *dp, mp_size count)
{
#if MP_MEMCPY == 0
  int  ix;

  for(ix = 0; ix < count; ix++)
    dp[ix] = sp[ix];
#else
  memcpy(dp, sp, count * sizeof(mp_digit));
#endif

} /* end s_mp_copy() */
#endif

/* }}} */

/* {{{ s_mp_alloc(nb, ni) */

#if MP_MACRO == 0
/* Allocate ni records of nb bytes each, and return a pointer to that     */
void    *s_mp_alloc(size_t nb, size_t ni)
{
  ++mp_allocs;
  return calloc(nb, ni);

} /* end s_mp_alloc() */
#endif

/* }}} */

/* {{{ s_mp_free(ptr) */

#if MP_MACRO == 0
/* Free the memory pointed to by ptr                                      */
void     s_mp_free(void *ptr)
{
  if(ptr) {
    ++mp_frees;
    free(ptr);
  }
} /* end s_mp_free() */
#endif

/* }}} */

/* {{{ s_mp_clamp(mp) */

#if MP_MACRO == 0
/* Remove leading zeroes from the given value                             */
void     s_mp_clamp(mp_int *mp)
{
  mp_size used = MP_USED(mp);
  while (used > 1 && DIGIT(mp, used - 1) == 0)
    --used;
  MP_USED(mp) = used;
} /* end s_mp_clamp() */
#endif

/* }}} */

/* {{{ s_mp_exch(a, b) */

/* Exchange the data for a and b; (b, a) = (a, b)                         */
void     s_mp_exch(mp_int *a, mp_int *b)
{
  mp_int   tmp;

  tmp = *a;
  *a = *b;
  *b = tmp;

} /* end s_mp_exch() */

/* }}} */

/* }}} */

/* {{{ Arithmetic helpers */

/* {{{ s_mp_lshd(mp, p) */

/* 
   Shift mp leftward by p digits, growing if needed, and zero-filling
   the in-shifted digits at the right end.  This is a convenient
   alternative to multiplication by powers of the radix
   The value of USED(mp) must already have been set to the value for
   the shifted result.
 */   

mp_err   s_mp_lshd(mp_int *mp, mp_size p)
{
  mp_err  res;
  mp_size pos;
  int     ix;

  if(p == 0)
    return MP_OKAY;

  if (MP_USED(mp) == 1 && MP_DIGIT(mp, 0) == 0)
    return MP_OKAY;

  if((res = s_mp_pad(mp, USED(mp) + p)) != MP_OKAY)
    return res;

  pos = USED(mp) - 1;

  /* Shift all the significant figures over as needed */
  for(ix = pos - p; ix >= 0; ix--) 
    DIGIT(mp, ix + p) = DIGIT(mp, ix);

  /* Fill the bottom digits with zeroes */
  for(ix = 0; ix < p; ix++)
    DIGIT(mp, ix) = 0;

  return MP_OKAY;

} /* end s_mp_lshd() */

/* }}} */

/* {{{ s_mp_mul_2d(mp, d) */

/*
  Multiply the integer by 2^d, where d is a number of bits.  This
  amounts to a bitwise shift of the value.
 */
mp_err   s_mp_mul_2d(mp_int *mp, mp_digit d)
{
  mp_err   res;
  mp_digit dshift, bshift;
  mp_digit mask;

  ARGCHK(mp != NULL,  MP_BADARG);

  dshift = d / MP_DIGIT_BIT;
  bshift = d % MP_DIGIT_BIT;
  /* bits to be shifted out of the top word */
  mask   = ((mp_digit)~0 << (MP_DIGIT_BIT - bshift)); 
  mask  &= MP_DIGIT(mp, MP_USED(mp) - 1);

  if (MP_OKAY != (res = s_mp_pad(mp, MP_USED(mp) + dshift + (mask != 0) )))
    return res;

  if (dshift && MP_OKAY != (res = s_mp_lshd(mp, dshift)))
    return res;

  if (bshift) { 
    mp_digit *pa = MP_DIGITS(mp);
    mp_digit *alim = pa + MP_USED(mp);
    mp_digit  prev = 0;

    for (pa += dshift; pa < alim; ) {
      mp_digit x = *pa;
      *pa++ = (x << bshift) | prev;
      prev = x >> (DIGIT_BIT - bshift);
    }
  }

  s_mp_clamp(mp);
  return MP_OKAY;
} /* end s_mp_mul_2d() */

/* {{{ s_mp_rshd(mp, p) */

/* 
   Shift mp rightward by p digits.  Maintains the invariant that
   digits above the precision are all zero.  Digits shifted off the
   end are lost.  Cannot fail.
 */

void     s_mp_rshd(mp_int *mp, mp_size p)
{
  mp_size  ix;
  mp_digit *src, *dst;

  if(p == 0)
    return;

  /* Shortcut when all digits are to be shifted off */
  if(p >= USED(mp)) {
    s_mp_setz(DIGITS(mp), ALLOC(mp));
    USED(mp) = 1;
    SIGN(mp) = ZPOS;
    return;
  }

  /* Shift all the significant figures over as needed */
  dst = MP_DIGITS(mp);
  src = dst + p;
  for (ix = USED(mp) - p; ix > 0; ix--)
    *dst++ = *src++;

  MP_USED(mp) -= p;
  /* Fill the top digits with zeroes */
  while (p-- > 0)
    *dst++ = 0;

#if 0
  /* Strip off any leading zeroes    */
  s_mp_clamp(mp);
#endif

} /* end s_mp_rshd() */

/* }}} */

/* {{{ s_mp_div_2(mp) */

/* Divide by two -- take advantage of radix properties to do it fast      */
void     s_mp_div_2(mp_int *mp)
{
  s_mp_div_2d(mp, 1);

} /* end s_mp_div_2() */

/* }}} */

/* {{{ s_mp_mul_2(mp) */

mp_err s_mp_mul_2(mp_int *mp)
{
  mp_digit *pd;
  int      ix, used;
  mp_digit kin = 0;

  /* Shift digits leftward by 1 bit */
  used = MP_USED(mp);
  pd = MP_DIGITS(mp);
  for (ix = 0; ix < used; ix++) {
    mp_digit d = *pd;
    *pd++ = (d << 1) | kin;
    kin = (d >> (DIGIT_BIT - 1));
  }

  /* Deal with rollover from last digit */
  if (kin) {
    if (ix >= ALLOC(mp)) {
      mp_err res;
      if((res = s_mp_grow(mp, ALLOC(mp) + 1)) != MP_OKAY)
	return res;
    }

    DIGIT(mp, ix) = kin;
    USED(mp) += 1;
  }

  return MP_OKAY;

} /* end s_mp_mul_2() */

/* }}} */

/* {{{ s_mp_mod_2d(mp, d) */

/*
  Remainder the integer by 2^d, where d is a number of bits.  This
  amounts to a bitwise AND of the value, and does not require the full
  division code
 */
void     s_mp_mod_2d(mp_int *mp, mp_digit d)
{
  mp_size  ndig = (d / DIGIT_BIT), nbit = (d % DIGIT_BIT);
  mp_size  ix;
  mp_digit dmask;

  if(ndig >= USED(mp))
    return;

  /* Flush all the bits above 2^d in its digit */
  dmask = ((mp_digit)1 << nbit) - 1;
  DIGIT(mp, ndig) &= dmask;

  /* Flush all digits above the one with 2^d in it */
  for(ix = ndig + 1; ix < USED(mp); ix++)
    DIGIT(mp, ix) = 0;

  s_mp_clamp(mp);

} /* end s_mp_mod_2d() */

/* }}} */

/* {{{ s_mp_div_2d(mp, d) */

/*
  Divide the integer by 2^d, where d is a number of bits.  This
  amounts to a bitwise shift of the value, and does not require the
  full division code (used in Barrett reduction, see below)
 */
void     s_mp_div_2d(mp_int *mp, mp_digit d)
{
  int       ix;
  mp_digit  save, next, mask;

  s_mp_rshd(mp, d / DIGIT_BIT);
  d %= DIGIT_BIT;
  if (d) {
    mask = ((mp_digit)1 << d) - 1;
    save = 0;
    for(ix = USED(mp) - 1; ix >= 0; ix--) {
      next = DIGIT(mp, ix) & mask;
      DIGIT(mp, ix) = (DIGIT(mp, ix) >> d) | (save << (DIGIT_BIT - d));
      save = next;
    }
  }
  s_mp_clamp(mp);

} /* end s_mp_div_2d() */

/* }}} */

/* {{{ s_mp_norm(a, b, *d) */

/*
  s_mp_norm(a, b, *d)

  Normalize a and b for division, where b is the divisor.  In order
  that we might make good guesses for quotient digits, we want the
  leading digit of b to be at least half the radix, which we
  accomplish by multiplying a and b by a power of 2.  The exponent 
  (shift count) is placed in *pd, so that the remainder can be shifted 
  back at the end of the division process.
 */

mp_err   s_mp_norm(mp_int *a, mp_int *b, mp_digit *pd)
{
  mp_digit  d;
  mp_digit  mask;
  mp_digit  b_msd;
  mp_err    res    = MP_OKAY;

  d = 0;
  mask  = DIGIT_MAX & ~(DIGIT_MAX >> 1);	/* mask is msb of digit */
  b_msd = DIGIT(b, USED(b) - 1);
  while (!(b_msd & mask)) {
    b_msd <<= 1;
    ++d;
  }

  if (d) {
    MP_CHECKOK( s_mp_mul_2d(a, d) );
    MP_CHECKOK( s_mp_mul_2d(b, d) );
  }

  *pd = d;
CLEANUP:
  return res;

} /* end s_mp_norm() */

/* }}} */

/* }}} */

/* {{{ Primitive digit arithmetic */

/* {{{ s_mp_add_d(mp, d) */

/* Add d to |mp| in place                                                 */
mp_err   s_mp_add_d(mp_int *mp, mp_digit d)    /* unsigned digit addition */
{
#if !defined(MP_NO_MP_WORD)
  mp_word   w, k = 0;
  mp_size   ix = 1;

  w = (mp_word)DIGIT(mp, 0) + d;
  DIGIT(mp, 0) = ACCUM(w);
  k = CARRYOUT(w);

  while(ix < USED(mp) && k) {
    w = (mp_word)DIGIT(mp, ix) + k;
    DIGIT(mp, ix) = ACCUM(w);
    k = CARRYOUT(w);
    ++ix;
  }

  if(k != 0) {
    mp_err  res;

    if((res = s_mp_pad(mp, USED(mp) + 1)) != MP_OKAY)
      return res;

    DIGIT(mp, ix) = (mp_digit)k;
  }

  return MP_OKAY;
#else
  mp_digit * pmp = MP_DIGITS(mp);
  mp_digit sum, mp_i, carry = 0;
  mp_err   res = MP_OKAY;
  int used = (int)MP_USED(mp);

  mp_i = *pmp;
  *pmp++ = sum = d + mp_i;
  carry = (sum < d);
  while (carry && --used > 0) {
    mp_i = *pmp;
    *pmp++ = sum = carry + mp_i;
    carry = !sum;
  }
  if (carry && !used) {
    /* mp is growing */
    used = MP_USED(mp);
    MP_CHECKOK( s_mp_pad(mp, used + 1) );
    MP_DIGIT(mp, used) = carry;
  }
CLEANUP:
  return res;
#endif
} /* end s_mp_add_d() */

/* }}} */

/* {{{ s_mp_sub_d(mp, d) */

/* Subtract d from |mp| in place, assumes |mp| > d                        */
mp_err   s_mp_sub_d(mp_int *mp, mp_digit d)    /* unsigned digit subtract */
{
#if !defined(MP_NO_MP_WORD)
  mp_word   w, b = 0;
  mp_size   ix = 1;

  /* Compute initial subtraction    */
  w = (RADIX + (mp_word)DIGIT(mp, 0)) - d;
  b = CARRYOUT(w) ? 0 : 1;
  DIGIT(mp, 0) = ACCUM(w);

  /* Propagate borrows leftward     */
  while(b && ix < USED(mp)) {
    w = (RADIX + (mp_word)DIGIT(mp, ix)) - b;
    b = CARRYOUT(w) ? 0 : 1;
    DIGIT(mp, ix) = ACCUM(w);
    ++ix;
  }

  /* Remove leading zeroes          */
  s_mp_clamp(mp);

  /* If we have a borrow out, it's a violation of the input invariant */
  if(b)
    return MP_RANGE;
  else
    return MP_OKAY;
#else
  mp_digit *pmp = MP_DIGITS(mp);
  mp_digit mp_i, diff, borrow;
  mp_size  used = MP_USED(mp);

  mp_i = *pmp;
  *pmp++ = diff = mp_i - d;
  borrow = (diff > mp_i);
  while (borrow && --used) {
    mp_i = *pmp;
    *pmp++ = diff = mp_i - borrow;
    borrow = (diff > mp_i);
  }
  s_mp_clamp(mp);
  return (borrow && !used) ? MP_RANGE : MP_OKAY;
#endif
} /* end s_mp_sub_d() */

/* }}} */

/* {{{ s_mp_mul_d(a, d) */

/* Compute a = a * d, single digit multiplication                         */
mp_err   s_mp_mul_d(mp_int *a, mp_digit d)
{
  mp_err  res;
  mp_size used;
  int     pow;

  if (!d) {
    mp_zero(a);
    return MP_OKAY;
  }
  if (d == 1)
    return MP_OKAY;
  if (0 <= (pow = s_mp_ispow2d(d))) {
    return s_mp_mul_2d(a, (mp_digit)pow);
  }

  used = MP_USED(a);
  MP_CHECKOK( s_mp_pad(a, used + 1) );

  s_mpv_mul_d(MP_DIGITS(a), used, d, MP_DIGITS(a));

  s_mp_clamp(a);

CLEANUP:
  return res;
  
} /* end s_mp_mul_d() */

/* }}} */

/* {{{ s_mp_div_d(mp, d, r) */

/*
  s_mp_div_d(mp, d, r)

  Compute the quotient mp = mp / d and remainder r = mp mod d, for a
  single digit d.  If r is null, the remainder will be discarded.
 */

mp_err   s_mp_div_d(mp_int *mp, mp_digit d, mp_digit *r)
{
#if !defined(MP_NO_MP_WORD)
  mp_word   w = 0, q;
#else
  mp_digit  w, q;
#endif
  int       ix;
  mp_err    res;
  mp_int    quot;
  mp_int    rem;

  if(d == 0)
    return MP_RANGE;
  if (d == 1) {
    if (r)
      *r = 0;
    return MP_OKAY;
  }
  /* could check for power of 2 here, but mp_div_d does that. */
  if (MP_USED(mp) == 1) {
    mp_digit n   = MP_DIGIT(mp,0);
    mp_digit rem;

    q   = n / d;
    rem = n % d;
    MP_DIGIT(mp,0) = q;
    if (r)
      *r = rem;
    return MP_OKAY;
  }

  MP_DIGITS(&rem)  = 0;
  MP_DIGITS(&quot) = 0;
  /* Make room for the quotient */
  MP_CHECKOK( mp_init_size(&quot, USED(mp)) );

#if !defined(MP_NO_MP_WORD)
  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    w = (w << DIGIT_BIT) | DIGIT(mp, ix);

    if(w >= d) {
      q = w / d;
      w = w % d;
    } else {
      q = 0;
    }

    s_mp_lshd(&quot, 1);
    DIGIT(&quot, 0) = (mp_digit)q;
  }
#else
  {
    mp_digit norm, p;

    MP_CHECKOK( mp_init_copy(&rem, mp) );

#if !defined(MP_ASSEMBLY_DIV_2DX1D)
    MP_DIGIT(&quot, 0) = d;
    MP_CHECKOK( s_mp_norm(&rem, &quot, &norm) );
    if (norm)
      d <<= norm;
    MP_DIGIT(&quot, 0) = 0;
#endif

    p = 0;
    for (ix = USED(&rem) - 1; ix >= 0; ix--) {
      w = DIGIT(&rem, ix);

      if (p) {
        MP_CHECKOK( s_mpv_div_2dx1d(p, w, d, &q, &w) );
      } else if (w >= d) {
	q = w / d;
	w = w % d;
      } else {
	q = 0;
      }

      MP_CHECKOK( s_mp_lshd(&quot, 1) );
      DIGIT(&quot, 0) = q;
      p = w;
    }
#if !defined(MP_ASSEMBLY_DIV_2DX1D)
    if (norm)
      w >>= norm;
#endif
  }
#endif

  /* Deliver the remainder, if desired */
  if(r)
    *r = (mp_digit)w;

  s_mp_clamp(&quot);
  mp_exch(&quot, mp);
CLEANUP:
  mp_clear(&quot);
  mp_clear(&rem);

  return res;
} /* end s_mp_div_d() */

/* }}} */


/* }}} */

/* {{{ Primitive full arithmetic */

/* {{{ s_mp_add(a, b) */

/* Compute a = |a| + |b|                                                  */
mp_err   s_mp_add(mp_int *a, const mp_int *b)  /* magnitude addition      */
{
#if !defined(MP_NO_MP_WORD)
  mp_word   w = 0;
#else
  mp_digit  d, sum, carry = 0;
#endif
  mp_digit *pa, *pb;
  mp_size   ix;
  mp_size   used;
  mp_err    res;

  /* Make sure a has enough precision for the output value */
  if((USED(b) > USED(a)) && (res = s_mp_pad(a, USED(b))) != MP_OKAY)
    return res;

  /*
    Add up all digits up to the precision of b.  If b had initially
    the same precision as a, or greater, we took care of it by the
    padding step above, so there is no problem.  If b had initially
    less precision, we'll have to make sure the carry out is duly
    propagated upward among the higher-order digits of the sum.
   */
  pa = MP_DIGITS(a);
  pb = MP_DIGITS(b);
  used = MP_USED(b);
  for(ix = 0; ix < used; ix++) {
#if !defined(MP_NO_MP_WORD)
    w = w + *pa + *pb++;
    *pa++ = ACCUM(w);
    w = CARRYOUT(w);
#else
    d = *pa;
    sum = d + *pb++;
    d = (sum < d);			/* detect overflow */
    *pa++ = sum += carry;
    carry = d + (sum < carry);		/* detect overflow */
#endif
  }

  /* If we run out of 'b' digits before we're actually done, make
     sure the carries get propagated upward...  
   */
  used = MP_USED(a);
#if !defined(MP_NO_MP_WORD)
  while (w && ix < used) {
    w = w + *pa;
    *pa++ = ACCUM(w);
    w = CARRYOUT(w);
    ++ix;
  }
#else
  while (carry && ix < used) {
    sum = carry + *pa;
    *pa++ = sum;
    carry = !sum;
    ++ix;
  }
#endif

  /* If there's an overall carry out, increase precision and include
     it.  We could have done this initially, but why touch the memory
     allocator unless we're sure we have to?
   */
#if !defined(MP_NO_MP_WORD)
  if (w) {
    if((res = s_mp_pad(a, used + 1)) != MP_OKAY)
      return res;

    DIGIT(a, ix) = (mp_digit)w;
  }
#else
  if (carry) {
    if((res = s_mp_pad(a, used + 1)) != MP_OKAY)
      return res;

    DIGIT(a, used) = carry;
  }
#endif

  return MP_OKAY;
} /* end s_mp_add() */

/* }}} */

/* Compute c = |a| + |b|         */ /* magnitude addition      */
mp_err   s_mp_add_3arg(const mp_int *a, const mp_int *b, mp_int *c)  
{
  mp_digit *pa, *pb, *pc;
#if !defined(MP_NO_MP_WORD)
  mp_word   w = 0;
#else
  mp_digit  sum, carry = 0, d;
#endif
  mp_size   ix;
  mp_size   used;
  mp_err    res;

  MP_SIGN(c) = MP_SIGN(a);
  if (MP_USED(a) < MP_USED(b)) {
    const mp_int *xch = a;
    a = b;
    b = xch;
  }

  /* Make sure a has enough precision for the output value */
  if (MP_OKAY != (res = s_mp_pad(c, MP_USED(a))))
    return res;

  /*
    Add up all digits up to the precision of b.  If b had initially
    the same precision as a, or greater, we took care of it by the
    exchange step above, so there is no problem.  If b had initially
    less precision, we'll have to make sure the carry out is duly
    propagated upward among the higher-order digits of the sum.
   */
  pa = MP_DIGITS(a);
  pb = MP_DIGITS(b);
  pc = MP_DIGITS(c);
  used = MP_USED(b);
  for (ix = 0; ix < used; ix++) {
#if !defined(MP_NO_MP_WORD)
    w = w + *pa++ + *pb++;
    *pc++ = ACCUM(w);
    w = CARRYOUT(w);
#else
    d = *pa++;
    sum = d + *pb++;
    d = (sum < d);			/* detect overflow */
    *pc++ = sum += carry;
    carry = d + (sum < carry);		/* detect overflow */
#endif
  }

  /* If we run out of 'b' digits before we're actually done, make
     sure the carries get propagated upward...  
   */
  for (used = MP_USED(a); ix < used; ++ix) {
#if !defined(MP_NO_MP_WORD)
    w = w + *pa++;
    *pc++ = ACCUM(w);
    w = CARRYOUT(w);
#else
    *pc++ = sum = carry + *pa++;
    carry = (sum < carry);
#endif
  }

  /* If there's an overall carry out, increase precision and include
     it.  We could have done this initially, but why touch the memory
     allocator unless we're sure we have to?
   */
#if !defined(MP_NO_MP_WORD)
  if (w) {
    if((res = s_mp_pad(c, used + 1)) != MP_OKAY)
      return res;

    DIGIT(c, used) = (mp_digit)w;
    ++used;
  }
#else
  if (carry) {
    if((res = s_mp_pad(c, used + 1)) != MP_OKAY)
      return res;

    DIGIT(c, used) = carry;
    ++used;
  }
#endif
  MP_USED(c) = used;
  return MP_OKAY;
}
/* {{{ s_mp_add_offset(a, b, offset) */

/* Compute a = |a| + ( |b| * (RADIX ** offset) )             */
mp_err   s_mp_add_offset(mp_int *a, mp_int *b, mp_size offset)   
{
#if !defined(MP_NO_MP_WORD)
  mp_word   w, k = 0;
#else
  mp_digit  d, sum, carry = 0;
#endif
  mp_size   ib;
  mp_size   ia;
  mp_size   lim;
  mp_err    res;

  /* Make sure a has enough precision for the output value */
  lim = MP_USED(b) + offset;
  if((lim > USED(a)) && (res = s_mp_pad(a, lim)) != MP_OKAY)
    return res;

  /*
    Add up all digits up to the precision of b.  If b had initially
    the same precision as a, or greater, we took care of it by the
    padding step above, so there is no problem.  If b had initially
    less precision, we'll have to make sure the carry out is duly
    propagated upward among the higher-order digits of the sum.
   */
  lim = USED(b);
  for(ib = 0, ia = offset; ib < lim; ib++, ia++) {
#if !defined(MP_NO_MP_WORD)
    w = (mp_word)DIGIT(a, ia) + DIGIT(b, ib) + k;
    DIGIT(a, ia) = ACCUM(w);
    k = CARRYOUT(w);
#else
    d = MP_DIGIT(a, ia);
    sum = d + MP_DIGIT(b, ib);
    d = (sum < d);
    MP_DIGIT(a,ia) = sum += carry;
    carry = d + (sum < carry);
#endif
  }

  /* If we run out of 'b' digits before we're actually done, make
     sure the carries get propagated upward...  
   */
#if !defined(MP_NO_MP_WORD)
  for (lim = MP_USED(a); k && (ia < lim); ++ia) {
    w = (mp_word)DIGIT(a, ia) + k;
    DIGIT(a, ia) = ACCUM(w);
    k = CARRYOUT(w);
  }
#else
  for (lim = MP_USED(a); carry && (ia < lim); ++ia) {
    d = MP_DIGIT(a, ia);
    MP_DIGIT(a,ia) = sum = d + carry;
    carry = (sum < d);
  }
#endif

  /* If there's an overall carry out, increase precision and include
     it.  We could have done this initially, but why touch the memory
     allocator unless we're sure we have to?
   */
#if !defined(MP_NO_MP_WORD)
  if(k) {
    if((res = s_mp_pad(a, USED(a) + 1)) != MP_OKAY)
      return res;

    DIGIT(a, ia) = (mp_digit)k;
  }
#else
  if (carry) {
    if((res = s_mp_pad(a, lim + 1)) != MP_OKAY)
      return res;

    DIGIT(a, lim) = carry;
  }
#endif
  s_mp_clamp(a);

  return MP_OKAY;

} /* end s_mp_add_offset() */

/* }}} */

/* {{{ s_mp_sub(a, b) */

/* Compute a = |a| - |b|, assumes |a| >= |b|                              */
mp_err   s_mp_sub(mp_int *a, const mp_int *b)  /* magnitude subtract      */
{
  mp_digit *pa, *pb, *limit;
#if !defined(MP_NO_MP_WORD)
  mp_sword  w = 0;
#else
  mp_digit  d, diff, borrow = 0;
#endif

  /*
    Subtract and propagate borrow.  Up to the precision of b, this
    accounts for the digits of b; after that, we just make sure the
    carries get to the right place.  This saves having to pad b out to
    the precision of a just to make the loops work right...
   */
  pa = MP_DIGITS(a);
  pb = MP_DIGITS(b);
  limit = pb + MP_USED(b);
  while (pb < limit) {
#if !defined(MP_NO_MP_WORD)
    w = w + *pa - *pb++;
    *pa++ = ACCUM(w);
    w >>= MP_DIGIT_BIT;
#else
    d = *pa;
    diff = d - *pb++;
    d = (diff > d);				/* detect borrow */
    if (borrow && --diff == MP_DIGIT_MAX)
      ++d;
    *pa++ = diff;
    borrow = d;	
#endif
  }
  limit = MP_DIGITS(a) + MP_USED(a);
#if !defined(MP_NO_MP_WORD)
  while (w && pa < limit) {
    w = w + *pa;
    *pa++ = ACCUM(w);
    w >>= MP_DIGIT_BIT;
  }
#else
  while (borrow && pa < limit) {
    d = *pa;
    *pa++ = diff = d - borrow;
    borrow = (diff > d);
  }
#endif

  /* Clobber any leading zeroes we created    */
  s_mp_clamp(a);

  /* 
     If there was a borrow out, then |b| > |a| in violation
     of our input invariant.  We've already done the work,
     but we'll at least complain about it...
   */
#if !defined(MP_NO_MP_WORD)
  return w ? MP_RANGE : MP_OKAY;
#else
  return borrow ? MP_RANGE : MP_OKAY;
#endif
} /* end s_mp_sub() */

/* }}} */

/* Compute c = |a| - |b|, assumes |a| >= |b| */ /* magnitude subtract      */
mp_err   s_mp_sub_3arg(const mp_int *a, const mp_int *b, mp_int *c)  
{
  mp_digit *pa, *pb, *pc;
#if !defined(MP_NO_MP_WORD)
  mp_sword  w = 0;
#else
  mp_digit  d, diff, borrow = 0;
#endif
  int       ix, limit;
  mp_err    res;

  MP_SIGN(c) = MP_SIGN(a);

  /* Make sure a has enough precision for the output value */
  if (MP_OKAY != (res = s_mp_pad(c, MP_USED(a))))
    return res;

  /*
    Subtract and propagate borrow.  Up to the precision of b, this
    accounts for the digits of b; after that, we just make sure the
    carries get to the right place.  This saves having to pad b out to
    the precision of a just to make the loops work right...
   */
  pa = MP_DIGITS(a);
  pb = MP_DIGITS(b);
  pc = MP_DIGITS(c);
  limit = MP_USED(b);
  for (ix = 0; ix < limit; ++ix) {
#if !defined(MP_NO_MP_WORD)
    w = w + *pa++ - *pb++;
    *pc++ = ACCUM(w);
    w >>= MP_DIGIT_BIT;
#else
    d = *pa++;
    diff = d - *pb++;
    d = (diff > d);
    if (borrow && --diff == MP_DIGIT_MAX)
      ++d;
    *pc++ = diff;
    borrow = d;
#endif
  }
  for (limit = MP_USED(a); ix < limit; ++ix) {
#if !defined(MP_NO_MP_WORD)
    w = w + *pa++;
    *pc++ = ACCUM(w);
    w >>= MP_DIGIT_BIT;
#else
    d = *pa++;
    *pc++ = diff = d - borrow;
    borrow = (diff > d);
#endif
  }

  /* Clobber any leading zeroes we created    */
  MP_USED(c) = ix;
  s_mp_clamp(c);

  /* 
     If there was a borrow out, then |b| > |a| in violation
     of our input invariant.  We've already done the work,
     but we'll at least complain about it...
   */
#if !defined(MP_NO_MP_WORD)
  return w ? MP_RANGE : MP_OKAY;
#else
  return borrow ? MP_RANGE : MP_OKAY;
#endif
}
/* {{{ s_mp_mul(a, b) */

/* Compute a = |a| * |b|                                                  */
mp_err   s_mp_mul(mp_int *a, const mp_int *b)
{
  return mp_mul(a, b, a);
} /* end s_mp_mul() */

/* }}} */

#if defined(SOLARIS) && (ULONG_MAX == UINT_MAX)
/* This trick works on Sparc V8 CPUs with the Workshop compilers. */
#define MP_MUL_DxD(a, b, Phi, Plo) \
  { unsigned long long product = (unsigned long long)a * b; \
    Plo = (mp_digit)product; \
    Phi = (mp_digit)(product >> MP_DIGIT_BIT); }
#else
#define MP_MUL_DxD(a, b, Phi, Plo) \
  { mp_digit a0b1, a1b0; \
    Plo = (a & MP_HALF_DIGIT_MAX) * (b & MP_HALF_DIGIT_MAX); \
    Phi = (a >> MP_HALF_DIGIT_BIT) * (b >> MP_HALF_DIGIT_BIT); \
    a0b1 = (a & MP_HALF_DIGIT_MAX) * (b >> MP_HALF_DIGIT_BIT); \
    a1b0 = (a >> MP_HALF_DIGIT_BIT) * (b & MP_HALF_DIGIT_MAX); \
    a1b0 += a0b1; \
    Phi += a1b0 >> MP_HALF_DIGIT_BIT; \
    if (a1b0 < a0b1)  \
      Phi += MP_HALF_RADIX; \
    a1b0 <<= MP_HALF_DIGIT_BIT; \
    Plo += a1b0; \
    if (Plo < a1b0) \
      ++Phi; \
  }
#endif

#if !defined(MP_ASSEMBLY_MULTIPLY)
/* c = a * b */
void s_mpv_mul_d(const mp_digit *a, mp_size a_len, mp_digit b, mp_digit *c)
{
#if !defined(MP_NO_MP_WORD)
  mp_digit   d = 0;

  /* Inner product:  Digits of a */
  while (a_len--) {
    mp_word w = ((mp_word)b * *a++) + d;
    *c++ = ACCUM(w);
    d = CARRYOUT(w);
  }
  *c = d;
#else
  mp_digit carry = 0;
  while (a_len--) {
    mp_digit a_i = *a++;
    mp_digit a0b0, a1b1;

    MP_MUL_DxD(a_i, b, a1b1, a0b0);

    a0b0 += carry;
    if (a0b0 < carry)
      ++a1b1;
    *c++ = a0b0;
    carry = a1b1;
  }
  *c = carry;
#endif
}

/* c += a * b */
void s_mpv_mul_d_add(const mp_digit *a, mp_size a_len, mp_digit b, 
			      mp_digit *c)
{
#if !defined(MP_NO_MP_WORD)
  mp_digit   d = 0;

  /* Inner product:  Digits of a */
  while (a_len--) {
    mp_word w = ((mp_word)b * *a++) + *c + d;
    *c++ = ACCUM(w);
    d = CARRYOUT(w);
  }
  *c = d;
#else
  mp_digit carry = 0;
  while (a_len--) {
    mp_digit a_i = *a++;
    mp_digit a0b0, a1b1;

    MP_MUL_DxD(a_i, b, a1b1, a0b0);

    a0b0 += carry;
    if (a0b0 < carry)
      ++a1b1;
    a0b0 += a_i = *c;
    if (a0b0 < a_i)
      ++a1b1;
    *c++ = a0b0;
    carry = a1b1;
  }
  *c = carry;
#endif
}

/* Presently, this is only used by the Montgomery arithmetic code. */
/* c += a * b */
void s_mpv_mul_d_add_prop(const mp_digit *a, mp_size a_len, mp_digit b, mp_digit *c)
{
#if !defined(MP_NO_MP_WORD)
  mp_digit   d = 0;

  /* Inner product:  Digits of a */
  while (a_len--) {
    mp_word w = ((mp_word)b * *a++) + *c + d;
    *c++ = ACCUM(w);
    d = CARRYOUT(w);
  }

  while (d) {
    mp_word w = (mp_word)*c + d;
    *c++ = ACCUM(w);
    d = CARRYOUT(w);
  }
#else
  mp_digit carry = 0;
  while (a_len--) {
    mp_digit a_i = *a++;
    mp_digit a0b0, a1b1;

    MP_MUL_DxD(a_i, b, a1b1, a0b0);

    a0b0 += carry;
    if (a0b0 < carry)
      ++a1b1;

    a0b0 += a_i = *c;
    if (a0b0 < a_i)
      ++a1b1;

    *c++ = a0b0;
    carry = a1b1;
  }
  while (carry) {
    mp_digit c_i = *c;
    carry += c_i;
    *c++ = carry;
    carry = carry < c_i;
  }
#endif
}
#endif

#if !defined(MP_ASSEMBLY_SQUARE)
/* Add the squares of the digits of a to the digits of b. */
void s_mpv_sqr_add_prop(const mp_digit *pa, mp_size a_len, mp_digit *ps)
{
#if !defined(MP_NO_MP_WORD)
  mp_word  w;
  mp_digit d;
  mp_size  ix;

  w  = 0;
#define ADD_SQUARE(n) \
    d = pa[n]; \
    w += (d * (mp_word)d) + ps[2*n]; \
    ps[2*n] = ACCUM(w); \
    w = (w >> DIGIT_BIT) + ps[2*n+1]; \
    ps[2*n+1] = ACCUM(w); \
    w = (w >> DIGIT_BIT)

  for (ix = a_len; ix >= 4; ix -= 4) {
    ADD_SQUARE(0);
    ADD_SQUARE(1);
    ADD_SQUARE(2);
    ADD_SQUARE(3);
    pa += 4;
    ps += 8;
  }
  if (ix) {
    ps += 2*ix;
    pa += ix;
    switch (ix) {
    case 3: ADD_SQUARE(-3); /* FALLTHRU */
    case 2: ADD_SQUARE(-2); /* FALLTHRU */
    case 1: ADD_SQUARE(-1); /* FALLTHRU */
    case 0: break;
    }
  }
  while (w) {
    w += *ps;
    *ps++ = ACCUM(w);
    w = (w >> DIGIT_BIT);
  }
#else
  mp_digit carry = 0;
  while (a_len--) {
    mp_digit a_i = *pa++;
    mp_digit a0 = a_i & MP_HALF_DIGIT_MAX;
    mp_digit a1 = a_i >> MP_HALF_DIGIT_BIT;
    mp_digit a0a0, a0a1, a1a1;

    a0a0 = a0 * a0;
    a1a1 = a1 * a1;
    a0a1 = a0 * a1;

    a1a1 += a0a1 >> (MP_HALF_DIGIT_BIT - 1);
    a0a1 <<= (MP_HALF_DIGIT_BIT + 1);
    a0a0 += a0a1;
    if (a0a0 < a0a1)
      ++a1a1;
    a0a0 += carry;
    if (a0a0 < carry)
      ++a1a1;
    /* here a1a1 and a0a0 constitute a_i ** 2 */
    /* now add to ps */
    a0a0 += a0a1 = *ps;
    if (a0a0 < a0a1)
      ++a1a1;
    *ps++ = a0a0;
    a1a1 += a0a1 = *ps;
    carry = (a1a1 < a0a1);
    *ps++ = a1a1;
  }
  while (carry) {
    mp_digit s_i = *ps;
    carry += s_i;
    *ps++ = carry;
    carry = carry < s_i;
  }
#endif
}
#endif

#if defined(MP_NO_MP_WORD) && !defined(MP_ASSEMBLY_DIV_2DX1D)
/*
** Divide 64-bit (Nhi,Nlo) by 32-bit divisor, which must be normalized 
** so its high bit is 1.   This code is from NSPR.
*/
mp_err s_mpv_div_2dx1d(mp_digit Nhi, mp_digit Nlo, mp_digit divisor, 
		       mp_digit *qp, mp_digit *rp)
{
    mp_digit d1, d0, q1, q0;
    mp_digit r1, r0, m;

    d1 = divisor >> MP_HALF_DIGIT_BIT;
    d0 = divisor & MP_HALF_DIGIT_MAX;
    r1 = Nhi % d1;
    q1 = Nhi / d1;
    m = q1 * d0;
    r1 = (r1 << MP_HALF_DIGIT_BIT) | (Nlo >> MP_HALF_DIGIT_BIT);
    if (r1 < m) {
        q1--, r1 += divisor;
        if (r1 >= divisor && r1 < m) {
	    q1--, r1 += divisor;
	}
    }
    r1 -= m;
    r0 = r1 % d1;
    q0 = r1 / d1;
    m = q0 * d0;
    r0 = (r0 << MP_HALF_DIGIT_BIT) | (Nlo & MP_HALF_DIGIT_MAX);
    if (r0 < m) {
        q0--, r0 += divisor;
        if (r0 >= divisor && r0 < m) {
	    q0--, r0 += divisor;
	}
    }
    if (qp)
	*qp = (q1 << MP_HALF_DIGIT_BIT) | q0;
    if (rp)
	*rp = r0 - m;
    return MP_OKAY;
}
#endif

#if MP_SQUARE
/* {{{ s_mp_sqr(a) */

mp_err   s_mp_sqr(mp_int *a)
{
  mp_err   res;
  mp_int   tmp;

  if((res = mp_init_size(&tmp, 2 * USED(a))) != MP_OKAY)
    return res;
  res = mp_sqr(a, &tmp);
  if (res == MP_OKAY) {
    s_mp_exch(&tmp, a);
  }
  mp_clear(&tmp);
  return res;
}

/* }}} */
#endif

/* {{{ s_mp_div(a, b) */

/*
  s_mp_div(a, b)

  Compute a = a / b and b = a mod b.  Assumes b > a.
 */

mp_err   s_mp_div(mp_int *a, mp_int *b)
{
  mp_int   quot, rem, t;
#if !defined(MP_NO_MP_WORD)
  mp_word  q;
#else
  mp_digit q;
#endif
  mp_err   res;
  mp_digit d;
  mp_digit b_msd;
  int      ix;

  if(mp_cmp_z(b) == 0)
    return MP_RANGE;

  /* Shortcut if b is power of two */
  if((ix = s_mp_ispow2(b)) >= 0) {
    mp_copy(a, b);  /* need this for remainder */
    s_mp_div_2d(a, (mp_digit)ix);
    s_mp_mod_2d(b, (mp_digit)ix);

    return MP_OKAY;
  }

  /* Allocate space to store the quotient */
  if((res = mp_init_size(&quot, MP_ALLOC(a))) != MP_OKAY)
    return res;

  /* A working temporary for division     */
  if((res = mp_init_size(&t, MP_ALLOC(a))) != MP_OKAY)
    goto T;

  /* Allocate space for the remainder     */
  if((res = mp_init_size(&rem, MP_ALLOC(a))) != MP_OKAY)
    goto REM;

  /* Normalize to optimize guessing       */
  MP_CHECKOK( s_mp_norm(a, b, &d) );

  /* Perform the division itself...woo!   */
  ix = USED(a) - 1;

  while(ix >= 0) {
    int i;

    /* Find a partial substring of a which is at least b */
    while(s_mp_cmp(&rem, b) < 0 && ix >= 0) {
      MP_CHECKOK( s_mp_lshd(&rem, 1) );
      MP_CHECKOK( s_mp_lshd(&quot, 1) );
      DIGIT(&rem, 0) = DIGIT(a, ix);
      --ix;
    }

    /* If we didn't find one, we're finished dividing    */
    if(s_mp_cmp(&rem, b) < 0) 
      break;    

    /* Compute a guess for the next quotient digit       */
    q = DIGIT(&rem, USED(&rem) - 1);
    b_msd = DIGIT(b, USED(b) - 1);
    if (q >= b_msd) {
      q = 1;
    } else if (USED(&rem) > 1) {
#if !defined(MP_NO_MP_WORD)
      q = (q << DIGIT_BIT) | DIGIT(&rem, USED(&rem) - 2);
      q /= b_msd;
      if (q == RADIX)
        --q;
#else
      mp_digit r;
      MP_CHECKOK( s_mpv_div_2dx1d(q, DIGIT(&rem, MP_USED(&rem) - 2), 
				  b_msd, &q, &r) );
#endif
    } else {
      q = 0;
    }

    /* See what that multiplies out to                   */
    mp_copy(b, &t);
    MP_CHECKOK( s_mp_mul_d(&t, (mp_digit)q) );

    /* 
       If it's too big, back it off.  We should not have to do this
       more than once, or, in rare cases, twice.  Knuth describes a
       method by which this could be reduced to a maximum of once, but
       I didn't implement that here.
     * When using s_mpv_div_2dx1d, we may have to do this 3 times.
     */
    for (i = 4; s_mp_cmp(&t, &rem) > 0 && i > 0; --i) {
      --q;
      s_mp_sub(&t, b);
    }
    if (i < 0) {
      res = MP_RANGE;
      goto CLEANUP;
    }

    /* At this point, q should be the right next digit   */
    MP_CHECKOK( s_mp_sub(&rem, &t) );

    /*
      Include the digit in the quotient.  We allocated enough memory
      for any quotient we could ever possibly get, so we should not
      have to check for failures here
     */
    DIGIT(&quot, 0) = (mp_digit)q;
  }

  /* Denormalize remainder                */
  if (d) {
    s_mp_div_2d(&rem, d);
  }

  s_mp_clamp(&quot);
  s_mp_clamp(&rem);

  /* Copy quotient back to output         */
  s_mp_exch(&quot, a);
  
  /* Copy remainder back to output        */
  s_mp_exch(&rem, b);

CLEANUP:
  mp_clear(&rem);
REM:
  mp_clear(&t);
T:
  mp_clear(&quot);

  return res;

} /* end s_mp_div() */

/* }}} */

/* {{{ s_mp_2expt(a, k) */

mp_err   s_mp_2expt(mp_int *a, mp_digit k)
{
  mp_err    res;
  mp_size   dig, bit;

  dig = k / DIGIT_BIT;
  bit = k % DIGIT_BIT;

  mp_zero(a);
  if((res = s_mp_pad(a, dig + 1)) != MP_OKAY)
    return res;
  
  DIGIT(a, dig) |= ((mp_digit)1 << bit);

  return MP_OKAY;

} /* end s_mp_2expt() */

/* }}} */

/* {{{ s_mp_reduce(x, m, mu) */

/*
  Compute Barrett reduction, x (mod m), given a precomputed value for
  mu = b^2k / m, where b = RADIX and k = #digits(m).  This should be
  faster than straight division, when many reductions by the same
  value of m are required (such as in modular exponentiation).  This
  can nearly halve the time required to do modular exponentiation,
  as compared to using the full integer divide to reduce.

  This algorithm was derived from the _Handbook of Applied
  Cryptography_ by Menezes, Oorschot and VanStone, Ch. 14,
  pp. 603-604.  
 */

mp_err   s_mp_reduce(mp_int *x, const mp_int *m, const mp_int *mu)
{
  mp_int   q;
  mp_err   res;

  if((res = mp_init_copy(&q, x)) != MP_OKAY)
    return res;

  s_mp_rshd(&q, USED(m) - 1);  /* q1 = x / b^(k-1)  */
  s_mp_mul(&q, mu);            /* q2 = q1 * mu      */
  s_mp_rshd(&q, USED(m) + 1);  /* q3 = q2 / b^(k+1) */

  /* x = x mod b^(k+1), quick (no division) */
  s_mp_mod_2d(x, DIGIT_BIT * (USED(m) + 1));

  /* q = q * m mod b^(k+1), quick (no division) */
  s_mp_mul(&q, m);
  s_mp_mod_2d(&q, DIGIT_BIT * (USED(m) + 1));

  /* x = x - q */
  if((res = mp_sub(x, &q, x)) != MP_OKAY)
    goto CLEANUP;

  /* If x < 0, add b^(k+1) to it */
  if(mp_cmp_z(x) < 0) {
    mp_set(&q, 1);
    if((res = s_mp_lshd(&q, USED(m) + 1)) != MP_OKAY)
      goto CLEANUP;
    if((res = mp_add(x, &q, x)) != MP_OKAY)
      goto CLEANUP;
  }

  /* Back off if it's too big */
  while(mp_cmp(x, m) >= 0) {
    if((res = s_mp_sub(x, m)) != MP_OKAY)
      break;
  }

 CLEANUP:
  mp_clear(&q);

  return res;

} /* end s_mp_reduce() */

/* }}} */

/* }}} */

/* {{{ Primitive comparisons */

/* {{{ s_mp_cmp(a, b) */

/* Compare |a| <=> |b|, return 0 if equal, <0 if a<b, >0 if a>b           */
int      s_mp_cmp(const mp_int *a, const mp_int *b)
{
  mp_size used_a = MP_USED(a);
  {
    mp_size used_b = MP_USED(b);

    if (used_a > used_b)
      goto IS_GT;
    if (used_a < used_b)
      goto IS_LT;
  }
  {
    mp_digit *pa, *pb;
    mp_digit da = 0, db = 0;

#define CMP_AB(n) if ((da = pa[n]) != (db = pb[n])) goto done

    pa = MP_DIGITS(a) + used_a;
    pb = MP_DIGITS(b) + used_a;
    while (used_a >= 4) {
      pa     -= 4;
      pb     -= 4;
      used_a -= 4;
      CMP_AB(3);
      CMP_AB(2);
      CMP_AB(1);
      CMP_AB(0);
    }
    while (used_a-- > 0 && ((da = *--pa) == (db = *--pb))) 
      /* do nothing */;
done:
    if (da > db)
      goto IS_GT;
    if (da < db) 
      goto IS_LT;
  }
  return MP_EQ;
IS_LT:
  return MP_LT;
IS_GT:
  return MP_GT;
} /* end s_mp_cmp() */

/* }}} */

/* {{{ s_mp_cmp_d(a, d) */

/* Compare |a| <=> d, return 0 if equal, <0 if a<d, >0 if a>d             */
int      s_mp_cmp_d(const mp_int *a, mp_digit d)
{
  if(USED(a) > 1)
    return MP_GT;

  if(DIGIT(a, 0) < d)
    return MP_LT;
  else if(DIGIT(a, 0) > d)
    return MP_GT;
  else
    return MP_EQ;

} /* end s_mp_cmp_d() */

/* }}} */

/* {{{ s_mp_ispow2(v) */

/*
  Returns -1 if the value is not a power of two; otherwise, it returns
  k such that v = 2^k, i.e. lg(v).
 */
int      s_mp_ispow2(mp_int *v)
{
  mp_digit d;
  int      extra = 0, ix;

  ix = MP_USED(v) - 1;
  d = MP_DIGIT(v, ix); /* most significant digit of v */

  extra = s_mp_ispow2d(d);
  if (extra < 0 || ix == 0)
    return extra;

  while (--ix >= 0) {
    if (DIGIT(v, ix) != 0)
      return -1; /* not a power of two */
    extra += MP_DIGIT_BIT;
  }

  return extra;

} /* end s_mp_ispow2() */

/* }}} */

/* {{{ s_mp_ispow2d(d) */

int      s_mp_ispow2d(mp_digit d)
{
  if ((d != 0) && ((d & (d-1)) == 0)) { /* d is a power of 2 */
    int pow = 0;
#if MP_DIGIT_MAX == MP_32BIT_MAX
    if (d & 0xffff0000)
      pow += 16;
    if (d & 0xff00ff00)
      pow += 8;
    if (d & 0xf0f0f0f0)
      pow += 4;
    if (d & 0xcccccccc)
      pow += 2;
    if (d & 0xaaaaaaaa)
      pow += 1;
#else
    if (d & 0xffffffff00000000UL)
      pow += 32;
    if (d & 0xffff0000ffff0000UL)
      pow += 16;
    if (d & 0xff00ff00ff00ff00UL)
      pow += 8;
    if (d & 0xf0f0f0f0f0f0f0f0UL)
      pow += 4;
    if (d & 0xccccccccccccccccUL)
      pow += 2;
    if (d & 0xaaaaaaaaaaaaaaaaUL)
      pow += 1;
#endif
    return pow;
  }
  return -1;

} /* end s_mp_ispow2d() */

/* }}} */

/* }}} */

/* {{{ Primitive I/O helpers */

/* {{{ s_mp_tovalue(ch, r) */

/*
  Convert the given character to its digit value, in the given radix.
  If the given character is not understood in the given radix, -1 is
  returned.  Otherwise the digit's numeric value is returned.

  The results will be odd if you use a radix < 2 or > 62, you are
  expected to know what you're up to.
 */
int      s_mp_tovalue(char ch, int r)
{
  int    val, xch;
  
  if(r > 36)
    xch = ch;
  else
    xch = toupper(ch);

  if(isdigit(xch))
    val = xch - '0';
  else if(isupper(xch))
    val = xch - 'A' + 10;
  else if(islower(xch))
    val = xch - 'a' + 36;
  else if(xch == '+')
    val = 62;
  else if(xch == '/')
    val = 63;
  else 
    return -1;

  if(val < 0 || val >= r)
    return -1;

  return val;

} /* end s_mp_tovalue() */

/* }}} */

/* {{{ s_mp_todigit(val, r, low) */

/*
  Convert val to a radix-r digit, if possible.  If val is out of range
  for r, returns zero.  Otherwise, returns an ASCII character denoting
  the value in the given radix.

  The results may be odd if you use a radix < 2 or > 64, you are
  expected to know what you're doing.
 */
  
char     s_mp_todigit(mp_digit val, int r, int low)
{
  char   ch;

  if(val >= r)
    return 0;

  ch = s_dmap_1[val];

  if(r <= 36 && low)
    ch = tolower(ch);

  return ch;

} /* end s_mp_todigit() */

/* }}} */

/* {{{ s_mp_outlen(bits, radix) */

/* 
   Return an estimate for how long a string is needed to hold a radix
   r representation of a number with 'bits' significant bits, plus an
   extra for a zero terminator (assuming C style strings here)
 */
int      s_mp_outlen(int bits, int r)
{
  return (int)((double)bits * LOG_V_2(r) + 1.5) + 1;

} /* end s_mp_outlen() */

/* }}} */

/* }}} */

/* {{{ mp_read_unsigned_octets(mp, str, len) */
/* mp_read_unsigned_octets(mp, str, len)
   Read in a raw value (base 256) into the given mp_int
   No sign bit, number is positive.  Leading zeros ignored.
 */

mp_err  
mp_read_unsigned_octets(mp_int *mp, const unsigned char *str, mp_size len)
{
  int            count;
  mp_err         res;
  mp_digit       d;

  ARGCHK(mp != NULL && str != NULL && len > 0, MP_BADARG);

  mp_zero(mp);

  count = len % sizeof(mp_digit);
  if (count) {
    for (d = 0; count-- > 0; --len) {
      d = (d << 8) | *str++;
    }
    MP_DIGIT(mp, 0) = d;
  }

  /* Read the rest of the digits */
  for(; len > 0; len -= sizeof(mp_digit)) {
    for (d = 0, count = sizeof(mp_digit); count > 0; --count) {
      d = (d << 8) | *str++;
    }
    if (MP_EQ == mp_cmp_z(mp)) {
      if (!d)
	continue;
    } else {
      if((res = s_mp_lshd(mp, 1)) != MP_OKAY)
	return res;
    }
    MP_DIGIT(mp, 0) = d;
  }
  return MP_OKAY;
} /* end mp_read_unsigned_octets() */
/* }}} */

/* {{{ mp_unsigned_octet_size(mp) */
int    
mp_unsigned_octet_size(const mp_int *mp)
{
  int  bytes;
  int  ix;
  mp_digit  d = 0;

  ARGCHK(mp != NULL, MP_BADARG);
  ARGCHK(MP_ZPOS == SIGN(mp), MP_BADARG);

  bytes = (USED(mp) * sizeof(mp_digit));

  /* subtract leading zeros. */
  /* Iterate over each digit... */
  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    d = DIGIT(mp, ix);
    if (d) 
	break;
    bytes -= sizeof(d);
  }
  if (!bytes)
    return 1;

  /* Have MSD, check digit bytes, high order first */
  for(ix = sizeof(mp_digit) - 1; ix >= 0; ix--) {
    unsigned char x = (unsigned char)(d >> (ix * CHAR_BIT));
    if (x) 
	break;
    --bytes;
  }
  return bytes;
} /* end mp_unsigned_octet_size() */
/* }}} */

/* {{{ mp_to_unsigned_octets(mp, str) */
/* output a buffer of big endian octets no longer than specified. */
mp_err 
mp_to_unsigned_octets(const mp_int *mp, unsigned char *str, mp_size maxlen)
{
  int  ix, pos = 0;
  int  bytes;

  ARGCHK(mp != NULL && str != NULL && !SIGN(mp), MP_BADARG);

  bytes = mp_unsigned_octet_size(mp);
  ARGCHK(bytes <= maxlen, MP_BADARG);

  /* Iterate over each digit... */
  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    mp_digit  d = DIGIT(mp, ix);
    int       jx;

    /* Unpack digit bytes, high order first */
    for(jx = sizeof(mp_digit) - 1; jx >= 0; jx--) {
      unsigned char x = (unsigned char)(d >> (jx * CHAR_BIT));
      if (!pos && !x)	/* suppress leading zeros */
	continue;
      str[pos++] = x;
    }
  }
  return pos;
} /* end mp_to_unsigned_octets() */
/* }}} */

/* {{{ mp_to_signed_octets(mp, str) */
/* output a buffer of big endian octets no longer than specified. */
mp_err 
mp_to_signed_octets(const mp_int *mp, unsigned char *str, mp_size maxlen)
{
  int  ix, pos = 0;
  int  bytes;

  ARGCHK(mp != NULL && str != NULL && !SIGN(mp), MP_BADARG);

  bytes = mp_unsigned_octet_size(mp);
  ARGCHK(bytes <= maxlen, MP_BADARG);

  /* Iterate over each digit... */
  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    mp_digit  d = DIGIT(mp, ix);
    int       jx;

    /* Unpack digit bytes, high order first */
    for(jx = sizeof(mp_digit) - 1; jx >= 0; jx--) {
      unsigned char x = (unsigned char)(d >> (jx * CHAR_BIT));
      if (!pos) {
	if (!x)		/* suppress leading zeros */
	  continue;
	if (x & 0x80) { /* add one leading zero to make output positive.  */
	  ARGCHK(bytes + 1 <= maxlen, MP_BADARG);
	  if (bytes + 1 > maxlen)
	    return MP_BADARG;
	  str[pos++] = 0;
	}
      }
      str[pos++] = x;
    }
  }
  return pos;
} /* end mp_to_signed_octets() */
/* }}} */

/* {{{ mp_to_fixlen_octets(mp, str) */
/* output a buffer of big endian octets exactly as long as requested. */
mp_err 
mp_to_fixlen_octets(const mp_int *mp, unsigned char *str, mp_size length)
{
  int  ix, pos = 0;
  int  bytes;

  ARGCHK(mp != NULL && str != NULL && !SIGN(mp), MP_BADARG);

  bytes = mp_unsigned_octet_size(mp);
  ARGCHK(bytes <= length, MP_BADARG);

  /* place any needed leading zeros */
  for (;length > bytes; --length) {
	*str++ = 0;
  }

  /* Iterate over each digit... */
  for(ix = USED(mp) - 1; ix >= 0; ix--) {
    mp_digit  d = DIGIT(mp, ix);
    int       jx;

    /* Unpack digit bytes, high order first */
    for(jx = sizeof(mp_digit) - 1; jx >= 0; jx--) {
      unsigned char x = (unsigned char)(d >> (jx * CHAR_BIT));
      if (!pos && !x)	/* suppress leading zeros */
	continue;
      str[pos++] = x;
    }
  }
  return MP_OKAY;
} /* end mp_to_fixlen_octets() */
/* }}} */


/*------------------------------------------------------------------------*/
/* HERE THERE BE DRAGONS                                                  */
