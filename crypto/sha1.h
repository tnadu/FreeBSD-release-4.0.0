/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/crypto/sha1.h,v 1.3 2000/02/10 19:35:52 shin Exp $
 */
/*
 * FIPS pub 180-1: Secure Hash Algorithm (SHA-1)
 * based on: http://csrc.nist.gov/fips/fip180-1.txt
 * implemented by Jun-ichiro itojun Itoh <itojun@itojun.org>
 */

#ifndef _NETINET6_SHA1_H_
#define	_NETINET6_SHA1_H_

struct sha1_ctxt {
	union {
		u_int8_t	b8[20];
		u_int32_t	b32[5];
	} h;
	union {
		u_int8_t	b8[8];
		u_int64_t	b64[1];
	} c;
	union {
		u_int8_t	b8[64];
		u_int32_t	b32[16];
	} m;
	u_int8_t	count;
};

#ifdef _KERNEL
extern void sha1_init __P((struct sha1_ctxt *));
extern void sha1_pad __P((struct sha1_ctxt *));
extern void sha1_loop __P((struct sha1_ctxt *, const caddr_t, size_t));
extern void sha1_result __P((struct sha1_ctxt *, caddr_t));

/* compatibilty with other SHA1 source codes */
typedef struct sha1_ctxt SHA1_CTX;
#define	SHA1Init(x)		sha1_init((x))
#define	SHA1Update(x, y, z)	sha1_loop((x), (y), (z))
#define	SHA1Final(x, y)		sha1_result((y), (x))
#endif

#define	SHA1_RESULTLEN	(160/8)

#endif /*_NETINET6_SHA1_H_*/
