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
 * $FreeBSD: src/sys/netinet6/dest6.c,v 1.1 1999/11/22 02:44:58 shin Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/icmp6.h>

/*
 * Destination options header processing.
 */
int
dest6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	register struct mbuf *m = *mp;
	int off = *offp, dstoptlen, optlen;
	struct ip6_dest *dstopts;
	u_int8_t *opt;

	/* validation of the length of the header */
	IP6_EXTHDR_CHECK(m, off, sizeof(*dstopts), IPPROTO_DONE);
	dstopts = (struct ip6_dest *)(mtod(m, caddr_t) + off);
	dstoptlen = (dstopts->ip6d_len + 1) << 3;

	IP6_EXTHDR_CHECK(m, off, dstoptlen, IPPROTO_DONE);
	dstopts = (struct ip6_dest *)(mtod(m, caddr_t) + off);
	off += dstoptlen;
	dstoptlen -= sizeof(struct ip6_dest);
	opt = (u_int8_t *)dstopts + sizeof(struct ip6_dest);

	/* search header for all options. */
	for (optlen = 0; dstoptlen > 0; dstoptlen -= optlen, opt += optlen) {
		switch(*opt) {
		 case IP6OPT_PAD1:
			 optlen = 1;
			 break;
		 case IP6OPT_PADN:
			 if (dstoptlen < IP6OPT_MINLEN) {
				 ip6stat.ip6s_toosmall++;
				 goto bad;
			 }
			 optlen = *(opt + 1) + 2;
			 break;
		 default:		/* unknown option */
			 if (dstoptlen < IP6OPT_MINLEN) {
				 ip6stat.ip6s_toosmall++;
				 goto bad;
			 }
			 if ((optlen = ip6_unknown_opt(opt, m,
						       opt-mtod(m, u_int8_t *))) == -1)
				 return(IPPROTO_DONE);
			 optlen += 2;
			 break;
		}
	}

	*offp = off;
	return(dstopts->ip6d_nxt);

  bad:
	m_freem(m);
	return(IPPROTO_DONE);
}
