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
 * $FreeBSD: src/sys/netinet6/raw_ip6.c,v 1.7 2000/02/27 18:35:10 shin Exp $
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)raw_ip.c	8.2 (Berkeley) 1/4/94
 */

#include "opt_ipsec.h"

#include <stddef.h>

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet6/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet6/icmp6.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/nd6.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ipsec6.h>
#endif /*IPSEC*/

#include <machine/stdarg.h>

#include "faith.h"

#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))
#define	ifatoia6(ifa)	((struct in6_ifaddr *)(ifa))

/*
 * Raw interface to IP6 protocol.
 */

extern struct	inpcbhead ripcb;
extern struct	inpcbinfo ripcbinfo;
extern u_long	rip_sendspace;
extern u_long	rip_recvspace;

/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
int
rip6_input(mp, offp, proto)
	struct	mbuf **mp;
	int	*offp, proto;
{
	struct mbuf *m = *mp;
	register struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	register struct inpcb *in6p;
	struct inpcb *last = 0;
	struct mbuf *opts = 0;
	struct sockaddr_in6 rip6src;

#if defined(NFAITH) && 0 < NFAITH
	if (m->m_pkthdr.rcvif) {
		if (m->m_pkthdr.rcvif->if_type == IFT_FAITH) {
			/* XXX send icmp6 host/port unreach? */
			m_freem(m);
			return IPPROTO_DONE;
		}
	}
#endif
	init_sin6(&rip6src, m); /* general init */

	LIST_FOREACH(in6p, &ripcb, inp_list) {
		if ((in6p->in6p_vflag & INP_IPV6) == 0)
			continue;
		if (in6p->in6p_ip6_nxt &&
		    in6p->in6p_ip6_nxt != proto)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		if (in6p->in6p_cksum != -1
		    && in6_cksum(m, ip6->ip6_nxt, *offp,
				 m->m_pkthdr.len - *offp)) {
			/* XXX bark something */
			continue;
		}
		if (last) {
			struct mbuf *n = m_copy(m, 0, (int)M_COPYALL);
			if (n) {
				if (last->in6p_flags & IN6P_CONTROLOPTS ||
				    last->in6p_socket->so_options & SO_TIMESTAMP)
					ip6_savecontrol(last, &opts, ip6, n);
				/* strip intermediate headers */
				m_adj(n, *offp);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
						(struct sockaddr *)&rip6src,
						 n, opts) == 0) {
					/* should notify about lost packet */
					m_freem(n);
					if (opts)
						m_freem(opts);
				} else
					sorwakeup(last->in6p_socket);
				opts = NULL;
			}
		}
		last = in6p;
	}
	if (last) {
		if (last->in6p_flags & IN6P_CONTROLOPTS ||
		    last->in6p_socket->so_options & SO_TIMESTAMP)
			ip6_savecontrol(last, &opts, ip6, m);
		/* strip intermediate headers */
		m_adj(m, *offp);
		if (sbappendaddr(&last->in6p_socket->so_rcv,
				(struct sockaddr *)&rip6src, m, opts) == 0) {
			m_freem(m);
			if (opts)
				m_freem(opts);
		} else
			sorwakeup(last->in6p_socket);
	} else {
		if (proto == IPPROTO_NONE)
			m_freem(m);
		else {
			char *prvnxtp = ip6_get_prevhdr(m, *offp); /* XXX */
			icmp6_error(m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_NEXTHEADER,
				    prvnxtp - mtod(m, char *));
		}
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}

/*
 * Generate IPv6 header and pass packet to ip6_output.
 * Tack on options user may have setup with control call.
 */
int
#if __STDC__
rip6_output(struct mbuf *m, ...)
#else
rip6_output(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{
	struct socket *so;
	struct sockaddr_in6 *dstsock;
	struct mbuf *control;
	struct in6_addr *dst;
	struct ip6_hdr *ip6;
	struct inpcb *in6p;
	u_int	plen = m->m_pkthdr.len;
	int error = 0;
	struct ip6_pktopts opt, *optp = 0;
	struct ifnet *oifp = NULL;
	int type = 0, code = 0;		/* for ICMPv6 output statistics only */
	int priv = 0;
	va_list ap;

	va_start(ap, m);
	so = va_arg(ap, struct socket *);
	dstsock = va_arg(ap, struct sockaddr_in6 *);
	control = va_arg(ap, struct mbuf *);
	va_end(ap);

	in6p = sotoin6pcb(so);

	priv = 0;
	if (so->so_cred->cr_uid == 0)
		priv = 1;
	dst = &dstsock->sin6_addr;
	if (control) {
		if ((error = ip6_setpktoptions(control, &opt, priv)) != 0)
			goto bad;
		optp = &opt;
	} else
		optp = in6p->in6p_outputopts;

	/*
	 * For an ICMPv6 packet, we should know its type and code
	 * to update statistics.
	 */
	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icmp6;
		if (m->m_len < sizeof(struct icmp6_hdr) &&
		    (m = m_pullup(m, sizeof(struct icmp6_hdr))) == NULL) {
			error = ENOBUFS;
			goto bad;
		}
		icmp6 = mtod(m, struct icmp6_hdr *);
		type = icmp6->icmp6_type;
		code = icmp6->icmp6_code;
	}

	M_PREPEND(m, sizeof(*ip6), M_WAIT);
	ip6 = mtod(m, struct ip6_hdr *);

	/*
	 * Next header might not be ICMP6 but use its pseudo header anyway.
	 */
	ip6->ip6_dst = *dst;

	/*
	 * If the scope of the destination is link-local, embed the interface
	 * index in the address.
	 *
	 * XXX advanced-api value overrides sin6_scope_id
	 */
	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst)) {
		struct in6_pktinfo *pi;

		/*
		 * XXX Boundary check is assumed to be already done in
		 * ip6_setpktoptions().
		 */
		if (optp && (pi = optp->ip6po_pktinfo) && pi->ipi6_ifindex) {
			ip6->ip6_dst.s6_addr16[1] = htons(pi->ipi6_ifindex);
			oifp = ifindex2ifnet[pi->ipi6_ifindex];
		} else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) &&
			 in6p->in6p_moptions &&
			 in6p->in6p_moptions->im6o_multicast_ifp) {
			oifp = in6p->in6p_moptions->im6o_multicast_ifp;
			ip6->ip6_dst.s6_addr16[1] = htons(oifp->if_index);
		} else if (dstsock->sin6_scope_id) {
			/* boundary check */
			if (dstsock->sin6_scope_id < 0
			 || if_index < dstsock->sin6_scope_id) {
				error = ENXIO;  /* XXX EINVAL? */
				goto bad;
			}
			ip6->ip6_dst.s6_addr16[1]
				= htons(dstsock->sin6_scope_id & 0xffff);/*XXX*/
		}
	}

	/*
	 * Source address selection.
	 */
	{
		struct in6_addr *in6a;

		if ((in6a = in6_selectsrc(dstsock, optp,
					  in6p->in6p_moptions,
					  &in6p->in6p_route,
					  &in6p->in6p_laddr,
					  &error)) == 0) {
			if (error == 0)
				error = EADDRNOTAVAIL;
			goto bad;
		}
		ip6->ip6_src = *in6a;
		if (in6p->in6p_route.ro_rt)
			oifp = ifindex2ifnet[in6p->in6p_route.ro_rt->rt_ifp->if_index];
	}
	ip6->ip6_flow = (ip6->ip6_flow & ~IPV6_FLOWINFO_MASK) |
		(in6p->in6p_flowinfo & IPV6_FLOWINFO_MASK);
	ip6->ip6_vfc = (ip6->ip6_vfc & ~IPV6_VERSION_MASK) |
		(IPV6_VERSION & IPV6_VERSION_MASK);
	/* ip6_plen will be filled in ip6_output, so not fill it here. */
	ip6->ip6_nxt = in6p->in6p_ip6_nxt;
	ip6->ip6_hlim = in6_selecthlim(in6p, oifp);

	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6 ||
	    in6p->in6p_cksum != -1) {
		struct mbuf *n;
		int off;
		u_int16_t *p;

#define	offsetof(type, member)	((size_t)(&((type *)0)->member)) /* XXX */

		/* compute checksum */
		if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
			off = offsetof(struct icmp6_hdr, icmp6_cksum);
		else
			off = in6p->in6p_cksum;
		if (plen < off + 1) {
			error = EINVAL;
			goto bad;
		}
		off += sizeof(struct ip6_hdr);

		n = m;
		while (n && n->m_len <= off) {
			off -= n->m_len;
			n = n->m_next;
		}
		if (!n)
			goto bad;
		p = (u_int16_t *)(mtod(n, caddr_t) + off);
		*p = 0;
		*p = in6_cksum(m, ip6->ip6_nxt, sizeof(*ip6), plen);
	}

#ifdef IPSEC
	m->m_pkthdr.rcvif = (struct ifnet *)so;
#endif /*IPSEC*/

	error = ip6_output(m, optp, &in6p->in6p_route, IPV6_SOCKINMRCVIF,
			   in6p->in6p_moptions, &oifp);
	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
		if (oifp)
			icmp6_ifoutstat_inc(oifp, type, code);
		icmp6stat.icp6s_outhist[type]++;
	}

	goto freectl;

 bad:
	if (m)
		m_freem(m);

 freectl:
	if (optp == &opt && optp->ip6po_rthdr && optp->ip6po_route.ro_rt)
		RTFREE(optp->ip6po_route.ro_rt);
	if (control)
		m_freem(control);
	return(error);
}

/*
 * Raw IPv6 socket option processing.
 */
int
rip6_ctloutput(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int error;

	if (sopt->sopt_level == IPPROTO_ICMPV6)
		/*
		 * XXX: is it better to call icmp6_ctloutput() directly
		 * from protosw?
		 */
		return(icmp6_ctloutput(so, sopt));
	else if (sopt->sopt_level != IPPROTO_IPV6)
		return (EINVAL);

	error = 0;

	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case MRT6_INIT:
		case MRT6_DONE:
		case MRT6_ADD_MIF:
		case MRT6_DEL_MIF:
		case MRT6_ADD_MFC:
		case MRT6_DEL_MFC:
		case MRT6_PIM:
			error = ip6_mrouter_get(so, sopt);
			break;
		default:
			error = ip6_ctloutput(so, sopt);
			break;
		}
		break;

	case SOPT_SET:
		switch (sopt->sopt_name) {
		case MRT6_INIT:
		case MRT6_DONE:
		case MRT6_ADD_MIF:
		case MRT6_DEL_MIF:
		case MRT6_ADD_MFC:
		case MRT6_DEL_MFC:
		case MRT6_PIM:
			error = ip6_mrouter_set(so, sopt);
			break;
		default:
			error = ip6_ctloutput(so, sopt);
			break;
		}
		break;
	}

	return (error);
}

static int
rip6_attach(struct socket *so, int proto, struct proc *p)
{
	struct inpcb *inp;
	int error, s;

	inp = sotoinpcb(so);
	if (inp)
		panic("rip6_attach");
	if (p && (error = suser(p)) != 0)
		return error;

	error = soreserve(so, rip_sendspace, rip_recvspace);
	if (error)
		return error;
	s = splnet();
	error = in_pcballoc(so, &ripcbinfo, p);
	splx(s);
	if (error)
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV6;
	inp->in6p_ip6_nxt = (long)proto;
	inp->in6p_hops = -1;	/* use kernel default */
	inp->in6p_cksum = -1;
#ifdef IPSEC
	error = ipsec_init_policy(so, &inp->in6p_sp);
	if (error != 0) {
		in6_pcbdetach(inp);
		return (error);
	}
#endif /*IPSEC*/
	MALLOC(inp->in6p_icmp6filt, struct icmp6_filter *,
	       sizeof(struct icmp6_filter), M_PCB, M_NOWAIT);
	ICMP6_FILTER_SETPASSALL(inp->in6p_icmp6filt);
	return 0;
}

static int
rip6_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0)
		panic("rip6_detach");
	/* xxx: RSVP */
	if (so == ip6_mrouter)
		ip6_mrouter_done();
	if (inp->in6p_icmp6filt) {
		FREE(inp->in6p_icmp6filt, M_PCB);
		inp->in6p_icmp6filt = NULL;
	}
	in6_pcbdetach(inp);
	return 0;
}

static int
rip6_abort(struct socket *so)
{
	soisdisconnected(so);
	return rip6_detach(so);
}

static int
rip6_disconnect(struct socket *so)
{
	struct inpcb *inp = sotoinpcb(so);

	if ((so->so_state & SS_ISCONNECTED) == 0)
		return ENOTCONN;
	inp->in6p_faddr = in6addr_any;
	return rip6_abort(so);
}

static int
rip6_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)nam;
	struct ifaddr *ia = NULL;

	if (nam->sa_len != sizeof(*addr))
		return EINVAL;

	if (TAILQ_EMPTY(&ifnet) || addr->sin6_family != AF_INET6)
		return EADDRNOTAVAIL;
	if (!IN6_IS_ADDR_UNSPECIFIED(&addr->sin6_addr) &&
	    (ia = ifa_ifwithaddr((struct sockaddr *)addr)) == 0)
		return EADDRNOTAVAIL;
	if (ia &&
	    ((struct in6_ifaddr *)ia)->ia6_flags &
	    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|
	     IN6_IFF_DETACHED|IN6_IFF_DEPRECATED)) {
		return(EADDRNOTAVAIL);
	}
	inp->in6p_laddr = addr->sin6_addr;
	return 0;
}

static int
rip6_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)nam;
	struct in6_addr *in6a = NULL;
	int error = 0;

	if (nam->sa_len != sizeof(*addr))
		return EINVAL;
	if (TAILQ_EMPTY(&ifnet))
		return EADDRNOTAVAIL;
	if (addr->sin6_family != AF_INET6)
		return EAFNOSUPPORT;

	/* Source address selection. XXX: need pcblookup? */
	in6a = in6_selectsrc(addr, inp->in6p_outputopts,
			     inp->in6p_moptions, &inp->in6p_route,
			     &inp->in6p_laddr, &error);
	if (in6a == NULL)
		return (error ? error : EADDRNOTAVAIL);
	inp->in6p_laddr = *in6a;
	inp->in6p_faddr = addr->sin6_addr;
	soisconnected(so);
	return 0;
}

static int
rip6_shutdown(struct socket *so)
{
	socantsendmore(so);
	return 0;
}

static int
rip6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct proc *p)
{
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 tmp;
	struct sockaddr_in6 *dst;

	if (so->so_state & SS_ISCONNECTED) {
		if (nam) {
			m_freem(m);
			return EISCONN;
		}
		/* XXX */
		bzero(&tmp, sizeof(tmp));
		tmp.sin6_family = AF_INET6;
		tmp.sin6_len = sizeof(struct sockaddr_in6);
		bcopy(&inp->in6p_faddr, &tmp.sin6_addr,
		      sizeof(struct in6_addr));
		dst = &tmp;
	} else {
		if (nam == NULL) {
			m_freem(m);
			return ENOTCONN;
		}
		dst = (struct sockaddr_in6 *)nam;
	}
	return rip6_output(m, so, dst, control);
}

struct pr_usrreqs rip6_usrreqs = {
	rip6_abort, pru_accept_notsupp, rip6_attach, rip6_bind, rip6_connect,
	pru_connect2_notsupp, in6_control, rip6_detach, rip6_disconnect,
	pru_listen_notsupp, in6_setpeeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, rip6_send, pru_sense_null, rip6_shutdown,
	in6_setsockaddr, sosend, soreceive, sopoll
};
