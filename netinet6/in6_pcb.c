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
 * $FreeBSD: src/sys/netinet6/in6_pcb.c,v 1.10 2000/01/16 18:00:06 shin Exp $
 */

/*
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)in_pcb.c	8.2 (Berkeley) 1/4/94
 * $FreeBSD: src/sys/netinet6/in6_pcb.c,v 1.10 2000/01/16 18:00:06 shin Exp $
 */

#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/jail.h>

#include <vm/vm_zone.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet6/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>

#include "faith.h"

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#include <netinet6/ipsec6.h>
#include <netinet6/ah6.h>
#include <netkey/key.h>
#ifdef IPSEC_DEBUG
#include <netkey/key_debug.h>
#else
#define	KEYDEBUG(lev,arg)
#endif /* IPSEC_DEBUG */
#endif /* IPSEC */

struct	in6_addr zeroin6_addr;

int
in6_pcbbind(inp, nam, p)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct proc *p;
{
	struct socket *so = inp->inp_socket;
	unsigned short *lastport;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)NULL;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	u_short	lport = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);
	int error;

	if (!in6_ifaddr) /* XXX broken! */
		return (EADDRNOTAVAIL);
	if (inp->inp_lport || !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
		return(EINVAL);
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;
	if (nam) {
		sin6 = (struct sockaddr_in6 *)nam;
		if (nam->sa_len != sizeof(*sin6))
			return(EINVAL);
		/*
		 * family check.
		 */
		if (nam->sa_family != AF_INET6)
			return(EAFNOSUPPORT);

		/*
		 * If the scope of the destination is link-local, embed the
		 * interface index in the address.
		 */
		if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr)) {
			/* XXX boundary check is assumed to be already done. */
			/* XXX sin6_scope_id is weaker than advanced-api. */
			struct in6_pktinfo *pi;
			if (inp->in6p_outputopts &&
			    (pi = inp->in6p_outputopts->ip6po_pktinfo) &&
			    pi->ipi6_ifindex) {
				sin6->sin6_addr.s6_addr16[1]
					= htons(pi->ipi6_ifindex);
			} else if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)
				&& inp->in6p_moptions
				&& inp->in6p_moptions->im6o_multicast_ifp) {
				sin6->sin6_addr.s6_addr16[1] =
					htons(inp->in6p_moptions->im6o_multicast_ifp->if_index);
			} else if (sin6->sin6_scope_id) {
				/* boundary check */
				if (sin6->sin6_scope_id < 0
				 || if_index < sin6->sin6_scope_id) {
					return ENXIO;  /* XXX EINVAL? */
				}
				sin6->sin6_addr.s6_addr16[1]
					= htons(sin6->sin6_scope_id & 0xffff);/*XXX*/
				/* this must be cleared for ifa_ifwithaddr() */
				sin6->sin6_scope_id = 0;
			}
		}

		lport = sin6->sin6_port;
		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
			/*
			 * Treat SO_REUSEADDR as SO_REUSEPORT for multicast;
			 * allow compepte duplication of binding if
			 * SO_REUSEPORT is set, or if SO_REUSEADDR is set
			 * and a multicast address is bound on both
			 * new and duplicated sockets.
			 */
			if (so->so_options & SO_REUSEADDR)
				reuseport = SO_REUSEADDR|SO_REUSEPORT;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			struct ifaddr *ia = NULL;

			sin6->sin6_port = 0;		/* yech... */
			if ((ia = ifa_ifwithaddr((struct sockaddr *)sin6)) == 0)
				return(EADDRNOTAVAIL);

			/*
			 * XXX: bind to an anycast address might accidentally
			 * cause sending a packet with anycast source address.
			 */
			if (ia &&
			    ((struct in6_ifaddr *)ia)->ia6_flags &
			    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|
			     IN6_IFF_DETACHED|IN6_IFF_DEPRECATED)) {
				return(EADDRNOTAVAIL);
			}
		}
		if (lport) {
			struct inpcb *t;

			/* GROSS */
			if (ntohs(lport) < IPV6PORT_RESERVED && p &&
			    suser_xxx(0, p, PRISON_ROOT))
				return(EACCES);
			if (so->so_cred->cr_uid != 0 &&
			    !IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
				t = in6_pcblookup_local(pcbinfo,
				    &sin6->sin6_addr, lport,
				    INPLOOKUP_WILDCARD);
				if (t &&
				    (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
				     !IN6_IS_ADDR_UNSPECIFIED(&t->in6p_laddr) ||
				     (t->inp_socket->so_options &
				      SO_REUSEPORT) == 0) &&
				    (so->so_cred->cr_uid !=
				     t->inp_socket->so_cred->cr_uid))
					return (EADDRINUSE);
				if (ip6_mapped_addr_on != 0 &&
				    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
					struct sockaddr_in sin;

					in6_sin6_2_sin(&sin, sin6);
					t = in_pcblookup_local(pcbinfo,
						sin.sin_addr, lport,
						INPLOOKUP_WILDCARD);
					if (t &&
					    (so->so_cred->cr_uid !=
					     t->inp_socket->so_cred->cr_uid) &&
					    (ntohl(t->inp_laddr.s_addr) !=
					     INADDR_ANY ||
					     INP_SOCKAF(so) ==
					     INP_SOCKAF(t->inp_socket)))
						return (EADDRINUSE);
				}
			}
			t = in6_pcblookup_local(pcbinfo, &sin6->sin6_addr,
						lport, wild);
			if (t && (reuseport & t->inp_socket->so_options) == 0)
				return(EADDRINUSE);
			if (ip6_mapped_addr_on != 0 &&
			    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				struct sockaddr_in sin;

				in6_sin6_2_sin(&sin, sin6);
				t = in_pcblookup_local(pcbinfo, sin.sin_addr,
						       lport, wild);
				if (t &&
				    (reuseport & t->inp_socket->so_options)
				    == 0 &&
				    (ntohl(t->inp_laddr.s_addr)
				     != INADDR_ANY ||
				     INP_SOCKAF(so) ==
				     INP_SOCKAF(t->inp_socket)))
					return (EADDRINUSE);
			}
		}
		inp->in6p_laddr = sin6->sin6_addr;
	}
	if (lport == 0) {
		ushort first, last;
		int count;

		inp->inp_flags |= INP_ANONPORT;

		if (inp->inp_flags & INP_HIGHPORT) {
			first = ipport_hifirstauto;	/* sysctl */
			last  = ipport_hilastauto;
			lastport = &pcbinfo->lasthi;
		} else if (inp->inp_flags & INP_LOWPORT) {
			if (p && (error = suser_xxx(0, p, PRISON_ROOT)))
				return error;
			first = ipport_lowfirstauto;	/* 1023 */
			last  = ipport_lowlastauto;	/* 600 */
			lastport = &pcbinfo->lastlow;
		} else {
			first = ipport_firstauto;	/* sysctl */
			last  = ipport_lastauto;
			lastport = &pcbinfo->lastport;
		}
		/*
		 * Simple check to ensure all ports are not used up causing
		 * a deadlock here.
		 *
		 * We split the two cases (up and down) so that the direction
		 * is not being tested on each round of the loop.
		 */
		if (first > last) {
			/*
			 * counting down
			 */
			count = first - last;

			do {
				if (count-- < 0) {	/* completely used? */
					/*
					 * Undo any address bind that may have
					 * occurred above.
					 */
					inp->in6p_laddr = in6addr_any;
					return (EAGAIN);
				}
				--*lastport;
				if (*lastport > first || *lastport < last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in6_pcblookup_local(pcbinfo,
				 &inp->in6p_laddr, lport, wild));
		} else {
			/*
			 * counting up
			 */
			count = last - first;

			do {
				if (count-- < 0) {	/* completely used? */
					/*
					 * Undo any address bind that may have
					 * occurred above.
					 */
					inp->in6p_laddr = in6addr_any;
					return (EAGAIN);
				}
				++*lastport;
				if (*lastport < first || *lastport > last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in6_pcblookup_local(pcbinfo,
				 &inp->in6p_laddr, lport, wild));
		}
	}
	inp->inp_lport = lport;
	if (in_pcbinshash(inp) != 0) {
		inp->in6p_laddr = in6addr_any;
		inp->inp_lport = 0;
		return (EAGAIN);
	}
	inp->in6p_flowinfo = sin6 ? sin6->sin6_flowinfo : 0;	/*XXX*/
	return(0);
}

/*
 *   Transform old in6_pcbconnect() into an inner subroutine for new
 *   in6_pcbconnect(): Do some validity-checking on the remote
 *   address (in mbuf 'nam') and then determine local host address
 *   (i.e., which interface) to use to access that remote host.
 *
 *   This preserves definition of in6_pcbconnect(), while supporting a
 *   slightly different version for T/TCP.  (This is more than
 *   a bit of a kludge, but cleaning up the internal interfaces would
 *   have forced minor changes in every protocol).
 */

int
in6_pcbladdr(inp, nam, plocal_addr6)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct in6_addr **plocal_addr6;
{
	register struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)nam;
	struct in6_pktinfo *pi;
	struct ifnet *ifp = NULL;
	int error = 0;

	if (nam->sa_len != sizeof (*sin6))
		return (EINVAL);
	if (sin6->sin6_family != AF_INET6)
		return (EAFNOSUPPORT);
	if (sin6->sin6_port == 0)
		return (EADDRNOTAVAIL);

	/*
	 * If the scope of the destination is link-local, embed the interface
	 * index in the address.
	 */
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr)) {
		/* XXX boundary check is assumed to be already done. */
		/* XXX sin6_scope_id is weaker than advanced-api. */
		if (inp->in6p_outputopts &&
		    (pi = inp->in6p_outputopts->ip6po_pktinfo) &&
		    pi->ipi6_ifindex) {
			sin6->sin6_addr.s6_addr16[1] = htons(pi->ipi6_ifindex);
			ifp = ifindex2ifnet[pi->ipi6_ifindex];
		} else if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr) &&
			 inp->in6p_moptions &&
			 inp->in6p_moptions->im6o_multicast_ifp) {
			sin6->sin6_addr.s6_addr16[1] =
				htons(inp->in6p_moptions->im6o_multicast_ifp->if_index);
			ifp = ifindex2ifnet[inp->in6p_moptions->im6o_multicast_ifp->if_index];
		} else if (sin6->sin6_scope_id) {
			/* boundary check */
			if (sin6->sin6_scope_id < 0
			 || if_index < sin6->sin6_scope_id) {
				return ENXIO;  /* XXX EINVAL? */
			}
			sin6->sin6_addr.s6_addr16[1]
				= htons(sin6->sin6_scope_id & 0xffff);/*XXX*/
			ifp = ifindex2ifnet[sin6->sin6_scope_id];
		}
	}

	if (in6_ifaddr) {
		/*
		 * If the destination address is UNSPECIFIED addr,
		 * use the loopback addr, e.g ::1.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			sin6->sin6_addr = in6addr_loopback;
	}
	{
		/*
		 * XXX: in6_selectsrc might replace the bound local address
		 * with the address specified by setsockopt(IPV6_PKTINFO).
		 * Is it the intended behavior?
		 */
		*plocal_addr6 = in6_selectsrc(sin6, inp->in6p_outputopts,
					      inp->in6p_moptions,
					      &inp->in6p_route,
					      &inp->in6p_laddr, &error);
		if (*plocal_addr6 == 0) {
			if (error == 0)
				error = EADDRNOTAVAIL;
			return(error);
		}
		/*
		 * Don't do pcblookup call here; return interface in
		 * plocal_addr6
		 * and exit to caller, that will do the lookup.
		 */
	}

	if (inp->in6p_route.ro_rt)
		ifp = inp->in6p_route.ro_rt->rt_ifp;

	inp->in6p_ip6_hlim = (u_int8_t)in6_selecthlim(inp, ifp);

	return(0);
}

/*
 * Outer subroutine:
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 */
int
in6_pcbconnect(inp, nam, p)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct proc *p;
{
	struct in6_addr *addr6;
	register struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)nam;
	int error;

	/*
	 *   Call inner routine, to assign local interface address.
	 */
	if ((error = in6_pcbladdr(inp, nam, &addr6)) != 0)
		return(error);

	if (in6_pcblookup_hash(inp->inp_pcbinfo, &sin6->sin6_addr,
			       sin6->sin6_port,
			      IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)
			      ? addr6 : &inp->in6p_laddr,
			      inp->inp_lport, 0, NULL) != NULL) {
		return (EADDRINUSE);
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		if (inp->inp_lport == 0) {
			error = in6_pcbbind(inp, (struct sockaddr *)0, p);
			if (error)
				return (error);
		}
		inp->in6p_laddr = *addr6;
	}
	inp->in6p_faddr = sin6->sin6_addr;
	inp->inp_fport = sin6->sin6_port;
	/*
	 * xxx kazu flowlabel is necessary for connect?
	 * but if this line is missing, the garbage value remains.
	 */
	inp->in6p_flowinfo = sin6->sin6_flowinfo;
	if ((inp->in6p_flowinfo & IPV6_FLOWLABEL_MASK) == 0 &&
	    ip6_auto_flowlabel != 0)
		inp->in6p_flowinfo |=
			(htonl(ip6_flow_seq++) & IPV6_FLOWLABEL_MASK);

	in_pcbrehash(inp);
	return (0);
}

/*
 * Return an IPv6 address, which is the most appropriate for given
 * destination and user specified options.
 * If necessary, this function lookups the routing table and return
 * an entry to the caller for later use.
 */
struct in6_addr *
in6_selectsrc(dstsock, opts, mopts, ro, laddr, errorp)
	struct sockaddr_in6 *dstsock;
	struct ip6_pktopts *opts;
	struct ip6_moptions *mopts;
	struct route_in6 *ro;
	struct in6_addr *laddr;
	int *errorp;
{
	struct in6_addr *dst;
	struct in6_ifaddr *ia6 = 0;
	struct in6_pktinfo *pi = NULL;

	dst = &dstsock->sin6_addr;
	*errorp = 0;

	/*
	 * If the source address is explicitly specified by the caller,
	 * use it.
	 */
	if (opts && (pi = opts->ip6po_pktinfo) &&
	    !IN6_IS_ADDR_UNSPECIFIED(&pi->ipi6_addr))
		return(&pi->ipi6_addr);

	/*
	 * If the source address is not specified but the socket(if any)
	 * is already bound, use the bound address.
	 */
	if (laddr && !IN6_IS_ADDR_UNSPECIFIED(laddr))
		return(laddr);

	/*
	 * If the caller doesn't specify the source address but
	 * the outgoing interface, use an address associated with
	 * the interface.
	 */
	if (pi && pi->ipi6_ifindex) {
		/* XXX boundary check is assumed to be already done. */
		ia6 = in6_ifawithscope(ifindex2ifnet[pi->ipi6_ifindex],
				       dst);
		if (ia6 == 0) {
			*errorp = EADDRNOTAVAIL;
			return(0);
		}
		return(&satosin6(&ia6->ia_addr)->sin6_addr);
	}

	/*
	 * If the destination address is a link-local unicast address or
	 * a multicast address, and if the outgoing interface is specified
	 * by the sin6_scope_id filed, use an address associated with the
	 * interface.
	 * XXX: We're now trying to define more specific semantics of
	 *      sin6_scope_id field, so this part will be rewritten in
	 *      the near future.
	 */
	if ((IN6_IS_ADDR_LINKLOCAL(dst) || IN6_IS_ADDR_MULTICAST(dst)) &&
	    dstsock->sin6_scope_id) {
		/*
		 * I'm not sure if boundary check for scope_id is done
		 * somewhere...
		 */
		if (dstsock->sin6_scope_id < 0 ||
		    if_index < dstsock->sin6_scope_id) {
			*errorp = ENXIO; /* XXX: better error? */
			return(0);
		}
		ia6 = in6_ifawithscope(ifindex2ifnet[dstsock->sin6_scope_id],
				       dst);
		if (ia6 == 0) {
			*errorp = EADDRNOTAVAIL;
			return(0);
		}
		return(&satosin6(&ia6->ia_addr)->sin6_addr);
	}

	/*
	 * If the destination address is a multicast address and
	 * the outgoing interface for the address is specified
	 * by the caller, use an address associated with the interface.
	 * There is a sanity check here; if the destination has node-local
	 * scope, the outgoing interfacde should be a loopback address.
	 * Even if the outgoing interface is not specified, we also
	 * choose a loopback interface as the outgoing interface.
	 */
	if (IN6_IS_ADDR_MULTICAST(dst)) {
		struct ifnet *ifp = mopts ? mopts->im6o_multicast_ifp : NULL;

		if (ifp == NULL && IN6_IS_ADDR_MC_NODELOCAL(dst)) {
			ifp = &loif[0];
		}

		if (ifp) {
			ia6 = in6_ifawithscope(ifp, dst);
			if (ia6 == 0) {
				*errorp = EADDRNOTAVAIL;
				return(0);
			}
			return(&ia6->ia_addr.sin6_addr);
		}
	}

	/*
	 * If the next hop address for the packet is specified
	 * by caller, use an address associated with the route
	 * to the next hop.
	 */
	{
		struct sockaddr_in6 *sin6_next;
		struct rtentry *rt;

		if (opts && opts->ip6po_nexthop) {
			sin6_next = satosin6(opts->ip6po_nexthop);
			rt = nd6_lookup(&sin6_next->sin6_addr, 1, NULL);
			if (rt) {
				ia6 = in6_ifawithscope(rt->rt_ifp, dst);
				if (ia6 == 0)
					ia6 = ifatoia6(rt->rt_ifa);
			}
			if (ia6 == 0) {
				*errorp = EADDRNOTAVAIL;
				return(0);
			}
			return(&satosin6(&ia6->ia_addr)->sin6_addr);
		}
	}

	/*
	 * If route is known or can be allocated now,
	 * our src addr is taken from the i/f, else punt.
	 */
	if (ro) {
		if (ro->ro_rt &&
		    !IN6_ARE_ADDR_EQUAL(&satosin6(&ro->ro_dst)->sin6_addr, dst)) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)0;
		}
		if (ro->ro_rt == (struct rtentry *)0 ||
		    ro->ro_rt->rt_ifp == (struct ifnet *)0) {
			/* No route yet, so try to acquire one */
			bzero(&ro->ro_dst, sizeof(struct sockaddr_in6));
			ro->ro_dst.sin6_family = AF_INET6;
			ro->ro_dst.sin6_len = sizeof(struct sockaddr_in6);
			ro->ro_dst.sin6_addr = *dst;
			if (IN6_IS_ADDR_MULTICAST(dst)) {
				ro->ro_rt = rtalloc1(&((struct route *)ro)
						     ->ro_dst, 0, 0UL);
			} else {
				rtalloc((struct route *)ro);
			}
		}

		/*
		 * in_pcbconnect() checks out IFF_LOOPBACK to skip using
		 * the address. But we don't know why it does so.
		 * It is necessary to ensure the scope even for lo0
		 * so doesn't check out IFF_LOOPBACK.
		 */

		if (ro->ro_rt) {
			ia6 = in6_ifawithscope(ro->ro_rt->rt_ifa->ifa_ifp, dst);
			if (ia6 == 0) /* xxx scope error ?*/
				ia6 = ifatoia6(ro->ro_rt->rt_ifa);
		}
		if (ia6 == 0) {
			*errorp = EHOSTUNREACH;	/* no route */
			return(0);
		}
		return(&satosin6(&ia6->ia_addr)->sin6_addr);
	}

	*errorp = EADDRNOTAVAIL;
	return(0);
}

/*
 * Default hop limit selection. The precedence is as follows:
 * 1. Hoplimit valued specified via ioctl.
 * 2. (If the outgoing interface is detected) the current
 *     hop limit of the interface specified by router advertisement.
 * 3. The system default hoplimit.
*/
int
in6_selecthlim(in6p, ifp)
	struct in6pcb *in6p;
	struct ifnet *ifp;
{
	if (in6p && in6p->in6p_hops >= 0)
		return(in6p->in6p_hops);
	else if (ifp)
		return(nd_ifinfo[ifp->if_index].chlim);
	else
		return(ip6_defhlim);
}

void
in6_pcbdisconnect(inp)
	struct inpcb *inp;
{
	bzero((caddr_t)&inp->in6p_faddr, sizeof(inp->in6p_faddr));
	inp->inp_fport = 0;
	in_pcbrehash(inp);
	if (inp->inp_socket->so_state & SS_NOFDREF)
		in6_pcbdetach(inp);
}

void
in6_pcbdetach(inp)
	struct inpcb *inp;
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

#ifdef IPSEC
	if (sotoinpcb(so) != 0)
		key_freeso(so);
	ipsec6_delete_pcbpolicy(inp);
#endif /* IPSEC */
	inp->inp_gencnt = ++ipi->ipi_gencnt;
	in_pcbremlists(inp);
	sotoinpcb(so) = 0;
	sofree(so);
	if (inp->in6p_options)
		m_freem(inp->in6p_options);
	if (inp->in6p_outputopts) {
		if (inp->in6p_outputopts->ip6po_rthdr &&
		    inp->in6p_outputopts->ip6po_route.ro_rt)
			RTFREE(inp->in6p_outputopts->ip6po_route.ro_rt);
		if (inp->in6p_outputopts->ip6po_m)
			(void)m_free(inp->in6p_outputopts->ip6po_m);
		free(inp->in6p_outputopts, M_IP6OPT);
	}
	if (inp->in6p_route.ro_rt)
		rtfree(inp->in6p_route.ro_rt);
	ip6_freemoptions(inp->in6p_moptions);

	/* Check and free IPv4 related resources in case of mapped addr */
	if (inp->inp_options)
		(void)m_free(inp->inp_options);
	ip_freemoptions(inp->inp_moptions);

	inp->inp_vflag = 0;
	zfreei(ipi->ipi_zone, inp);
}

/*
 * The calling convention of in6_setsockaddr() and in6_setpeeraddr() was
 * modified to match the pru_sockaddr() and pru_peeraddr() entry points
 * in struct pr_usrreqs, so that protocols can just reference then directly
 * without the need for a wrapper function.  The socket must have a valid
 * (i.e., non-nil) PCB, but it should be impossible to get an invalid one
 * except through a kernel programming error, so it is acceptable to panic
 * (or in this case trap) if the PCB is invalid.  (Actually, we don't trap
 * because there actually /is/ a programming error somewhere... XXX)
 */
int
in6_setsockaddr(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	int s;
	register struct inpcb *inp;
	register struct sockaddr_in6 *sin6;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6, M_SONAME, M_WAITOK);
	bzero(sin6, sizeof *sin6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);

	s = splnet();
	inp = sotoinpcb(so);
	if (!inp) {
		splx(s);
		free(sin6, M_SONAME);
		return EINVAL;
	}
	sin6->sin6_port = inp->inp_lport;
	sin6->sin6_addr = inp->in6p_laddr;
	splx(s);
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
	else
		sin6->sin6_scope_id = 0;	/*XXX*/
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_addr.s6_addr16[1] = 0;

	*nam = (struct sockaddr *)sin6;
	return 0;
}

int
in6_setpeeraddr(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	int s;
	struct inpcb *inp;
	register struct sockaddr_in6 *sin6;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin6, struct sockaddr_in6 *, sizeof(*sin6), M_SONAME, M_WAITOK);
	bzero((caddr_t)sin6, sizeof (*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);

	s = splnet();
	inp = sotoinpcb(so);
	if (!inp) {
		splx(s);
		free(sin6, M_SONAME);
		return EINVAL;
	}
	sin6->sin6_port = inp->inp_fport;
	sin6->sin6_addr = inp->in6p_faddr;
	splx(s);
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
	else
		sin6->sin6_scope_id = 0;	/*XXX*/
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_addr.s6_addr16[1] = 0;

	*nam = (struct sockaddr *)sin6;
	return 0;
}

int
in6_mapped_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct	inpcb *inp = sotoinpcb(so);
	int	error;

	if (inp == NULL)
		return EINVAL;
	if (inp->inp_vflag & INP_IPV4) {
		error = in_setsockaddr(so, nam);
		if (error == 0)
			in6_sin_2_v4mapsin6_in_sock(nam);
	} else
	error = in6_setsockaddr(so, nam);

	return error;
}

int
in6_mapped_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct	inpcb *inp = sotoinpcb(so);
	int	error;

	if (inp == NULL)
		return EINVAL;
	if (inp->inp_vflag & INP_IPV4) {
		error = in_setpeeraddr(so, nam);
		if (error == 0)
			in6_sin_2_v4mapsin6_in_sock(nam);
	} else
	error = in6_setpeeraddr(so, nam);

	return error;
}

/*
 * Pass some notification to all connections of a protocol
 * associated with address dst.  The local address and/or port numbers
 * may be specified to limit the search.  The "usual action" will be
 * taken, depending on the ctlinput cmd.  The caller must filter any
 * cmds that are uninteresting (e.g., no error in the map).
 * Call the protocol specific routine (if any) to report
 * any errors for each matching socket.
 *
 * Must be called at splnet.
 */
void
in6_pcbnotify(head, dst, fport_arg, laddr6, lport_arg, cmd, notify)
	struct inpcbhead *head;
	struct sockaddr *dst;
	u_int fport_arg, lport_arg;
	struct in6_addr *laddr6;
	int cmd;
	void (*notify) __P((struct inpcb *, int));
{
	struct inpcb *inp, *oinp;
	struct in6_addr faddr6;
	u_short	fport = fport_arg, lport = lport_arg;
	int errno, s;

	if ((unsigned)cmd > PRC_NCMDS || dst->sa_family != AF_INET6)
		return;
	faddr6 = ((struct sockaddr_in6 *)dst)->sin6_addr;
	if (IN6_IS_ADDR_UNSPECIFIED(&faddr6))
		return;

	/*
	 * Redirects go to all references to the destination,
	 * and use in_rtchange to invalidate the route cache.
	 * Dead host indications: notify all references to the destination.
	 * Otherwise, if we have knowledge of the local port and address,
	 * deliver only to that socket.
	 */
	if (PRC_IS_REDIRECT(cmd) || cmd == PRC_HOSTDEAD) {
		fport = 0;
		lport = 0;
		bzero((caddr_t)laddr6, sizeof(*laddr6));
		if (cmd != PRC_HOSTDEAD)
			notify = in6_rtchange;
	}
	errno = inet6ctlerrmap[cmd];
	s = splnet();
	for (inp = LIST_FIRST(head); inp != NULL;) {
		if ((inp->inp_vflag & INP_IPV6) == 0) {
			inp = LIST_NEXT(inp, inp_list);
			continue;
		}
		if (!IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr, &faddr6) ||
		   inp->inp_socket == 0 ||
		   (lport && inp->inp_lport != lport) ||
		   (!IN6_IS_ADDR_UNSPECIFIED(laddr6) &&
		    !IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, laddr6)) ||
		   (fport && inp->inp_fport != fport)) {
			inp = LIST_NEXT(inp, inp_list);
			continue;
		}
		oinp = inp;
		inp = LIST_NEXT(inp, inp_list);
		if (notify)
			(*notify)(oinp, errno);
	}
	splx(s);
}

/*
 * Lookup a PCB based on the local address and port.
 */
struct inpcb *
in6_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay)
	struct inpcbinfo *pcbinfo;
	struct in6_addr *laddr;
	u_int lport_arg;
	int wild_okay;
{
	register struct inpcb *inp;
	int matchwild = 3, wildcard;
	u_short lport = lport_arg;

	if (!wild_okay) {
		struct inpcbhead *head;
		/*
		 * Look for an unconnected (wildcard foreign addr) PCB that
		 * matches the local address and port we're looking for.
		 */
		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
						      pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
			if ((inp->inp_vflag & INP_IPV6) == 0)
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) &&
			    IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, laddr) &&
			    inp->inp_lport == lport) {
				/*
				 * Found.
				 */
				return (inp);
			}
		}
		/*
		 * Not found.
		 */
		return (NULL);
	} else {
		struct inpcbporthead *porthash;
		struct inpcbport *phd;
		struct inpcb *match = NULL;
		/*
		 * Best fit PCB lookup.
		 *
		 * First see if this local port is in use by looking on the
		 * port hash list.
		 */
		porthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(lport,
		    pcbinfo->porthashmask)];
		LIST_FOREACH(phd, porthash, phd_hash) {
			if (phd->phd_port == lport)
				break;
		}
		if (phd != NULL) {
			/*
			 * Port is in use by one or more PCBs. Look for best
			 * fit.
			 */
			LIST_FOREACH(inp, &phd->phd_pcblist, inp_portlist) {
				wildcard = 0;
				if ((inp->inp_vflag & INP_IPV6) == 0)
					continue;
				if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))
					wildcard++;
				if (!IN6_IS_ADDR_UNSPECIFIED(
					&inp->in6p_laddr)) {
					if (IN6_IS_ADDR_UNSPECIFIED(laddr))
						wildcard++;
					else if (!IN6_ARE_ADDR_EQUAL(
						&inp->in6p_laddr, laddr))
						continue;
				} else {
					if (!IN6_IS_ADDR_UNSPECIFIED(laddr))
						wildcard++;
				}
				if (wildcard < matchwild) {
					match = inp;
					matchwild = wildcard;
					if (matchwild == 0) {
						break;
					}
				}
			}
		}
		return (match);
	}
}

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in6_losing(in6p)
	struct inpcb *in6p;
{
	struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = in6p->in6p_route.ro_rt) != NULL) {
		in6p->in6p_route.ro_rt = 0;
		bzero((caddr_t)&info, sizeof(info));
		info.rti_info[RTAX_DST] =
			(struct sockaddr *)&in6p->in6p_route.ro_dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC)
			(void)rtrequest(RTM_DELETE, rt_key(rt),
					rt->rt_gateway, rt_mask(rt), rt->rt_flags,
					(struct rtentry **)0);
		else
		/*
		 * A new route can be allocated
		 * the next time output is attempted.
		 */
			rtfree(rt);
	}
}

/*
 * After a routing change, flush old routing
 * and allocate a (hopefully) better one.
 */
void
in6_rtchange(inp, errno)
	struct inpcb *inp;
	int errno;
{
	if (inp->in6p_route.ro_rt) {
		rtfree(inp->in6p_route.ro_rt);
		inp->in6p_route.ro_rt = 0;
		/*
		 * A new route can be allocated the next time
		 * output is attempted.
		 */
	}
}

/*
 * Lookup PCB in hash list.
 */
struct inpcb *
in6_pcblookup_hash(pcbinfo, faddr, fport_arg, laddr, lport_arg, wildcard, ifp)
	struct inpcbinfo *pcbinfo;
	struct in6_addr *faddr, *laddr;
	u_int fport_arg, lport_arg;
	int wildcard;
	struct ifnet *ifp;
{
	struct inpcbhead *head;
	register struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->hashbase[INP_PCBHASH(faddr->s6_addr32[3] /* XXX */,
					      lport, fport,
					      pcbinfo->hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
		if ((inp->inp_vflag & INP_IPV6) == 0)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr, faddr) &&
		    IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, laddr) &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
			 * Found.
			 */
			return (inp);
		}
	}
	if (wildcard) {
		struct inpcb *local_wild = NULL;

		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
						      pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
			if ((inp->inp_vflag & INP_IPV6) == 0)
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) &&
			    inp->inp_lport == lport) {
#if defined(NFAITH) && NFAITH > 0
				if (ifp && ifp->if_type == IFT_FAITH &&
				    (inp->inp_flags & INP_FAITH) == 0)
					continue;
#endif
				if (IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr,
						       laddr))
					return (inp);
				else if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
					local_wild = inp;
			}
		}
		return (local_wild);
	}

	/*
	 * Not found.
	 */
	return (NULL);
}

void
init_sin6(struct sockaddr_in6 *sin6, struct mbuf *m)
{
	struct ip6_hdr *ip;

	ip = mtod(m, struct ip6_hdr *);
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = ip->ip6_src;
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_addr.s6_addr16[1] = 0;
	sin6->sin6_scope_id =
		(m->m_pkthdr.rcvif && IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		? m->m_pkthdr.rcvif->if_index : 0;

	return;
}
