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
 *	@(#)if_ether.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/netinet/if_ether.c,v 1.64 2000/03/11 00:24:29 rwatson Exp $
 */

/*
 * Ethernet address resolution protocol.
 * TODO:
 *	add "inuse/lock" bit (or ref. count) along with valid bit
 */

#include "opt_inet.h"
#include "opt_bdg.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>

#include <net/iso88025.h>

#define SIN(s) ((struct sockaddr_in *)s)
#define SDL(s) ((struct sockaddr_dl *)s)

SYSCTL_DECL(_net_link_ether);
SYSCTL_NODE(_net_link_ether, PF_INET, inet, CTLFLAG_RW, 0, "");

/* timer values */
static int arpt_prune = (5*60*1); /* walk list every 5 minutes */
static int arpt_keep = (20*60); /* once resolved, good for 20 more minutes */
static int arpt_down = 20;	/* once declared down, don't send for 20 sec */

SYSCTL_INT(_net_link_ether_inet, OID_AUTO, prune_intvl, CTLFLAG_RW,
	   &arpt_prune, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, max_age, CTLFLAG_RW, 
	   &arpt_keep, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, host_down_time, CTLFLAG_RW,
	   &arpt_down, 0, "");

#define	rt_expire rt_rmx.rmx_expire

struct llinfo_arp {
	LIST_ENTRY(llinfo_arp) la_le;
	struct	rtentry *la_rt;
	struct	mbuf *la_hold;		/* last packet until resolved/timeout */
	long	la_asked;		/* last time we QUERIED for this addr */
#define la_timer la_rt->rt_rmx.rmx_expire /* deletion time in seconds */
};

static	LIST_HEAD(, llinfo_arp) llinfo_arp;

struct	ifqueue arpintrq = {0, 0, 0, 50};
static int	arp_inuse, arp_allocated;

static int	arp_maxtries = 5;
static int	useloopback = 1; /* use loopback interface for local traffic */
static int	arp_proxyall = 0;

SYSCTL_INT(_net_link_ether_inet, OID_AUTO, maxtries, CTLFLAG_RW,
	   &arp_maxtries, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, useloopback, CTLFLAG_RW,
	   &useloopback, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, proxyall, CTLFLAG_RW,
	   &arp_proxyall, 0, "");

static void	arp_rtrequest __P((int, struct rtentry *, struct sockaddr *));
static void	arprequest __P((struct arpcom *,
			struct in_addr *, struct in_addr *, u_char *));
static void	arpintr __P((void));
static void	arptfree __P((struct llinfo_arp *));
static void	arptimer __P((void *));
static struct llinfo_arp
		*arplookup __P((u_long, int, int));
#ifdef INET
static void	in_arpinput __P((struct mbuf *));
#endif

/*
 * Timeout routine.  Age arp_tab entries periodically.
 */
/* ARGSUSED */
static void
arptimer(ignored_arg)
	void *ignored_arg;
{
	int s = splnet();
	register struct llinfo_arp *la = llinfo_arp.lh_first;
	struct llinfo_arp *ola;

	timeout(arptimer, (caddr_t)0, arpt_prune * hz);
	while ((ola = la) != 0) {
		register struct rtentry *rt = la->la_rt;
		la = la->la_le.le_next;
		if (rt->rt_expire && rt->rt_expire <= time_second)
			arptfree(ola); /* timer has expired, clear */
	}
	splx(s);
}

/*
 * Parallel to llc_rtrequest.
 */
static void
arp_rtrequest(req, rt, sa)
	int req;
	register struct rtentry *rt;
	struct sockaddr *sa;
{
	register struct sockaddr *gate = rt->rt_gateway;
	register struct llinfo_arp *la = (struct llinfo_arp *)rt->rt_llinfo;
	static struct sockaddr_dl null_sdl = {sizeof(null_sdl), AF_LINK};
	static int arpinit_done;

	if (!arpinit_done) {
		arpinit_done = 1;
		LIST_INIT(&llinfo_arp);
		timeout(arptimer, (caddr_t)0, hz);
		register_netisr(NETISR_ARP, arpintr);
	}
	if (rt->rt_flags & RTF_GATEWAY)
		return;
	switch (req) {

	case RTM_ADD:
		/*
		 * XXX: If this is a manually added route to interface
		 * such as older version of routed or gated might provide,
		 * restore cloning bit.
		 */
		if ((rt->rt_flags & RTF_HOST) == 0 &&
		    SIN(rt_mask(rt))->sin_addr.s_addr != 0xffffffff)
			rt->rt_flags |= RTF_CLONING;
		if (rt->rt_flags & RTF_CLONING) {
			/*
			 * Case 1: This route should come from a route to iface.
			 */
			rt_setgate(rt, rt_key(rt),
					(struct sockaddr *)&null_sdl);
			gate = rt->rt_gateway;
			SDL(gate)->sdl_type = rt->rt_ifp->if_type;
			SDL(gate)->sdl_index = rt->rt_ifp->if_index;
			rt->rt_expire = time_second;
			break;
		}
		/* Announce a new entry if requested. */
		if (rt->rt_flags & RTF_ANNOUNCE)
			arprequest((struct arpcom *)rt->rt_ifp,
			    &SIN(rt_key(rt))->sin_addr,
			    &SIN(rt_key(rt))->sin_addr,
			    (u_char *)LLADDR(SDL(gate)));
		/*FALLTHROUGH*/
	case RTM_RESOLVE:
		if (gate->sa_family != AF_LINK ||
		    gate->sa_len < sizeof(null_sdl)) {
			log(LOG_DEBUG, "arp_rtrequest: bad gateway value\n");
			break;
		}
		SDL(gate)->sdl_type = rt->rt_ifp->if_type;
		SDL(gate)->sdl_index = rt->rt_ifp->if_index;
		if (la != 0)
			break; /* This happens on a route change */
		/*
		 * Case 2:  This route may come from cloning, or a manual route
		 * add with a LL address.
		 */
		R_Malloc(la, struct llinfo_arp *, sizeof(*la));
		rt->rt_llinfo = (caddr_t)la;
		if (la == 0) {
			log(LOG_DEBUG, "arp_rtrequest: malloc failed\n");
			break;
		}
		arp_inuse++, arp_allocated++;
		Bzero(la, sizeof(*la));
		la->la_rt = rt;
		rt->rt_flags |= RTF_LLINFO;
		LIST_INSERT_HEAD(&llinfo_arp, la, la_le);

#ifdef INET
		/*
		 * This keeps the multicast addresses from showing up
		 * in `arp -a' listings as unresolved.  It's not actually
		 * functional.  Then the same for broadcast.
		 */
		if (IN_MULTICAST(ntohl(SIN(rt_key(rt))->sin_addr.s_addr))) {
			ETHER_MAP_IP_MULTICAST(&SIN(rt_key(rt))->sin_addr,
					       LLADDR(SDL(gate)));
			SDL(gate)->sdl_alen = 6;
			rt->rt_expire = 0;
		}
		if (in_broadcast(SIN(rt_key(rt))->sin_addr, rt->rt_ifp)) {
			memcpy(LLADDR(SDL(gate)), etherbroadcastaddr, 6);
			SDL(gate)->sdl_alen = 6;
			rt->rt_expire = 0;
		}
#endif

		if (SIN(rt_key(rt))->sin_addr.s_addr ==
		    (IA_SIN(rt->rt_ifa))->sin_addr.s_addr) {
		    /*
		     * This test used to be
		     *	if (loif.if_flags & IFF_UP)
		     * It allowed local traffic to be forced
		     * through the hardware by configuring the loopback down.
		     * However, it causes problems during network configuration
		     * for boards that can't receive packets they send.
		     * It is now necessary to clear "useloopback" and remove
		     * the route to force traffic out to the hardware.
		     */
			rt->rt_expire = 0;
			Bcopy(((struct arpcom *)rt->rt_ifp)->ac_enaddr,
				LLADDR(SDL(gate)), SDL(gate)->sdl_alen = 6);
			if (useloopback)
				rt->rt_ifp = loif;

		}
		break;

	case RTM_DELETE:
		if (la == 0)
			break;
		arp_inuse--;
		LIST_REMOVE(la, la_le);
		rt->rt_llinfo = 0;
		rt->rt_flags &= ~RTF_LLINFO;
		if (la->la_hold)
			m_freem(la->la_hold);
		Free((caddr_t)la);
	}
}

/*
 * Broadcast an ARP request. Caller specifies:
 *	- arp header source ip address
 *	- arp header target ip address
 *	- arp header source ethernet address
 */
static void
arprequest(ac, sip, tip, enaddr)
	register struct arpcom *ac;
	register struct in_addr *sip, *tip;
	register u_char *enaddr;
{
	register struct mbuf *m;
	register struct ether_header *eh;
	register struct ether_arp *ea;
	struct sockaddr sa;

	if ((m = m_gethdr(M_DONTWAIT, MT_DATA)) == NULL)
		return;
	m->m_pkthdr.rcvif = (struct ifnet *)0;
	switch (ac->ac_if.if_type) {
	case IFT_ISO88025:
		m->m_len = sizeof(*ea) + 10;
		m->m_pkthdr.len = sizeof(*ea) + 10;
		MH_ALIGN(m, sizeof(*ea) + 10);
		(void)memcpy(mtod(m, caddr_t),
		    "\x82\x40\xaa\xaa\x03\x00\x00\x00\x08\x06", 10);
		(void)memcpy(sa.sa_data, etherbroadcastaddr, 6);
		(void)memcpy(sa.sa_data + 6, enaddr, 6);
		sa.sa_data[6] |= 0x80;
		sa.sa_data[12] = 0x10;
		sa.sa_data[13] = 0x40;
		ea = (struct ether_arp *)(mtod(m, char *) + 10);
		bzero((caddr_t)ea, sizeof (*ea));
		ea->arp_hrd = htons(ARPHRD_IEEE802);
		break;
	case IFT_FDDI:
	case IFT_ETHER:
		/*
		 * This may not be correct for types not explicitly
		 * listed, but this is our best guess
		 */
	default:
		m->m_len = sizeof(*ea);
		m->m_pkthdr.len = sizeof(*ea);
		MH_ALIGN(m, sizeof(*ea));
		ea = mtod(m, struct ether_arp *);
		eh = (struct ether_header *)sa.sa_data;
		bzero((caddr_t)ea, sizeof (*ea));
		/* if_output will not swap */
		eh->ether_type = htons(ETHERTYPE_ARP);
		(void)memcpy(eh->ether_dhost, etherbroadcastaddr,
		    sizeof(eh->ether_dhost));
		ea->arp_hrd = htons(ARPHRD_ETHER);
		break;
	}
	ea->arp_pro = htons(ETHERTYPE_IP);
	ea->arp_hln = sizeof(ea->arp_sha);	/* hardware address length */
	ea->arp_pln = sizeof(ea->arp_spa);	/* protocol address length */
	ea->arp_op = htons(ARPOP_REQUEST);
	(void)memcpy(ea->arp_sha, enaddr, sizeof(ea->arp_sha));
	(void)memcpy(ea->arp_spa, sip, sizeof(ea->arp_spa));
	(void)memcpy(ea->arp_tpa, tip, sizeof(ea->arp_tpa));
	sa.sa_family = AF_UNSPEC;
	sa.sa_len = sizeof(sa);
	(*ac->ac_if.if_output)(&ac->ac_if, m, &sa, (struct rtentry *)0);
}

/*
 * Resolve an IP address into an ethernet address.  If success,
 * desten is filled in.  If there is no entry in arptab,
 * set one up and broadcast a request for the IP address.
 * Hold onto this mbuf and resend it once the address
 * is finally resolved.  A return value of 1 indicates
 * that desten has been filled in and the packet should be sent
 * normally; a 0 return indicates that the packet has been
 * taken over here, either now or for later transmission.
 */
int
arpresolve(ac, rt, m, dst, desten, rt0)
	register struct arpcom *ac;
	register struct rtentry *rt;
	struct mbuf *m;
	register struct sockaddr *dst;
	register u_char *desten;
	struct rtentry *rt0;
{
	register struct llinfo_arp *la = 0;
	struct sockaddr_dl *sdl;

	if (m->m_flags & M_BCAST) {	/* broadcast */
		(void)memcpy(desten, etherbroadcastaddr, sizeof(etherbroadcastaddr));
		return (1);
	}
	if (m->m_flags & M_MCAST) {	/* multicast */
		ETHER_MAP_IP_MULTICAST(&SIN(dst)->sin_addr, desten);
		return(1);
	}
	if (rt)
		la = (struct llinfo_arp *)rt->rt_llinfo;
	if (la == 0) {
		la = arplookup(SIN(dst)->sin_addr.s_addr, 1, 0);
		if (la)
			rt = la->la_rt;
	}
	if (la == 0 || rt == 0) {
		log(LOG_DEBUG, "arpresolve: can't allocate llinfo for %s%s%s\n",
			inet_ntoa(SIN(dst)->sin_addr), la ? "la" : "",
				rt ? "rt" : "");
		m_freem(m);
		return (0);
	}
	sdl = SDL(rt->rt_gateway);
	/*
	 * Check the address family and length is valid, the address
	 * is resolved; otherwise, try to resolve.
	 */
	if ((rt->rt_expire == 0 || rt->rt_expire > time_second) &&
	    sdl->sdl_family == AF_LINK && sdl->sdl_alen != 0) {
		bcopy(LLADDR(sdl), desten, sdl->sdl_alen);
		return 1;
	}
	/*
	 * There is an arptab entry, but no ethernet address
	 * response yet.  Replace the held mbuf with this
	 * latest one.
	 */
	if (la->la_hold)
		m_freem(la->la_hold);
	la->la_hold = m;
	if (rt->rt_expire) {
		rt->rt_flags &= ~RTF_REJECT;
		if (la->la_asked == 0 || rt->rt_expire != time_second) {
			rt->rt_expire = time_second;
			if (la->la_asked++ < arp_maxtries)
			    arprequest(ac,
			        &SIN(rt->rt_ifa->ifa_addr)->sin_addr,
				&SIN(dst)->sin_addr, ac->ac_enaddr);
			else {
				rt->rt_flags |= RTF_REJECT;
				rt->rt_expire += arpt_down;
				la->la_asked = 0;
			}

		}
	}
	return (0);
}

/*
 * Common length and type checks are done here,
 * then the protocol-specific routine is called.
 */
static void
arpintr()
{
	register struct mbuf *m, *m0;
	register struct arphdr *ar;
	int s, ml;

	while (arpintrq.ifq_head) {
		s = splimp();
		IF_DEQUEUE(&arpintrq, m);
		splx(s);
		if (m == 0 || (m->m_flags & M_PKTHDR) == 0)
			panic("arpintr");
	
                if (m->m_len < sizeof(struct arphdr) &&
                    (m = m_pullup(m, sizeof(struct arphdr)) == NULL)) {
			log(LOG_ERR, "arp: runt packet -- m_pullup failed.");
			continue;
		}
		ar = mtod(m, struct arphdr *);

		if (ntohs(ar->ar_hrd) != ARPHRD_ETHER
		    && ntohs(ar->ar_hrd) != ARPHRD_IEEE802) {
			log(LOG_ERR,
			    "arp: unknown hardware address format (%2D)",
			    (unsigned char *)&ar->ar_hrd, "");
			m_freem(m);
			continue;
		}

		m0 = m;
		ml = 0;
		while (m0 != NULL) {	
			ml += m0->m_len;	/* wanna implement m_size?? */
			m0 = m0->m_next;	
		}

		if (ml < sizeof(struct arphdr) + 2 * ar->ar_hln
		    + 2 * ar->ar_pln) {
			log(LOG_ERR, "arp: runt packet.");
			m_freem(m);
			continue;
		}

		switch (ntohs(ar->ar_pro)) {
#ifdef INET
			case ETHERTYPE_IP:
				in_arpinput(m);
				continue;
#endif
		}
		m_freem(m);
	}
}

#ifdef INET
/*
 * ARP for Internet protocols on 10 Mb/s Ethernet.
 * Algorithm is that given in RFC 826.
 * In addition, a sanity check is performed on the sender
 * protocol address, to catch impersonators.
 * We no longer handle negotiations for use of trailer protocol:
 * Formerly, ARP replied for protocol type ETHERTYPE_TRAIL sent
 * along with IP replies if we wanted trailers sent to us,
 * and also sent them in response to IP replies.
 * This allowed either end to announce the desire to receive
 * trailer packets.
 * We no longer reply to requests for ETHERTYPE_TRAIL protocol either,
 * but formerly didn't normally send requests.
 */
static void
in_arpinput(m)
	struct mbuf *m;
{
	register struct ether_arp *ea;
	register struct arpcom *ac = (struct arpcom *)m->m_pkthdr.rcvif;
	struct ether_header *eh;
	struct iso88025_header *th = (struct iso88025_header *)0;
	register struct llinfo_arp *la = 0;
	register struct rtentry *rt;
	struct in_ifaddr *ia, *maybe_ia = 0;
	struct sockaddr_dl *sdl;
	struct sockaddr sa;
	struct in_addr isaddr, itaddr, myaddr;
	int op;

	ea = mtod(m, struct ether_arp *);
	op = ntohs(ea->arp_op);
	(void)memcpy(&isaddr, ea->arp_spa, sizeof (isaddr));
	(void)memcpy(&itaddr, ea->arp_tpa, sizeof (itaddr));
	for (ia = in_ifaddrhead.tqh_first; ia; ia = ia->ia_link.tqe_next)
#ifdef BRIDGE
		/*
		 * For a bridge, we want to check the address irrespective
		 * of the receive interface. (This will change slightly
		 * when we have clusters of interfaces).
		 */
		{
#else
		if (ia->ia_ifp == &ac->ac_if) {
#endif
			maybe_ia = ia;
			if ((itaddr.s_addr == ia->ia_addr.sin_addr.s_addr) ||
			     (isaddr.s_addr == ia->ia_addr.sin_addr.s_addr))
				break;
		}
	if (maybe_ia == 0) {
		m_freem(m);
		return;
	}
	myaddr = ia ? ia->ia_addr.sin_addr : maybe_ia->ia_addr.sin_addr;
	if (!bcmp((caddr_t)ea->arp_sha, (caddr_t)ac->ac_enaddr,
	    sizeof (ea->arp_sha))) {
		m_freem(m);	/* it's from me, ignore it. */
		return;
	}
	if (!bcmp((caddr_t)ea->arp_sha, (caddr_t)etherbroadcastaddr,
	    sizeof (ea->arp_sha))) {
		log(LOG_ERR,
		    "arp: ether address is broadcast for IP address %s!\n",
		    inet_ntoa(isaddr));
		m_freem(m);
		return;
	}
	if (isaddr.s_addr == myaddr.s_addr) {
		log(LOG_ERR,
		   "arp: %6D is using my IP address %s!\n",
		   ea->arp_sha, ":", inet_ntoa(isaddr));
		itaddr = myaddr;
		goto reply;
	}
	la = arplookup(isaddr.s_addr, itaddr.s_addr == myaddr.s_addr, 0);
	if (la && (rt = la->la_rt) && (sdl = SDL(rt->rt_gateway))) {
#ifndef BRIDGE /* the following is not an error when doing bridging */
		if (rt->rt_ifp != &ac->ac_if) {
			log(LOG_ERR, "arp: %s is on %s%d but got reply from %6D on %s%d\n",
			    inet_ntoa(isaddr),
			    rt->rt_ifp->if_name, rt->rt_ifp->if_unit,
			    ea->arp_sha, ":",
			    ac->ac_if.if_name, ac->ac_if.if_unit);
			goto reply;
		}
#endif
		if (sdl->sdl_alen &&
		    bcmp((caddr_t)ea->arp_sha, LLADDR(sdl), sdl->sdl_alen)) {
			if (rt->rt_expire)
			    log(LOG_INFO, "arp: %s moved from %6D to %6D on %s%d\n",
				inet_ntoa(isaddr), (u_char *)LLADDR(sdl), ":",
				ea->arp_sha, ":",
				ac->ac_if.if_name, ac->ac_if.if_unit);
			else {
			    log(LOG_ERR,
				"arp: %6D attempts to modify permanent entry for %s on %s%d\n",
				ea->arp_sha, ":", inet_ntoa(isaddr),
				ac->ac_if.if_name, ac->ac_if.if_unit);
			    goto reply;
			}
		}
		(void)memcpy(LLADDR(sdl), ea->arp_sha, sizeof(ea->arp_sha));
		sdl->sdl_alen = sizeof(ea->arp_sha);
                sdl->sdl_rcf = NULL;
		/*
		 * If we receive an arp from a token-ring station over
		 * a token-ring nic then try to save the source
		 * routing info.
		 */
		if (ac->ac_if.if_type == IFT_ISO88025) {
			th = (struct iso88025_header *)m->m_pkthdr.header;
			if ((th->iso88025_shost[0] & 0x80) &&
			    ((th->rcf & 0x001f) > 2)) {
				sdl->sdl_rcf = (th->rcf & 0x8000) ?
				    (th->rcf & 0x7fff) :
				    (th->rcf | 0x8000);
				memcpy(sdl->sdl_route, th->rseg,
				    (th->rcf & 0x001f)  - 2);
				sdl->sdl_rcf = sdl->sdl_rcf & 0xff1f;
				/*
				 * Set up source routing information for
				 * reply packet (XXX)
				 */
				m->m_data -= (th->rcf & 0x001f);
				m->m_len  += (th->rcf & 0x001f);
				m->m_pkthdr.len += (th->rcf & 0x001f);
			} else {
				th->iso88025_shost[0] &= 0x7f;
			}
			m->m_data -= 8;
			m->m_len  += 8;
			m->m_pkthdr.len += 8;
			th->rcf = sdl->sdl_rcf;
		} else {
			sdl->sdl_rcf = NULL;
		}
		if (rt->rt_expire)
			rt->rt_expire = time_second + arpt_keep;
		rt->rt_flags &= ~RTF_REJECT;
		la->la_asked = 0;
		if (la->la_hold) {
			(*ac->ac_if.if_output)(&ac->ac_if, la->la_hold,
				rt_key(rt), rt);
			la->la_hold = 0;
		}
	}
reply:
	if (op != ARPOP_REQUEST) {
		m_freem(m);
		return;
	}
	if (itaddr.s_addr == myaddr.s_addr) {
		/* I am the target */
		(void)memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
		(void)memcpy(ea->arp_sha, ac->ac_enaddr, sizeof(ea->arp_sha));
	} else {
		la = arplookup(itaddr.s_addr, 0, SIN_PROXY);
		if (la == NULL) {
			struct sockaddr_in sin;

			if (!arp_proxyall) {
				m_freem(m);
				return;
			}

			bzero(&sin, sizeof sin);
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof sin;
			sin.sin_addr = itaddr;

			rt = rtalloc1((struct sockaddr *)&sin, 0, 0UL);
			if (!rt) {
				m_freem(m);
				return;
			}
			/*
			 * Don't send proxies for nodes on the same interface
			 * as this one came out of, or we'll get into a fight
			 * over who claims what Ether address.
			 */
			if (rt->rt_ifp == &ac->ac_if) {
				rtfree(rt);
				m_freem(m);
				return;
			}
			(void)memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
			(void)memcpy(ea->arp_sha, ac->ac_enaddr, sizeof(ea->arp_sha));
			rtfree(rt);
#ifdef DEBUG_PROXY
			printf("arp: proxying for %s\n",
			       inet_ntoa(itaddr));
#endif
		} else {
			rt = la->la_rt;
			(void)memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
			sdl = SDL(rt->rt_gateway);
			(void)memcpy(ea->arp_sha, LLADDR(sdl), sizeof(ea->arp_sha));
		}
	}

	(void)memcpy(ea->arp_tpa, ea->arp_spa, sizeof(ea->arp_spa));
	(void)memcpy(ea->arp_spa, &itaddr, sizeof(ea->arp_spa));
	ea->arp_op = htons(ARPOP_REPLY);
	ea->arp_pro = htons(ETHERTYPE_IP); /* let's be sure! */
	switch (ac->ac_if.if_type) {
	case IFT_ISO88025:
		/* Re-arrange the source/dest address */
		memcpy(th->iso88025_dhost, th->iso88025_shost,
		    sizeof(th->iso88025_dhost));
		memcpy(th->iso88025_shost, ac->ac_enaddr,
		    sizeof(th->iso88025_shost));
		/* Set the source routing bit if neccesary */
		if (th->iso88025_dhost[0] & 0x80) {
			th->iso88025_dhost[0] &= 0x7f;
			if ((th->rcf & 0x001f) - 2)
				th->iso88025_shost[0] |= 0x80;
		}
		/* Copy the addresses, ac and fc into sa_data */
		memcpy(sa.sa_data, th->iso88025_dhost,
		    sizeof(th->iso88025_dhost) * 2);
		sa.sa_data[(sizeof(th->iso88025_dhost) * 2)] = 0x10;
		sa.sa_data[(sizeof(th->iso88025_dhost) * 2) + 1] = 0x40;
		break;
	case IFT_ETHER:
	case IFT_FDDI:
	/*
	 * May not be correct for types not explictly
	 * listed, but it is our best guess.
	 */
	default:
		eh = (struct ether_header *)sa.sa_data;
		(void)memcpy(eh->ether_dhost, ea->arp_tha,
		    sizeof(eh->ether_dhost));
		eh->ether_type = htons(ETHERTYPE_ARP);
		break;
	}
	sa.sa_family = AF_UNSPEC;
	sa.sa_len = sizeof(sa);
	(*ac->ac_if.if_output)(&ac->ac_if, m, &sa, (struct rtentry *)0);
	return;
}
#endif

/*
 * Free an arp entry.
 */
static void
arptfree(la)
	register struct llinfo_arp *la;
{
	register struct rtentry *rt = la->la_rt;
	register struct sockaddr_dl *sdl;
	if (rt == 0)
		panic("arptfree");
	if (rt->rt_refcnt > 0 && (sdl = SDL(rt->rt_gateway)) &&
	    sdl->sdl_family == AF_LINK) {
		sdl->sdl_alen = 0;
		la->la_asked = 0;
		rt->rt_flags &= ~RTF_REJECT;
		return;
	}
	rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0, rt_mask(rt),
			0, (struct rtentry **)0);
}
/*
 * Lookup or enter a new address in arptab.
 */
static struct llinfo_arp *
arplookup(addr, create, proxy)
	u_long addr;
	int create, proxy;
{
	register struct rtentry *rt;
	static struct sockaddr_inarp sin = {sizeof(sin), AF_INET };
	const char *why = 0;

	sin.sin_addr.s_addr = addr;
	sin.sin_other = proxy ? SIN_PROXY : 0;
	rt = rtalloc1((struct sockaddr *)&sin, create, 0UL);
	if (rt == 0)
		return (0);
	rt->rt_refcnt--;

	if (rt->rt_flags & RTF_GATEWAY)
		why = "host is not on local network";
	else if ((rt->rt_flags & RTF_LLINFO) == 0)
		why = "could not allocate llinfo";
	else if (rt->rt_gateway->sa_family != AF_LINK)
		why = "gateway route is not ours";

	if (why && create) {
		log(LOG_DEBUG, "arplookup %s failed: %s\n",
		    inet_ntoa(sin.sin_addr), why);
		return 0;
	} else if (why) {
		return 0;
	}
	return ((struct llinfo_arp *)rt->rt_llinfo);
}

void
arp_ifinit(ac, ifa)
	struct arpcom *ac;
	struct ifaddr *ifa;
{
	if (ntohl(IA_SIN(ifa)->sin_addr.s_addr) != INADDR_ANY)
		arprequest(ac, &IA_SIN(ifa)->sin_addr,
			       &IA_SIN(ifa)->sin_addr, ac->ac_enaddr);
	ifa->ifa_rtrequest = arp_rtrequest;
	ifa->ifa_flags |= RTF_CLONING;
}
