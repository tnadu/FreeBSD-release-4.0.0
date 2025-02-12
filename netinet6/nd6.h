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
 * $FreeBSD: src/sys/netinet6/nd6.h,v 1.2 1999/12/07 17:39:15 shin Exp $
 */

#ifndef _NETINET6_ND6_H_
#define	_NETINET6_ND6_H_

#include <sys/queue.h>

struct	llinfo_nd6 {
	struct	llinfo_nd6 *ln_next;
	struct	llinfo_nd6 *ln_prev;
	struct	rtentry *ln_rt;
	struct	mbuf *ln_hold;	/* last packet until resolved/timeout */
	long	ln_asked;	/* number of queries already sent for this addr */
	u_long	ln_expire;	/* lifetime for NDP state transition */
	short	ln_state;	/* reachability state */
	short	ln_router;	/* 2^0: ND6 router bit */
};

#define	ND6_LLINFO_NOSTATE	-2
#define	ND6_LLINFO_WAITDELETE	-1
#define	ND6_LLINFO_INCOMPLETE	0
#define	ND6_LLINFO_REACHABLE	1
#define	ND6_LLINFO_STALE	2
#define	ND6_LLINFO_DELAY	3
#define	ND6_LLINFO_PROBE	4

struct nd_ifinfo {
	u_int32_t	linkmtu;	/* LinkMTU */
	u_int32_t	maxmtu;		/* Upper bound of LinkMTU */
	u_int32_t	basereachable;	/* BaseReachableTime */
	u_int32_t	reachable;	/* Reachable Time */
	u_int32_t	retrans;	/* Retrans Timer */
	int	recalctm;		/* BaseReacable re-calculation timer */
	u_int8_t	chlim;		/* CurHopLimit */
	u_int8_t	receivedra;
};

struct in6_nbrinfo {
	char	ifname[IFNAMSIZ];	/* if name, e.g. "en0" */
	struct	in6_addr addr;	/* IPv6 address of the neighbor */
	long	asked;		/* number of queries already sent for this addr */
	int	isrouter;	/* if it acts as a router */
	int	state;		/* reachability state */
	int	expire;		/* lifetime for NDP state transition */
};

#define	DRLSTSIZ 10
#define	PRLSTSIZ 10
struct	in6_drlist {
	char	ifname[IFNAMSIZ];
	struct {
		struct	in6_addr rtaddr;
		u_char	flags;
		u_short	rtlifetime;
		u_long	expire;
		u_short	if_index;
	} defrouter[DRLSTSIZ];
};

struct	in6_prlist {
	char	ifname[IFNAMSIZ];
	struct {
		struct	in6_addr prefix;
		struct	prf_ra raflags;
		u_char	prefixlen;
		u_long	vltime;
		u_long	pltime;
		u_long	expire;
		u_short	if_index;
		u_short	advrtrs; /* number of advertisement routers */
		struct	in6_addr advrtr[DRLSTSIZ]; /* XXX: explicit limit */
	} prefix[PRLSTSIZ];
};

struct	in6_ndireq {
	char	ifname[IFNAMSIZ];
	struct	nd_ifinfo ndi;
};

/* protocol constants */
#define	MAX_RTR_SOLICITATION_DELAY	1	/*1sec*/
#define	RTR_SOLICITATION_INTERVAL	4	/*4sec*/
#define	MAX_RTR_SOLICITATIONS		3

#define	ND6_INFINITE_LIFETIME		0xffffffff

#ifdef _KERNEL
/* node constants */
#define	MAX_REACHABLE_TIME		3600000	/* msec */
#define	REACHABLE_TIME			30000	/* msec */
#define	RETRANS_TIMER			1000	/* msec */
#define	MIN_RANDOM_FACTOR		512	/* 1024 * 0.5 */
#define	MAX_RANDOM_FACTOR		1536	/* 1024 * 1.5 */
#define	ND_COMPUTE_RTIME(x) \
		(((MIN_RANDOM_FACTOR * (x >> 10)) + (random() & \
		((MAX_RANDOM_FACTOR - MIN_RANDOM_FACTOR) * (x >> 10)))) /1000)

struct	nd_defrouter {
	LIST_ENTRY(nd_defrouter)	dr_entry;
	struct	in6_addr rtaddr;
	u_char	flags;
	u_short	rtlifetime;
	u_long	expire;
	struct	ifnet *ifp;
};

struct nd_prefix {
	struct	ifnet *ndpr_ifp;
	LIST_ENTRY(nd_prefix) ndpr_entry;
	struct	sockaddr_in6 ndpr_prefix;	/* prefix */
	struct	in6_addr ndpr_mask; /* netmask derived from the prefix */
	struct	in6_addr ndpr_addr; /* address that is derived from the prefix */
	u_int32_t	ndpr_vltime;	/* advertised valid lifetime */
	u_int32_t	ndpr_pltime;	/* advertised preferred lifetime */
	time_t	ndpr_expire;	/* expiration time of the prefix */
	time_t	ndpr_preferred;	/* preferred time of the prefix */
	struct	prf_ra ndpr_flags;
	/* list of routers that advertise the prefix: */
	LIST_HEAD(pr_rtrhead, nd_pfxrouter) ndpr_advrtrs;
	u_char	ndpr_plen;
	struct	ndpr_stateflags {
		/* if this prefix can be regarded as on-link */
		u_char	onlink : 1;
	} ndpr_stateflags;
};

#define	ndpr_raf		ndpr_flags
#define	ndpr_raf_onlink		ndpr_flags.onlink
#define	ndpr_raf_auto		ndpr_flags.autonomous

#define	ndpr_statef_onlink	ndpr_stateflags.onlink
#define	ndpr_statef_addmark	ndpr_stateflags.addmark

/*
 * We keep expired prefix for certain amount of time, for validation purposes.
 * 1800s = MaxRtrAdvInterval
 */
#define	NDPR_KEEP_EXPIRED	(1800 * 2)

/*
 * Message format for use in obtaining information about prefixes
 * from inet6 sysctl function
 */
struct inet6_ndpr_msghdr {
	u_short	inpm_msglen;	/* to skip over non-understood messages */
	u_char	inpm_version;	/* future binary compatability */
	u_char	inpm_type;	/* message type */
	struct	in6_addr inpm_prefix;
	u_long	prm_vltim;
	u_long	prm_pltime;
	u_long	prm_expire;
	u_long	prm_preferred;
	struct	in6_prflags prm_flags;
	u_short	prm_index;	/* index for associated ifp */
	u_char	prm_plen;	/* length of prefix in bits */
};

#define	prm_raf_onlink		prm_flags.prf_ra.onlink
#define	prm_raf_auto		prm_flags.prf_ra.autonomous

#define	prm_statef_onlink	prm_flags.prf_state.onlink

#define	prm_rrf_decrvalid	prm_flags.prf_rr.decrvalid
#define	prm_rrf_decrprefd	prm_flags.prf_rr.decrprefd

#define	ifpr2ndpr(ifpr)	((struct nd_prefix *)(ifpr))
#define	ndpr2ifpr(ndpr)	((struct ifprefix *)(ndpr))

struct nd_pfxrouter {
	LIST_ENTRY(nd_pfxrouter) pfr_entry;
	struct	nd_defrouter *router;
};

LIST_HEAD(nd_drhead, nd_defrouter);
LIST_HEAD(nd_prhead, nd_prefix);

/* nd6.c */
extern int	nd6_prune;
extern int	nd6_delay;
extern int	nd6_umaxtries;
extern int	nd6_mmaxtries;
extern int	nd6_useloopback;
extern int	nd6_proxyall;
extern struct	llinfo_nd6 llinfo_nd6;
extern struct	nd_ifinfo *nd_ifinfo;
extern struct	nd_drhead nd_defrouter;
extern struct	nd_prhead nd_prefix;

union nd_opts {
	struct	nd_opt_hdr *nd_opt_array[9];
	struct {
		struct	nd_opt_hdr *zero;
		struct	nd_opt_hdr *src_lladdr;
		struct	nd_opt_hdr *tgt_lladdr;
		struct	nd_opt_prefix_info *pi_beg;/* multiple opts, start */
		struct	nd_opt_rd_hdr *rh;
		struct	nd_opt_mtu *mtu;
		struct	nd_opt_hdr *search;	/* multiple opts */
		struct	nd_opt_hdr *last;	/* multiple opts */
		int	done;
		struct	nd_opt_prefix_info *pi_end;/* multiple opts, end */
	} nd_opt_each;
};
#define	nd_opts_src_lladdr	nd_opt_each.src_lladdr
#define	nd_opts_tgt_lladdr	nd_opt_each.tgt_lladdr
#define	nd_opts_pi		nd_opt_each.pi_beg
#define	nd_opts_pi_end		nd_opt_each.pi_end
#define	nd_opts_rh		nd_opt_each.rh
#define	nd_opts_mtu		nd_opt_each.mtu
#define	nd_opts_search		nd_opt_each.search
#define	nd_opts_last		nd_opt_each.last
#define	nd_opts_done		nd_opt_each.done

/* XXX: need nd6_var.h?? */
/* nd6.c */
void	nd6_init __P((void));
void	nd6_ifattach __P((struct ifnet *));
int	nd6_is_addr_neighbor __P((struct in6_addr *, struct ifnet *));
void	nd6_option_init __P((void *, int, union nd_opts *));
struct	nd_opt_hdr *nd6_option __P((union nd_opts *));
int	nd6_options __P((union nd_opts *));
struct	rtentry *nd6_lookup __P((struct in6_addr *, int, struct ifnet *));
void	nd6_setmtu __P((struct ifnet *));
void	nd6_timer __P((void *));
void	nd6_free __P((struct rtentry *));
void	nd6_nud_hint __P((struct rtentry *, struct in6_addr *));
int	nd6_resolve __P((struct ifnet *, struct rtentry *,
			 struct mbuf *, struct sockaddr *, u_char *));
void	nd6_rtrequest __P((int, struct rtentry *, struct sockaddr *));
void	nd6_p2p_rtrequest __P((int, struct rtentry *, struct sockaddr *));
int	nd6_ioctl __P((u_long, caddr_t, struct ifnet *));
struct	rtentry *nd6_cache_lladdr __P((struct ifnet *, struct in6_addr *,
				       char *, int, int, int));
/* for test */
int	nd6_output __P((struct ifnet *, struct mbuf *, struct sockaddr_in6 *,
			struct rtentry *));
int	nd6_storelladdr __P((struct ifnet *, struct rtentry *, struct mbuf *,
			     struct sockaddr *, u_char *));

/* nd6_nbr.c */
void	nd6_na_input __P((struct mbuf *, int, int));
void	nd6_na_output __P((struct ifnet *, struct in6_addr *,
			   struct in6_addr *, u_long, int));
void	nd6_ns_input __P((struct mbuf *, int, int));
void	nd6_ns_output __P((struct ifnet *, struct in6_addr *,
			   struct in6_addr *, struct llinfo_nd6 *, int));
caddr_t	nd6_ifptomac __P((struct ifnet *));
void	nd6_dad_start __P((struct ifaddr *, int *));
void	nd6_dad_duplicated __P((struct ifaddr *));

/* nd6_rtr.c */
void	nd6_rs_input __P((struct mbuf *, int, int));
void	nd6_ra_input __P((struct mbuf *, int, int));
void	prelist_del __P((struct nd_prefix *));
void	defrouter_addreq __P((struct nd_defrouter *));
void	defrouter_delreq __P((struct nd_defrouter *, int));
void	defrtrlist_del __P((struct nd_defrouter *));
void	prelist_remove __P((struct nd_prefix *));
int	prelist_update __P((struct nd_prefix *, struct nd_defrouter *,
			    struct mbuf *));
struct	nd_defrouter *defrouter_lookup __P((struct in6_addr *,
					    struct ifnet *));
int	in6_ifdel __P((struct ifnet *, struct in6_addr *));
int	in6_init_prefix_ltimes __P((struct nd_prefix *ndpr));
void	rt6_flush __P((struct in6_addr *, struct ifnet *));

#endif /* _KERNEL */

#endif /* _NETINET6_ND6_H_ */
