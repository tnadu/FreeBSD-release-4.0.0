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
 * $FreeBSD: src/sys/netinet6/ipsec.c,v 1.3 2000/01/15 14:56:38 shin Exp $
 */

/*
 * IPsec controller part.
 */

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_ecn.h>
#ifdef INET6
#include <netinet6/ip6_ecn.h>
#endif

#ifdef INET6
#include <netinet6/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/icmp6.h>
#endif /*INET6*/

#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#ifdef INET6
#include <netinet6/ipsec6.h>
#include <netinet6/ah6.h>
#endif
#ifdef IPSEC_ESP
#include <netinet6/esp.h>
#ifdef INET6
#include <netinet6/esp6.h>
#endif
#endif

#include <netkey/key.h>
#include <netkey/key_var.h>
#include <netkey/keydb.h>
#ifdef IPSEC_DEBUG
#include <netkey/key_debug.h>
#else
#define	KEYDEBUG(lev,arg)
#endif

struct ipsecstat ipsecstat;
int ip4_inbound_call_ike = 0;
int ip4_ah_cleartos = 1;
int ip4_ah_offsetmask = 0;	/* maybe IP_DF? */
int ip4_ipsec_dfbit = 0;	/* DF bit on encap. 0: clear 1: set 2: copy */
int ip4_esp_trans_deflev = IPSEC_LEVEL_USE;
int ip4_esp_net_deflev = IPSEC_LEVEL_USE;
int ip4_ah_trans_deflev = IPSEC_LEVEL_USE;
int ip4_ah_net_deflev = IPSEC_LEVEL_USE;
struct secpolicy ip4_def_policy;
int ip4_ipsec_ecn = 0;		/* ECN ignore(-1)/forbidden(0)/allowed(1) */

/* net.inet.ipsec */
SYSCTL_STRUCT(_net_inet_ipsec, IPSECCTL_STATS,
	stats, CTLFLAG_RD,	&ipsecstat,	ipsecstat, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_POLICY,
	def_policy, CTLFLAG_RW,	&ip4_def_policy.policy,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_ESP_TRANSLEV, esp_trans_deflev,
	CTLFLAG_RW, &ip4_esp_trans_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_ESP_NETLEV, esp_net_deflev,
	CTLFLAG_RW, &ip4_esp_net_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_AH_TRANSLEV, ah_trans_deflev,
	CTLFLAG_RW, &ip4_ah_trans_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_AH_NETLEV, ah_net_deflev,
	CTLFLAG_RW, &ip4_ah_net_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_INBOUND_CALL_IKE,
	inbound_call_ike, CTLFLAG_RW,	&ip4_inbound_call_ike,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_AH_CLEARTOS,
	ah_cleartos, CTLFLAG_RW,	&ip4_ah_cleartos,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_AH_OFFSETMASK,
	ah_offsetmask, CTLFLAG_RW,	&ip4_ah_offsetmask,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DFBIT,
	dfbit, CTLFLAG_RW,	&ip4_ipsec_dfbit,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_ECN,
	ecn, CTLFLAG_RW,	&ip4_ipsec_ecn,	0, "");

#ifdef INET6
struct ipsecstat ipsec6stat;
int ip6_inbound_call_ike = 0;
int ip6_esp_trans_deflev = IPSEC_LEVEL_USE;
int ip6_esp_net_deflev = IPSEC_LEVEL_USE;
int ip6_ah_trans_deflev = IPSEC_LEVEL_USE;
int ip6_ah_net_deflev = IPSEC_LEVEL_USE;
struct secpolicy ip6_def_policy;
int ip6_ipsec_ecn = 0;		/* ECN ignore(-1)/forbidden(0)/allowed(1) */

/* net.inet6.ipsec6 */
SYSCTL_STRUCT(_net_inet6_ipsec6, IPSECCTL_STATS,
	stats, CTLFLAG_RD, &ipsec6stat, ipsecstat, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_POLICY,
	def_policy, CTLFLAG_RW,	&ip6_def_policy.policy,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_ESP_TRANSLEV, esp_trans_deflev,
	CTLFLAG_RW, &ip6_esp_trans_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_ESP_NETLEV, esp_net_deflev,
	CTLFLAG_RW, &ip6_esp_net_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_AH_TRANSLEV, ah_trans_deflev,
	CTLFLAG_RW, &ip6_ah_trans_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_AH_NETLEV, ah_net_deflev,
	CTLFLAG_RW, &ip6_ah_net_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_INBOUND_CALL_IKE,
	inbound_call_ike, CTLFLAG_RW,	&ip6_inbound_call_ike,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_ECN,
	ecn, CTLFLAG_RW,	&ip6_ipsec_ecn,	0, "");
#endif /* INET6 */

static int ipsec_setspidx_mbuf
	__P((struct secpolicyindex *, u_int, u_int, struct mbuf *));
static void ipsec4_setspidx_inpcb __P((struct mbuf *, struct inpcb *pcb));
static void ipsec4_setspidx_ipaddr __P((struct mbuf *, struct secpolicyindex *));
#ifdef INET6
static u_int16_t ipsec6_get_ulp __P((struct mbuf *m));
static void ipsec6_setspidx_in6pcb __P((struct mbuf *, struct in6pcb *pcb));
static void ipsec6_setspidx_ipaddr __P((struct mbuf *, struct secpolicyindex *));
#endif
static struct secpolicy *ipsec_deepcopy_policy __P((struct secpolicy *src));
static int ipsec_set_policy __P((struct secpolicy **pcb_sp,
	int optname, caddr_t request, int priv));
static int ipsec_get_policy __P((struct secpolicy *pcb_sp, struct mbuf **mp));
static void vshiftl __P((unsigned char *, int, int));
static int ipsec_in_reject __P((struct secpolicy *, struct mbuf *));
static size_t ipsec_hdrsiz __P((struct secpolicy *));
static struct mbuf *ipsec4_splithdr __P((struct mbuf *));
#ifdef INET6
static struct mbuf *ipsec6_splithdr __P((struct mbuf *));
#endif
static int ipsec4_encapsulate __P((struct mbuf *, struct secasvar *));
#ifdef INET6
static int ipsec6_encapsulate __P((struct mbuf *, struct secasvar *));
#endif

#define	KMALLOC(p, t, n) \
	((p) = (t) malloc((unsigned long)(n), M_SECA, M_NOWAIT))
#define	KFREE(p) \
	free((caddr_t)(p), M_SECA);

/*
 * For OUTBOUND packet having a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * OUT:	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occured.
 *	others:	a pointer to SP
 *
 * NOTE: IPv6 mapped adddress concern is implemented here.
 */
struct secpolicy *
ipsec4_getpolicybysock(m, dir, so, error)
	struct mbuf *m;
	u_int dir;
	struct socket *so;
	int *error;
{
	struct inpcbpolicy *pcbsp = NULL;
	struct secpolicy *currsp = NULL;	/* policy on socket */
	struct secpolicy *kernsp = NULL;	/* policy on kernel */

	/* sanity check */
	if (m == NULL || so == NULL || error == NULL)
		panic("ipsec4_getpolicybysock: NULL pointer was passed.\n");

	if ((sotoinpcb(so)->inp_vflag & INP_IPV4) != 0) {
		/* set spidx in pcb */
		ipsec4_setspidx_inpcb(m, sotoinpcb(so));
		pcbsp = sotoinpcb(so)->inp_sp;
	}
#ifdef INET6
	else if ((sotoinpcb(so)->inp_vflag & INP_IPV6) != 0) {
		/* set spidx in pcb */
		ipsec6_setspidx_in6pcb(m, sotoin6pcb(so));
		pcbsp = sotoin6pcb(so)->in6p_sp;
	}
#endif
	else
		panic("ipsec4_getpolicybysock: unsupported address family\n");

	/* sanity check */
	if (pcbsp == NULL)
		panic("ipsec4_getpolicybysock: pcbsp is NULL.\n");

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("send: priv=%d ", pcbsp->priv);
		if (so->so_cred)
			printf("cr_uid=%d\n", so->so_cred->cr_uid);
		);
	switch (dir) {
	case IPSEC_DIR_INBOUND:
		currsp = pcbsp->sp_in;
		break;
	case IPSEC_DIR_OUTBOUND:
		currsp = pcbsp->sp_out;
		break;
	default:
		panic("ipsec4_getpolicybysock: illegal direction.\n");
	}

	/* sanity check */
	if (currsp == NULL)
		panic("ipsec4_getpolicybysock: currsp is NULL.\n");

	/* when privilieged socket */
	if (pcbsp->priv) {
		switch (currsp->policy) {
		case IPSEC_POLICY_BYPASS:
			currsp->refcnt++;
			*error = 0;
			return currsp;

		case IPSEC_POLICY_ENTRUST:
			/* look for a policy in SPD */
			kernsp = key_allocsp(&currsp->spidx, dir);

			/* SP found */
			if (kernsp != NULL) {
				KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
					printf("DP ipsec4_getpolicybysock called "
					       "to allocate SP:%p\n", kernsp));
				*error = 0;
				return kernsp;
			}

			/* no SP found */
			if (ip4_def_policy.policy != IPSEC_POLICY_DISCARD
			 && ip4_def_policy.policy != IPSEC_POLICY_NONE) {
				printf("fixed system default policy:%d->%d\n",
					ip4_def_policy.policy,
					IPSEC_POLICY_NONE);
				ip4_def_policy.policy = IPSEC_POLICY_NONE;
			}
			ip4_def_policy.refcnt++;
			*error = 0;
			return &ip4_def_policy;

		case IPSEC_POLICY_IPSEC:
			currsp->refcnt++;
			*error = 0;
			return currsp;

		default:
			printf("ipsec4_getpolicybysock: "
			      "Invalid policy for PCB %d\n",
				currsp->policy);
			*error = EINVAL;
			return NULL;
		}
		/* NOTREACHED */
	}

	/* when non-privilieged socket */
	/* look for a policy in SPD */
	kernsp = key_allocsp(&currsp->spidx, dir);

	/* SP found */
	if (kernsp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ipsec4_getpolicybysock called "
			       "to allocate SP:%p\n", kernsp));
		*error = 0;
		return kernsp;
	}

	/* no SP found */
	switch (currsp->policy) {
	case IPSEC_POLICY_BYPASS:
		printf("ipsec4_getpolicybysock: "
		       "Illegal policy for non-priviliged defined %d\n",
			currsp->policy);
		*error = EINVAL;
		return NULL;

	case IPSEC_POLICY_ENTRUST:
		if (ip4_def_policy.policy != IPSEC_POLICY_DISCARD
		 && ip4_def_policy.policy != IPSEC_POLICY_NONE) {
			printf("fixed system default policy:%d->%d\n",
				ip4_def_policy.policy,
				IPSEC_POLICY_NONE);
			ip4_def_policy.policy = IPSEC_POLICY_NONE;
		}
		ip4_def_policy.refcnt++;
		*error = 0;
		return &ip4_def_policy;

	case IPSEC_POLICY_IPSEC:
		currsp->refcnt++;
		*error = 0;
		return currsp;

	default:
		printf("ipsec4_getpolicybysock: "
		      "Invalid policy for PCB %d\n",
			currsp->policy);
		*error = EINVAL;
		return NULL;
	}
	/* NOTREACHED */
}

/*
 * For FORWADING packet or OUTBOUND without a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * OUT:	positive: a pointer to the entry for security policy leaf matched.
 *	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occured.
 */
struct secpolicy *
ipsec4_getpolicybyaddr(m, dir, flag, error)
	struct mbuf *m;
	u_int dir;
	int flag;
	int *error;
{
	struct secpolicy *sp = NULL;

	/* sanity check */
	if (m == NULL || error == NULL)
		panic("ipsec4_getpolicybyaddr: NULL pointer was passed.\n");

    {
	struct secpolicyindex spidx;

	bzero(&spidx, sizeof(spidx));

	/* make a index to look for a policy */
	if ((flag & IP_FORWARDING) == IP_FORWARDING) {
		/* Case: IP forwarding */
		*error = ipsec_setspidx_mbuf(&spidx, dir, AF_INET, m);
	} else {
		/* Case: ICMP echo reply */
		*error = ipsec_setspidx_mbuf(&spidx, dir, AF_INET, m);
	}

	if (*error != 0)
		return NULL;

	sp = key_allocsp(&spidx, dir);
    }

	/* SP found */
	if (sp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ipsec4_getpolicybyaddr called "
			       "to allocate SP:%p\n", sp));
		*error = 0;
		return sp;
	}

	/* no SP found */
	if (ip4_def_policy.policy != IPSEC_POLICY_DISCARD
	 && ip4_def_policy.policy != IPSEC_POLICY_NONE) {
		printf("fixed system default policy:%d->%d\n",
			ip4_def_policy.policy,
			IPSEC_POLICY_NONE);
		ip4_def_policy.policy = IPSEC_POLICY_NONE;
	}
	ip4_def_policy.refcnt++;
	*error = 0;
	return &ip4_def_policy;
}

#ifdef INET6
/*
 * For OUTBOUND packet having a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * OUT:	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occured.
 *	others:	a pointer to SP
 */
struct secpolicy *
ipsec6_getpolicybysock(m, dir, so, error)
	struct mbuf *m;
	u_int dir;
	struct socket *so;
	int *error;
{
	struct inpcbpolicy *pcbsp = NULL;
	struct secpolicy *currsp = NULL;	/* policy on socket */
	struct secpolicy *kernsp = NULL;	/* policy on kernel */

	/* sanity check */
	if (m == NULL || so == NULL || error == NULL)
		panic("ipsec6_getpolicybysock: NULL pointer was passed.\n");

	/* set spidx in pcb */
	ipsec6_setspidx_in6pcb(m, sotoin6pcb(so));

	pcbsp = sotoin6pcb(so)->in6p_sp;

	/* sanity check */
	if (pcbsp == NULL)
		panic("ipsec6_getpolicybysock: pcbsp is NULL.\n");

	switch (dir) {
	case IPSEC_DIR_INBOUND:
		currsp = pcbsp->sp_in;
		break;
	case IPSEC_DIR_OUTBOUND:
		currsp = pcbsp->sp_out;
		break;
	default:
		panic("ipsec6_getpolicybysock: illegal direction.\n");
	}

	/* sanity check */
	if (currsp == NULL)
		panic("ipsec6_getpolicybysock: currsp is NULL.\n");

	/* when privilieged socket */
	if (pcbsp->priv) {
		switch (currsp->policy) {
		case IPSEC_POLICY_BYPASS:
			currsp->refcnt++;
			*error = 0;
			return currsp;

		case IPSEC_POLICY_ENTRUST:
			/* look for a policy in SPD */
			kernsp = key_allocsp(&currsp->spidx, dir);

			/* SP found */
			if (kernsp != NULL) {
				KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
					printf("DP ipsec6_getpolicybysock called "
					       "to allocate SP:%p\n", kernsp));
				*error = 0;
				return kernsp;
			}

			/* no SP found */
			if (ip6_def_policy.policy != IPSEC_POLICY_DISCARD
			 && ip6_def_policy.policy != IPSEC_POLICY_NONE) {
				printf("fixed system default policy:%d->%d\n",
					ip6_def_policy.policy,
					IPSEC_POLICY_NONE);
				ip6_def_policy.policy = IPSEC_POLICY_NONE;
			}
			ip6_def_policy.refcnt++;
			*error = 0;
			return &ip6_def_policy;

		case IPSEC_POLICY_IPSEC:
			currsp->refcnt++;
			*error = 0;
			return currsp;

		default:
			printf("ipsec6_getpolicybysock: "
			      "Invalid policy for PCB %d\n",
				currsp->policy);
			*error = EINVAL;
			return NULL;
		}
		/* NOTREACHED */
	}

	/* when non-privilieged socket */
	/* look for a policy in SPD */
	kernsp = key_allocsp(&currsp->spidx, dir);

	/* SP found */
	if (kernsp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ipsec6_getpolicybysock called "
			       "to allocate SP:%p\n", kernsp));
		*error = 0;
		return kernsp;
	}

	/* no SP found */
	switch (currsp->policy) {
	case IPSEC_POLICY_BYPASS:
		printf("ipsec6_getpolicybysock: "
		       "Illegal policy for non-priviliged defined %d\n",
			currsp->policy);
		*error = EINVAL;
		return NULL;

	case IPSEC_POLICY_ENTRUST:
		if (ip6_def_policy.policy != IPSEC_POLICY_DISCARD
		 && ip6_def_policy.policy != IPSEC_POLICY_NONE) {
			printf("fixed system default policy:%d->%d\n",
				ip6_def_policy.policy,
				IPSEC_POLICY_NONE);
			ip6_def_policy.policy = IPSEC_POLICY_NONE;
		}
		ip6_def_policy.refcnt++;
		*error = 0;
		return &ip6_def_policy;

	case IPSEC_POLICY_IPSEC:
		currsp->refcnt++;
		*error = 0;
		return currsp;

	default:
		printf("ipsec6_policybysock: "
		      "Invalid policy for PCB %d\n",
			currsp->policy);
		*error = EINVAL;
		return NULL;
	}
	/* NOTREACHED */
}

/*
 * For FORWADING packet or OUTBOUND without a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * `flag' means that packet is to be forwarded whether or not.
 *	flag = 1: forwad
 * OUT:	positive: a pointer to the entry for security policy leaf matched.
 *	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occured.
 */
#ifndef IP_FORWARDING
#define	IP_FORWARDING 1
#endif

struct secpolicy *
ipsec6_getpolicybyaddr(m, dir, flag, error)
	struct mbuf *m;
	u_int dir;
	int flag;
	int *error;
{
	struct secpolicy *sp = NULL;

	/* sanity check */
	if (m == NULL || error == NULL)
		panic("ipsec6_getpolicybyaddr: NULL pointer was passed.\n");

    {
	struct secpolicyindex spidx;

	bzero(&spidx, sizeof(spidx));

	/* make a index to look for a policy */
	if ((flag & IP_FORWARDING) == IP_FORWARDING) {
		/* Case: IP forwarding */
		*error = ipsec_setspidx_mbuf(&spidx, dir, AF_INET6, m);
	} else {
		/* Case: ICMP echo reply */
		*error = ipsec_setspidx_mbuf(&spidx, dir, AF_INET6, m);
	}

	if (*error != 0)
		return NULL;

	sp = key_allocsp(&spidx, dir);
    }

	/* SP found */
	if (sp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ipsec6_getpolicybyaddr called "
			       "to allocate SP:%p\n", sp));
		*error = 0;
		return sp;
	}

	/* no SP found */
	if (ip6_def_policy.policy != IPSEC_POLICY_DISCARD
	 && ip6_def_policy.policy != IPSEC_POLICY_NONE) {
		printf("fixed system default policy:%d->%d\n",
			ip6_def_policy.policy,
			IPSEC_POLICY_NONE);
		ip6_def_policy.policy = IPSEC_POLICY_NONE;
	}
	ip6_def_policy.refcnt++;
	*error = 0;
	return &ip6_def_policy;
}
#endif /* INET6 */

/*
 * set IP address into spidx from mbuf.
 * When Forwarding packet and ICMP echo reply, this function is used.
 *
 * IN:	get the followings from mbuf.
 *	protocol family, src, dst, next protocol
 * OUT:
 *	0:	success.
 *	other:	failure, and set errno.
 */
int
ipsec_setspidx_mbuf(spidx, dir, family, m)
	struct secpolicyindex *spidx;
	u_int dir, family;
	struct mbuf *m;
{
	/* sanity check */
	if (spidx == NULL || m == NULL)
		panic("ipsec_setspidx_mbuf: NULL pointer was passed.\n");

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_setspidx_mbuf: begin\n"); kdebug_mbuf(m));

	/* initialize */
	bzero(spidx, sizeof(*spidx));

	spidx->dir = dir;
	spidx->src.ss_len = spidx->dst.ss_len = _SALENBYAF(family);
	spidx->src.ss_family = spidx->dst.ss_family = family;
	spidx->prefs = spidx->prefd = _INALENBYAF(family) << 3;

    {
	/* sanity check for packet length. */
	struct mbuf *n;
	int tlen;

	tlen = 0;
	for (n = m; n; n = n->m_next)
		tlen += n->m_len;
	if (m->m_pkthdr.len != tlen) {
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec_setspidx_mbuf: "
			       "total of m_len(%d) != pkthdr.len(%d), "
			       "ignored.\n",
				tlen, m->m_pkthdr.len));
		goto bad;
	}
    }

	switch (family) {
	case AF_INET:
	{
		struct ip *ip;
		struct ip ipbuf;

		/* sanity check 1 for minimum ip header length */
		if (m->m_pkthdr.len < sizeof(struct ip)) {
			KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
				printf("ipsec_setspidx_mbuf: "
				       "pkthdr.len(%d) < sizeof(struct ip), "
				       "ignored.\n",
					m->m_pkthdr.len));
			goto bad;
		}

		/*
		 * get IPv4 header packet.  usually the mbuf is contiguous
		 * and we need no copies.
		 */
		if (m->m_len >= sizeof(*ip))
			ip = mtod(m, struct ip *);
		else {
			m_copydata(m, 0, sizeof(ipbuf), (caddr_t)&ipbuf);
			ip = &ipbuf;
		}

		/* some more checks on IPv4 header. */
		bcopy(&ip->ip_src, _INADDRBYSA(&spidx->src),
			sizeof(ip->ip_src));
		bcopy(&ip->ip_dst, _INADDRBYSA(&spidx->dst),
			sizeof(ip->ip_dst));

		spidx->ul_proto = ip->ip_p;
		_INPORTBYSA(&spidx->src) = IPSEC_PORT_ANY;
		_INPORTBYSA(&spidx->dst) = IPSEC_PORT_ANY;
		break;
	}

#ifdef INET6
	case AF_INET6:
	{
		struct ip6_hdr *ip6_hdr;
		struct ip6_hdr ip6buf;

		/* sanity check 1 for minimum ip header length */
		if (m->m_pkthdr.len < sizeof(struct ip6_hdr)) {
			KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
				printf("ipsec_setspidx_mbuf: "
				       "pkthdr.len(%d) < sizeof(struct ip6_hdr), "
				       "ignored.\n",
					m->m_pkthdr.len));
			goto bad;
		}

		/*
		 * get IPv6 header packet.  usually the mbuf is contiguous
		 * and we need no copies.
		 */
		if (m->m_len >= sizeof(*ip6_hdr))
			ip6_hdr = mtod(m, struct ip6_hdr *);
		else {
			m_copydata(m, 0, sizeof(ip6buf), (caddr_t)&ip6buf);
			ip6_hdr = &ip6buf;
		}

		/* some more checks on IPv4 header. */
		if ((ip6_hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
			KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
				printf("ipsec_setspidx_mbuf: "
					"wrong ip version on packet "
					"(expected IPv6), ignored.\n"));
			goto bad;
		}

		bcopy(&ip6_hdr->ip6_src, _INADDRBYSA(&spidx->src),
			sizeof(ip6_hdr->ip6_src));
		bcopy(&ip6_hdr->ip6_dst, _INADDRBYSA(&spidx->dst),
			sizeof(ip6_hdr->ip6_dst));

		spidx->ul_proto = ipsec6_get_ulp(m);
		_INPORTBYSA(&spidx->src) = IPSEC_PORT_ANY;
		_INPORTBYSA(&spidx->dst) = IPSEC_PORT_ANY;
		break;
	}
#endif /* INET6 */
	default:
		panic("ipsec_secsecidx: no supported family passed.\n");
	}

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_setspidx_mbuf: end\n");
		kdebug_secpolicyindex(spidx));

	return 0;

    bad:
	/* XXX initialize */
	bzero(spidx, sizeof(*spidx));
	return EINVAL;
}

#ifdef INET6
/*
 * Get the number of upper layer protocol.
 * Assumed all extension headers are in single mbuf.
 */
static u_int16_t
ipsec6_get_ulp(m)
	struct mbuf *m;
{
	struct ip6_hdr *ip6;
	struct ip6_ext *ip6e;
	int off, nxt;
	int len;

	/* sanity check */
	if (m == NULL)
		panic("ipsec6_get_ulp: NULL pointer was passed.\n");

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec6_get_ulp:\n"); kdebug_mbuf(m));

	ip6 = mtod(m, struct ip6_hdr *);
	nxt = ip6->ip6_nxt;
	off = sizeof(struct ip6_hdr);
	len = m->m_len;

	while (off < len) {
		ip6e = (struct ip6_ext *)((caddr_t) ip6 + off);
		if (m->m_len < off + sizeof(*ip6e)) {
			printf("ipsec6_get_ulp: all exthdr are not "
				"in single mbuf.\n");
			return IPSEC_PORT_ANY;
		}

		switch(nxt) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMPV6:
			return nxt;
		case IPPROTO_FRAGMENT:
			off += sizeof(struct ip6_frag);
			break;
		case IPPROTO_AH:
			off += (ip6e->ip6e_len + 2) << 2;
			break;
		default:
			switch (nxt) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_ESP:
			case IPPROTO_NONE:
			case IPPROTO_DSTOPTS:
				break;
			default:
				return nxt;	/* XXX */
			}
			off += (ip6e->ip6e_len + 1) << 3;
			break;
		}
		nxt = ip6e->ip6e_nxt;
	}

	return IPSEC_PORT_ANY;
}
#endif

static void
ipsec4_setspidx_inpcb(m, pcb)
	struct mbuf *m;
	struct inpcb *pcb;
{
	struct secpolicyindex *spidx;

	/* sanity check */
	if (pcb == NULL)
		panic("ipsec4_setspidx_inpcb: no PCB found.\n");
	if (pcb->inp_sp == NULL)
		panic("ipsec4_setspidx_inpcb: no inp_sp found.\n");
	if (pcb->inp_sp->sp_out ==NULL || pcb->inp_sp->sp_in == NULL)
		panic("ipsec4_setspidx_inpcb: no sp_in/out found.\n");

	bzero(&pcb->inp_sp->sp_in->spidx, sizeof(*spidx));
	bzero(&pcb->inp_sp->sp_out->spidx, sizeof(*spidx));

	spidx = &pcb->inp_sp->sp_in->spidx;
	spidx->dir = IPSEC_DIR_INBOUND;
	spidx->src.ss_len = spidx->dst.ss_len = _SALENBYAF(AF_INET);
	spidx->src.ss_family = spidx->dst.ss_family = AF_INET;
	spidx->prefs = _INALENBYAF(AF_INET) << 3;
	spidx->prefd = _INALENBYAF(AF_INET) << 3;
	spidx->ul_proto = pcb->inp_socket->so_proto->pr_protocol;
	_INPORTBYSA(&spidx->src) = pcb->inp_fport;
	_INPORTBYSA(&spidx->dst) = pcb->inp_lport;
	ipsec4_setspidx_ipaddr(m, spidx);

	spidx = &pcb->inp_sp->sp_out->spidx;
	spidx->dir = IPSEC_DIR_OUTBOUND;
	spidx->src.ss_len = spidx->dst.ss_len = _SALENBYAF(AF_INET);
	spidx->src.ss_family = spidx->dst.ss_family = AF_INET;
	spidx->prefs = _INALENBYAF(AF_INET) << 3;
	spidx->prefd = _INALENBYAF(AF_INET) << 3;
	spidx->ul_proto = pcb->inp_socket->so_proto->pr_protocol;
	_INPORTBYSA(&spidx->src) = pcb->inp_lport;
	_INPORTBYSA(&spidx->dst) = pcb->inp_fport;
	ipsec4_setspidx_ipaddr(m, spidx);

	return;
}

static void
ipsec4_setspidx_ipaddr(m, spidx)
	struct mbuf *m;
	struct secpolicyindex *spidx;
{
	struct ip *ip = NULL;

	/* sanity check 1 for minimum ip header length */
	if (m == NULL)
		panic("ipsec4_setspidx_in6pcb: m == 0 passed.\n");

	if (m->m_pkthdr.len < sizeof(struct ip)) {
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec4_setspidx_ipaddr: "
			       "pkthdr.len(%d) < sizeof(struct ip), "
			       "ignored.\n",
				m->m_pkthdr.len));
		return;
	}

	if (m->m_len >= sizeof(*ip))
		ip = mtod(m, struct ip *);
	else {
		struct ip ipbuf;

		m_copydata(m, 0, sizeof(ipbuf), (caddr_t)&ipbuf);
		ip = &ipbuf;
	}

	bcopy(&ip->ip_src, _INADDRBYSA(&spidx->src), sizeof(ip->ip_src));
	bcopy(&ip->ip_dst, _INADDRBYSA(&spidx->dst), sizeof(ip->ip_dst));

	return;
}

#ifdef INET6
static void
ipsec6_setspidx_in6pcb(m, pcb)
	struct mbuf *m;
	struct in6pcb *pcb;
{
	struct secpolicyindex *spidx;

	/* sanity check */
	if (pcb == NULL)
		panic("ipsec6_setspidx_in6pcb: no PCB found.\n");
	if (pcb->in6p_sp == NULL)
		panic("ipsec6_setspidx_in6pcb: no in6p_sp found.\n");
	if (pcb->in6p_sp->sp_out ==NULL || pcb->in6p_sp->sp_in == NULL)
		panic("ipsec6_setspidx_in6pcb: no sp_in/out found.\n");

	bzero(&pcb->in6p_sp->sp_in->spidx, sizeof(*spidx));
	bzero(&pcb->in6p_sp->sp_out->spidx, sizeof(*spidx));

	spidx = &pcb->in6p_sp->sp_in->spidx;
	spidx->dir = IPSEC_DIR_INBOUND;
	spidx->src.ss_len = spidx->dst.ss_len = _SALENBYAF(AF_INET6);
	spidx->src.ss_family = spidx->dst.ss_family = AF_INET6;
	spidx->prefs = _INALENBYAF(AF_INET6) << 3;
	spidx->prefd = _INALENBYAF(AF_INET6) << 3;
	spidx->ul_proto = pcb->in6p_socket->so_proto->pr_protocol;
	_INPORTBYSA(&spidx->src) = pcb->in6p_fport;
	_INPORTBYSA(&spidx->dst) = pcb->in6p_lport;
	ipsec6_setspidx_ipaddr(m, spidx);

	spidx = &pcb->in6p_sp->sp_out->spidx;
	spidx->dir = IPSEC_DIR_OUTBOUND;
	spidx->src.ss_len = spidx->dst.ss_len = _SALENBYAF(AF_INET6);
	spidx->src.ss_family = spidx->dst.ss_family = AF_INET6;
	spidx->prefs = _INALENBYAF(AF_INET6) << 3;
	spidx->prefd = _INALENBYAF(AF_INET6) << 3;
	spidx->ul_proto = pcb->in6p_socket->so_proto->pr_protocol;
	_INPORTBYSA(&spidx->src) = pcb->in6p_lport;
	_INPORTBYSA(&spidx->dst) = pcb->in6p_fport;
	ipsec6_setspidx_ipaddr(m, spidx);

	return;
}

static void
ipsec6_setspidx_ipaddr(m, spidx)
	struct mbuf *m;
	struct secpolicyindex *spidx;
{
	struct ip6_hdr *ip6_hdr = NULL;

	/* sanity check 1 for minimum ip header length */
	if (m == NULL)
		panic("ipsec6_setspidx_in6pcb: m == 0 passed.\n");

	if (m->m_pkthdr.len < sizeof(struct ip6_hdr)) {
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec6_setspidx_ipaddr: "
			       "pkthdr.len(%d) < sizeof(struct ip6_hdr), "
			       "ignored.\n",
				m->m_pkthdr.len));
		return;
	}

	if (m->m_len >= sizeof(*ip6_hdr))
		ip6_hdr = mtod(m, struct ip6_hdr *);
	else {
		struct ip6_hdr ip6buf;

		m_copydata(m, 0, sizeof(ip6buf), (caddr_t)&ip6buf);
		ip6_hdr = &ip6buf;
	}

	if ((ip6_hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec_setspidx_mbuf: "
				"wrong ip version on packet "
				"(expected IPv6), ignored.\n"));
		return;
	}

	bcopy(&ip6_hdr->ip6_src, _INADDRBYSA(&spidx->src),
		sizeof(ip6_hdr->ip6_src));
	bcopy(&ip6_hdr->ip6_dst, _INADDRBYSA(&spidx->dst),
		sizeof(ip6_hdr->ip6_dst));

	return;
}
#endif

/* initialize policy in PCB */
int
ipsec_init_policy(so, pcb_sp)
	struct socket *so;
	struct inpcbpolicy **pcb_sp;
{
	struct inpcbpolicy *new;

	/* sanity check. */
	if (so == NULL || pcb_sp == NULL)
		panic("ipsec_init_policy: NULL pointer was passed.\n");

	KMALLOC(new, struct inpcbpolicy *, sizeof(*new));
	if (new == NULL) {
		printf("ipsec_init_policy: No more memory.\n");
		return ENOBUFS;
	}
	bzero(new, sizeof(*new));

	if (so->so_cred != 0 && so->so_cred->cr_uid == 0)
		new->priv = 1;
	else
		new->priv = 0;

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("init: priv=%d ", new->priv);
		if (so->so_cred)
			printf("cr_uid=%d\n", so->so_cred->cr_uid);
		else
			printf("so_cred is NULL\n");
		);

	if ((new->sp_in = key_newsp()) == NULL) {
		KFREE(new);
		return ENOBUFS;
	}
	new->sp_in->state = IPSEC_SPSTATE_ALIVE;
	new->sp_in->policy = IPSEC_POLICY_ENTRUST;

	if ((new->sp_out = key_newsp()) == NULL) {
		key_freesp(new->sp_in);
		KFREE(new);
		return ENOBUFS;
	}
	new->sp_out->state = IPSEC_SPSTATE_ALIVE;
	new->sp_out->policy = IPSEC_POLICY_ENTRUST;

	*pcb_sp = new;

	return 0;
}

/* copy old ipsec policy into new */
int
ipsec_copy_policy(old, new)
	struct inpcbpolicy *old, *new;
{
	struct secpolicy *sp;

	sp = ipsec_deepcopy_policy(old->sp_in);
	if (sp) {
		key_freesp(new->sp_in);
		new->sp_in = sp;
	} else
		return ENOBUFS;

	sp = ipsec_deepcopy_policy(old->sp_out);
	if (sp) {
		key_freesp(new->sp_out);
		new->sp_out = sp;
	} else
		return ENOBUFS;

	new->priv = old->priv;

	return 0;
}

/* deep-copy a policy in PCB */
static struct secpolicy *
ipsec_deepcopy_policy(src)
	struct secpolicy *src;
{
	struct ipsecrequest *newchain = NULL;
	struct ipsecrequest *p;
	struct ipsecrequest **q;
	struct ipsecrequest *r;
	struct secpolicy *dst;

	dst = key_newsp();
	if (src == NULL || dst == NULL)
		return NULL;

	/*
	 * deep-copy IPsec request chain.  This is required since struct
	 * ipsecrequest is not reference counted.
	 */
	q = &newchain;
	for (p = src->req; p; p = p->next) {
		KMALLOC(*q, struct ipsecrequest *, sizeof(struct ipsecrequest));
		if (*q == NULL)
			goto fail;
		bzero(*q, sizeof(**q));
		(*q)->next = NULL;

		(*q)->saidx.proto = p->saidx.proto;
		(*q)->saidx.mode = p->saidx.mode;
		(*q)->level = p->level;

		bcopy(&p->saidx.src, &(*q)->saidx.src, sizeof((*q)->saidx.src));
		bcopy(&p->saidx.dst, &(*q)->saidx.dst, sizeof((*q)->saidx.dst));

		(*q)->sav = NULL;
		(*q)->sp = dst;

		q = &((*q)->next);
	}

	dst->req = newchain;
	dst->state = src->state;
	dst->policy = src->policy;
	/* do not touch the refcnt fields */

	return dst;

fail:
	for (p = newchain; p; p = r) {
		r = p->next;
		KFREE(p);
		p = NULL;
	}
	return NULL;
}

/* set policy and ipsec request if present. */
static int
ipsec_set_policy(pcb_sp, optname, request, priv)
	struct secpolicy **pcb_sp;
	int optname;
	caddr_t request;
	int priv;
{
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)request;
	struct secpolicy *newsp = NULL;

	/* sanity check. */
	if (pcb_sp == NULL || *pcb_sp == NULL || xpl == NULL)
		return EINVAL;

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_set_policy: passed policy\n");
		kdebug_sadb_x_policy((struct sadb_ext *)xpl));

	/* check policy type */
	/* ipsec_set_policy() accepts IPSEC, ENTRUST and BYPASS. */
	if (xpl->sadb_x_policy_type == IPSEC_POLICY_DISCARD
	 || xpl->sadb_x_policy_type == IPSEC_POLICY_NONE)
		return EINVAL;

	/* check privileged socket */
	if (priv == 0 && xpl->sadb_x_policy_type == IPSEC_POLICY_BYPASS)
		return EACCES;

	/* allocation new SP entry */
	if ((newsp = key_msg2sp(xpl)) == NULL)
		return EINVAL;	/* maybe ENOBUFS */

	newsp->state = IPSEC_SPSTATE_ALIVE;

	/* clear old SP and set new SP */
	key_freesp(*pcb_sp);
	*pcb_sp = newsp;
	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_set_policy: new policy\n");
		kdebug_secpolicy(newsp));

	return 0;
}

static int
ipsec_get_policy(pcb_sp, mp)
	struct secpolicy *pcb_sp;
	struct mbuf **mp;
{
	struct sadb_x_policy *xpl;

	/* sanity check. */
	if (pcb_sp == NULL || mp == NULL)
		return EINVAL;

	if ((xpl = key_sp2msg(pcb_sp)) == NULL) {
		printf("ipsec_get_policy: No more memory.\n");
		return ENOBUFS;
	}

	*mp = m_get(M_WAIT, MT_DATA);
	(*mp)->m_len = PFKEY_EXTLEN(xpl);
	m_copyback((*mp), 0, PFKEY_EXTLEN(xpl), (caddr_t)xpl);
	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_get_policy:\n");
		kdebug_mbuf(*mp));

	KFREE(xpl);

	return 0;
}

int
ipsec4_set_policy(inp, optname, request, priv)
	struct inpcb *inp;
	int optname;
	caddr_t request;
	int priv;
{
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)request;
	struct secpolicy **pcb_sp;

	/* sanity check. */
	if (inp == NULL || request == NULL)
		return EINVAL;

	/* select direction */
	switch (xpl->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
		pcb_sp = &inp->inp_sp->sp_in;
		break;
	case IPSEC_DIR_OUTBOUND:
		pcb_sp = &inp->inp_sp->sp_out;
		break;
	default:
		printf("ipsec4_set_policy: invalid direction=%u\n",
			xpl->sadb_x_policy_dir);
		return EINVAL;
	}

	return ipsec_set_policy(pcb_sp, optname, request, priv);
}

int
ipsec4_get_policy(inp, request, mp)
	struct inpcb *inp;
	caddr_t request;
	struct mbuf **mp;
{
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)request;
	struct secpolicy *pcb_sp;

	/* sanity check. */
	if (inp == NULL || request == NULL || mp == NULL)
		return EINVAL;

	/* select direction */
	switch (xpl->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
		pcb_sp = inp->inp_sp->sp_in;
		break;
	case IPSEC_DIR_OUTBOUND:
		pcb_sp = inp->inp_sp->sp_out;
		break;
	default:
		printf("ipsec6_set_policy: invalid direction=%u\n",
			xpl->sadb_x_policy_dir);
		return EINVAL;
	}

	return ipsec_get_policy(pcb_sp, mp);
}

/* delete policy in PCB */
int
ipsec4_delete_pcbpolicy(inp)
	struct inpcb *inp;
{
	/* sanity check. */
	if (inp == NULL)
		panic("ipsec4_delete_pcbpolicy: NULL pointer was passed.\n");

	if (inp->inp_sp->sp_in != NULL) {
		key_freesp(inp->inp_sp->sp_in);
		inp->inp_sp->sp_in = NULL;
	}

	if (inp->inp_sp->sp_out != NULL) {
		key_freesp(inp->inp_sp->sp_out);
		inp->inp_sp->sp_out = NULL;
	}

	KFREE(inp->inp_sp);
	inp->inp_sp = NULL;

	return 0;
}

#ifdef INET6
int
ipsec6_set_policy(in6p, optname, request, priv)
	struct in6pcb *in6p;
	int optname;
	caddr_t request;
	int priv;
{
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)request;
	struct secpolicy **pcb_sp;

	/* sanity check. */
	if (in6p == NULL || request == NULL)
		return EINVAL;

	/* select direction */
	switch (xpl->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
		pcb_sp = &in6p->in6p_sp->sp_in;
		break;
	case IPSEC_DIR_OUTBOUND:
		pcb_sp = &in6p->in6p_sp->sp_out;
		break;
	default:
		printf("ipsec6_set_policy: invalid direction=%u\n",
			xpl->sadb_x_policy_dir);
		return EINVAL;
	}

	return ipsec_set_policy(pcb_sp, optname, request, priv);
}

int
ipsec6_get_policy(in6p, request, mp)
	struct in6pcb *in6p;
	caddr_t request;
	struct mbuf **mp;
{
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)request;
	struct secpolicy *pcb_sp;

	/* sanity check. */
	if (in6p == NULL || request == NULL || mp == NULL)
		return EINVAL;

	/* select direction */
	switch (xpl->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
		pcb_sp = in6p->in6p_sp->sp_in;
		break;
	case IPSEC_DIR_OUTBOUND:
		pcb_sp = in6p->in6p_sp->sp_out;
		break;
	default:
		printf("ipsec6_set_policy: invalid direction=%u\n",
			xpl->sadb_x_policy_dir);
		return EINVAL;
	}

	return ipsec_get_policy(pcb_sp, mp);
}

int
ipsec6_delete_pcbpolicy(in6p)
	struct in6pcb *in6p;
{
	/* sanity check. */
	if (in6p == NULL)
		panic("ipsec6_delete_pcbpolicy: NULL pointer was passed.\n");

	if (in6p->in6p_sp->sp_in != NULL) {
		key_freesp(in6p->in6p_sp->sp_in);
		in6p->in6p_sp->sp_in = NULL;
	}

	if (in6p->in6p_sp->sp_out != NULL) {
		key_freesp(in6p->in6p_sp->sp_out);
		in6p->in6p_sp->sp_out = NULL;
	}

	KFREE(in6p->in6p_sp);
	in6p->in6p_sp = NULL;

	return 0;
}
#endif

/*
 * return current level.
 * IPSEC_LEVEL_USE or IPSEC_LEVEL_REQUIRE are always returned.
 */
u_int
ipsec_get_reqlevel(isr)
	struct ipsecrequest *isr;
{
	u_int level = 0;
	u_int esp_trans_deflev, esp_net_deflev, ah_trans_deflev, ah_net_deflev;

	/* sanity check */
	if (isr == NULL || isr->sp == NULL)
		panic("ipsec_get_reqlevel: NULL pointer is passed.\n");
	if (isr->sp->spidx.src.ss_family != isr->sp->spidx.dst.ss_family)
		panic("ipsec_get_reqlevel: family mismatched.\n");

#define	IPSEC_CHECK_DEFAULT(lev) \
        (((lev) != IPSEC_LEVEL_USE && (lev) != IPSEC_LEVEL_REQUIRE) \
                ? (printf("fixed system default level " #lev ":%d->%d\n", \
			(lev), IPSEC_LEVEL_USE), \
			(lev) = IPSEC_LEVEL_USE) : (lev))

	/* set default level */
	switch (isr->sp->spidx.src.ss_family) {
#ifdef INET
	case AF_INET:
		esp_trans_deflev = IPSEC_CHECK_DEFAULT(ip4_esp_trans_deflev);
		esp_net_deflev = IPSEC_CHECK_DEFAULT(ip4_esp_net_deflev);
		ah_trans_deflev = IPSEC_CHECK_DEFAULT(ip4_ah_trans_deflev);
		ah_net_deflev = IPSEC_CHECK_DEFAULT(ip4_ah_net_deflev);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		esp_trans_deflev = IPSEC_CHECK_DEFAULT(ip6_esp_trans_deflev);
		esp_net_deflev = IPSEC_CHECK_DEFAULT(ip6_esp_net_deflev);
		ah_trans_deflev = IPSEC_CHECK_DEFAULT(ip6_ah_trans_deflev);
		ah_net_deflev = IPSEC_CHECK_DEFAULT(ip6_ah_net_deflev);
		break;
#endif /* INET6 */
	default:
		panic("key_get_reqlevel: Unknown family. %d\n",
			isr->sp->spidx.src.ss_family);
	}

#undef IPSEC_CHECK_DEFAULT(lev)

	/* set level */
	switch (isr->level) {
	case IPSEC_LEVEL_DEFAULT:
		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
			if (isr->saidx.mode == IPSEC_MODE_TUNNEL)
				level = esp_net_deflev;
			else
				level = esp_trans_deflev;
			break;
		case IPPROTO_AH:
			if (isr->saidx.mode == IPSEC_MODE_TUNNEL)
				level = ah_net_deflev;
			else
				level = ah_trans_deflev;
		default:
			panic("ipsec_get_reqlevel: "
				"Illegal protocol defined %u\n",
				isr->saidx.proto);
		}
		break;

	case IPSEC_LEVEL_USE:
	case IPSEC_LEVEL_REQUIRE:
		level = isr->level;
		break;

	default:
		panic("ipsec_get_reqlevel: Illegal IPsec level %u\n",
			isr->level);
	}

	return level;
}

/*
 * Check AH/ESP integrity.
 * OUT:
 *	0: valid
 *	1: invalid
 */
static int
ipsec_in_reject(sp, m)
	struct secpolicy *sp;
	struct mbuf *m;
{
	struct ipsecrequest *isr;
	u_int level;
	int need_auth, need_conf, need_icv;

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec_in_reject: using SP\n");
		kdebug_secpolicy(sp));

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
		return 1;
	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		return 0;

	case IPSEC_POLICY_IPSEC:
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		panic("ipsec_hdrsiz: Invalid policy found. %d\n", sp->policy);
	}

	need_auth = 0;
	need_conf = 0;
	need_icv = 0;

	for (isr = sp->req; isr != NULL; isr = isr->next) {

		/* get current level */
		level = ipsec_get_reqlevel(isr);

		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
			if (level == IPSEC_LEVEL_REQUIRE) {
				need_conf++;

				if (isr->sav != NULL
				 && isr->sav->flags == SADB_X_EXT_NONE
				 && isr->sav->alg_auth != SADB_AALG_NONE)
					need_icv++;
			}
			break;
		case IPPROTO_AH:
			if (level == IPSEC_LEVEL_REQUIRE) {
				need_auth++;
				need_icv++;
			}
			break;
		}
	}

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_in_reject: auth:%d conf:%d icv:%d m_flags:%x\n",
			need_auth, need_conf, need_icv, m->m_flags));

	if ((need_conf && !(m->m_flags & M_DECRYPTED))
	 || (!need_auth && need_icv && !(m->m_flags & M_AUTHIPDGM))
	 || (need_auth && !(m->m_flags & M_AUTHIPHDR)))
		return 1;

	return 0;
}

/*
 * Check AH/ESP integrity.
 * This function is called from tcp_input(), udp_input(),
 * and {ah,esp}4_input for tunnel mode
 */
int
ipsec4_in_reject_so(m, so)
	struct mbuf *m;
	struct socket *so;
{
	struct secpolicy *sp = NULL;
	int error;
	int result;

	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX should be panic ? */

	/* get SP for this packet.
	 * When we are called from ip_forward(), we call
	 * ipsec4_getpolicybyaddr() with IP_FORWARDING flag.
	 */
	if (so == NULL)
		sp = ipsec4_getpolicybyaddr(m, IPSEC_DIR_INBOUND, IP_FORWARDING, &error);
	else
		sp = ipsec4_getpolicybysock(m, IPSEC_DIR_INBOUND, so, &error);

	if (sp == NULL)
		return 0;	/* XXX should be panic ?
				 * -> No, there may be error. */

	result = ipsec_in_reject(sp, m);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP ipsec4_in_reject_so call free SP:%p\n", sp));
	key_freesp(sp);

	return result;
}

int
ipsec4_in_reject(m, inp)
	struct mbuf *m;
	struct inpcb *inp;
{
	if (inp == NULL)
		return ipsec4_in_reject_so(m, NULL);
	else {
		if (inp->inp_socket)
			return ipsec4_in_reject_so(m, inp->inp_socket);
		else
			panic("ipsec4_in_reject: invalid inpcb/socket");
	}
}

#ifdef INET6
/*
 * Check AH/ESP integrity.
 * This function is called from tcp6_input(), udp6_input(),
 * and {ah,esp}6_input for tunnel mode
 */
int
ipsec6_in_reject_so(m, so)
	struct mbuf *m;
	struct socket *so;
{
	struct secpolicy *sp = NULL;
	int error;
	int result;

	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX should be panic ? */

	/* get SP for this packet.
	 * When we are called from ip_forward(), we call
	 * ipsec6_getpolicybyaddr() with IP_FORWARDING flag.
	 */
	if (so == NULL)
		sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_INBOUND, IP_FORWARDING, &error);
	else
		sp = ipsec6_getpolicybysock(m, IPSEC_DIR_INBOUND, so, &error);

	if (sp == NULL)
		return 0;	/* XXX should be panic ? */

	result = ipsec_in_reject(sp, m);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP ipsec6_in_reject_so call free SP:%p\n", sp));
	key_freesp(sp);

	return result;
}

int
ipsec6_in_reject(m, in6p)
	struct mbuf *m;
	struct in6pcb *in6p;
{
	if (in6p == NULL)
		return ipsec6_in_reject_so(m, NULL);
	else {
		if (in6p->in6p_socket)
			return ipsec6_in_reject_so(m, in6p->in6p_socket);
		else
			panic("ipsec6_in_reject: invalid in6p/socket");
	}
}
#endif

/*
 * compute the byte size to be occupied by IPsec header.
 * in case it is tunneled, it includes the size of outer IP header.
 * NOTE: SP passed is free in this function.
 */
static size_t
ipsec_hdrsiz(sp)
	struct secpolicy *sp;
{
	struct ipsecrequest *isr;
	size_t siz, clen;

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec_in_reject: using SP\n");
		kdebug_secpolicy(sp));

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		return 0;

	case IPSEC_POLICY_IPSEC:
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		panic("ipsec_hdrsiz: Invalid policy found. %d\n", sp->policy);
	}

	siz = 0;

	for (isr = sp->req; isr != NULL; isr = isr->next) {

		clen = 0;

		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
#ifdef IPSEC_ESP
			clen = esp_hdrsiz(isr);
#else
			clen = 0;	/*XXX*/
#endif
			break;
		case IPPROTO_AH:
			clen = ah_hdrsiz(isr);
			break;
		}

		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			switch (isr->saidx.dst.ss_family) {
			case AF_INET:
				clen += sizeof(struct ip);
				break;
#ifdef INET6
			case AF_INET6:
				clen += sizeof(struct ip6_hdr);
				break;
#endif
			default:
				printf("ipsec_hdrsiz: unknown AF %d "
					"in IPsec tunnel SA\n",
					isr->saidx.dst.ss_family);
				break;
			}
		}
		siz += clen;
	}

	return siz;
}

/* This function is called from ip_forward() and ipsec4_hdrsize_tcp(). */
size_t
ipsec4_hdrsiz(m, dir, inp)
	struct mbuf *m;
	u_int dir;
	struct inpcb *inp;
{
	struct secpolicy *sp = NULL;
	int error;
	size_t size;

	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX should be panic ? */
	if (inp != NULL && inp->inp_socket == NULL)
		panic("ipsec4_hdrsize: why is socket NULL but there is PCB.");

	/* get SP for this packet.
	 * When we are called from ip_forward(), we call
	 * ipsec4_getpolicybyaddr() with IP_FORWARDING flag.
	 */
	if (inp == NULL)
		sp = ipsec4_getpolicybyaddr(m, dir, IP_FORWARDING, &error);
	else
		sp = ipsec4_getpolicybysock(m, dir, inp->inp_socket, &error);

	if (sp == NULL)
		return 0;	/* XXX should be panic ? */

	size = ipsec_hdrsiz(sp);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP ipsec4_hdrsiz call free SP:%p\n", sp));
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec4_hdrsiz: size:%lu.\n", (unsigned long)size));
	key_freesp(sp);

	return size;
}

#ifdef INET6
/* This function is called from ipsec6_hdrsize_tcp(),
 * and maybe from ip6_forward.()
 */
size_t
ipsec6_hdrsiz(m, dir, in6p)
	struct mbuf *m;
	u_int dir;
	struct in6pcb *in6p;
{
	struct secpolicy *sp = NULL;
	int error;
	size_t size;

	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX shoud be panic ? */
	if (in6p != NULL && in6p->in6p_socket == NULL)
		panic("ipsec6_hdrsize: why is socket NULL but there is PCB.");

	/* get SP for this packet */
	/* XXX Is it right to call with IP_FORWARDING. */
	if (in6p == NULL)
		sp = ipsec6_getpolicybyaddr(m, dir, IP_FORWARDING, &error);
	else
		sp = ipsec6_getpolicybysock(m, dir, in6p->in6p_socket, &error);

	if (sp == NULL)
		return 0;
	size = ipsec_hdrsiz(sp);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP ipsec6_hdrsiz call free SP:%p\n", sp));
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec6_hdrsiz: size:%lu.\n", (unsigned long)size));
	key_freesp(sp);

	return size;
}
#endif /*INET6*/

#ifdef INET
/*
 * encapsulate for ipsec tunnel.
 * ip->ip_src must be fixed later on.
 */
static int
ipsec4_encapsulate(m, sav)
	struct mbuf *m;
	struct secasvar *sav;
{
	struct ip *oip;
	struct ip *ip;
	size_t hlen;
	size_t plen;

	/* can't tunnel between different AFs */
	if (sav->sah->saidx.src.ss_family != sav->sah->saidx.dst.ss_family
	 || sav->sah->saidx.src.ss_family != AF_INET) {
		m_freem(m);
		return EINVAL;
	}

	ip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	/* generate header checksum */
	ip->ip_sum = 0;
#ifdef _IP_VHL
	if (ip->ip_vhl == IP_VHL_BORING)
		ip->ip_sum = in_cksum_hdr(ip);
	else
		ip->ip_sum = in_cksum(m, hlen);
#else
	ip->ip_sum = in_cksum(m, hlen);
#endif

	plen = m->m_pkthdr.len;

	/*
	 * grow the mbuf to accomodate the new IPv4 header.
	 * NOTE: IPv4 options will never be copied.
	 */
	if (m->m_len != hlen)
		panic("ipsec4_encapsulate: assumption failed (first mbuf length)");
	if (M_LEADINGSPACE(m->m_next) < hlen) {
		struct mbuf *n;
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		n->m_len = hlen;
		n->m_next = m->m_next;
		m->m_next = n;
		m->m_pkthdr.len += hlen;
		oip = mtod(n, struct ip *);
	} else {
		m->m_next->m_len += hlen;
		m->m_next->m_data -= hlen;
		m->m_pkthdr.len += hlen;
		oip = mtod(m->m_next, struct ip *);
	}
	ip = mtod(m, struct ip *);
	ovbcopy((caddr_t)ip, (caddr_t)oip, hlen);
	m->m_len = sizeof(struct ip);
	m->m_pkthdr.len -= (hlen - sizeof(struct ip));

	/* construct new IPv4 header. see RFC 2401 5.1.2.1 */
	/* ECN consideration. */
	ip_ecn_ingress(ip4_ipsec_ecn, &ip->ip_tos, &oip->ip_tos);
#ifdef _IP_VHL
	ip->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof(struct ip) >> 2);
#else
	ip->ip_hl = sizeof(struct ip) >> 2;
#endif
	ip->ip_off &= htons(~IP_OFFMASK);
	ip->ip_off &= htons(~IP_MF);
	switch (ip4_ipsec_dfbit) {
	case 0:	/*clear DF bit*/
		ip->ip_off &= htons(~IP_DF);
		break;
	case 1:	/*set DF bit*/
		ip->ip_off |= htons(IP_DF);
		break;
	default:	/*copy DF bit*/
		break;
	}
	ip->ip_p = IPPROTO_IPIP;
	if (plen + sizeof(struct ip) < IP_MAXPACKET)
		ip->ip_len = htons(plen + sizeof(struct ip));
	else {
		printf("IPv4 ipsec: size exceeds limit: "
			"leave ip_len as is (invalid packet)\n");
	}
	ip->ip_id = htons(ip_id++);
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.src)->sin_addr,
		&ip->ip_src, sizeof(ip->ip_src));
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.dst)->sin_addr,
		&ip->ip_dst, sizeof(ip->ip_dst));

	/* XXX Should ip_src be updated later ? */

	return 0;
}
#endif /*INET*/

#ifdef INET6
static int
ipsec6_encapsulate(m, sav)
	struct mbuf *m;
	struct secasvar *sav;
{
	struct ip6_hdr *oip6;
	struct ip6_hdr *ip6;
	size_t plen;

	/* can't tunnel between different AFs */
	if (sav->sah->saidx.src.ss_family != sav->sah->saidx.dst.ss_family
	 || sav->sah->saidx.src.ss_family != AF_INET6) {
		m_freem(m);
		return EINVAL;
	}

	plen = m->m_pkthdr.len;

	/*
	 * grow the mbuf to accomodate the new IPv6 header.
	 */
	if (m->m_len != sizeof(struct ip6_hdr))
		panic("ipsec6_encapsulate: assumption failed (first mbuf length)");
	if (M_LEADINGSPACE(m->m_next) < sizeof(struct ip6_hdr)) {
		struct mbuf *n;
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		n->m_len = sizeof(struct ip6_hdr);
		n->m_next = m->m_next;
		m->m_next = n;
		m->m_pkthdr.len += sizeof(struct ip6_hdr);
		oip6 = mtod(n, struct ip6_hdr *);
	} else {
		m->m_next->m_len += sizeof(struct ip6_hdr);
		m->m_next->m_data -= sizeof(struct ip6_hdr);
		m->m_pkthdr.len += sizeof(struct ip6_hdr);
		oip6 = mtod(m->m_next, struct ip6_hdr *);
	}
	ip6 = mtod(m, struct ip6_hdr *);
	ovbcopy((caddr_t)ip6, (caddr_t)oip6, sizeof(struct ip6_hdr));

	/* Fake link-local scope-class addresses */
	if (IN6_IS_SCOPE_LINKLOCAL(&oip6->ip6_src))
		oip6->ip6_src.s6_addr16[1] = 0;
	if (IN6_IS_SCOPE_LINKLOCAL(&oip6->ip6_dst))
		oip6->ip6_dst.s6_addr16[1] = 0;

	/* construct new IPv6 header. see RFC 2401 5.1.2.2 */
	/* ECN consideration. */
	ip6_ecn_ingress(ip6_ipsec_ecn, &ip6->ip6_flow, &oip6->ip6_flow);
	if (plen < IPV6_MAXPACKET - sizeof(struct ip6_hdr))
		ip6->ip6_plen = htons(plen);
	else {
		/* ip6->ip6_plen will be updated in ip6_output() */
	}
	ip6->ip6_nxt = IPPROTO_IPV6;
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.src)->sin6_addr,
		&ip6->ip6_src, sizeof(ip6->ip6_src));
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.dst)->sin6_addr,
		&ip6->ip6_dst, sizeof(ip6->ip6_dst));

	/* XXX Should ip6_src be updated later ? */

	return 0;
}
#endif /*INET6*/

/*
 * Check the variable replay window.
 * ipsec_chkreplay() performs replay check before ICV verification.
 * ipsec_updatereplay() updates replay bitmap.  This must be called after
 * ICV verification (it also performs replay check, which is usually done
 * beforehand).
 * 0 (zero) is returned if packet disallowed, 1 if packet permitted.
 *
 * based on RFC 2401.
 */
int
ipsec_chkreplay(seq, sav)
	u_int32_t seq;
	struct secasvar *sav;
{
	const struct secreplay *replay;
	u_int32_t diff;
	int fr;
	u_int32_t wsizeb;	/* constant: bits of window size */
	int frlast;		/* constant: last frame */

	/* sanity check */
	if (sav == NULL)
		printf("ipsec_chkreplay: NULL pointer was passed.\n");

	replay = sav->replay;

	if (replay->wsize == 0)
		return 1;	/* no need to check replay. */

	/* constant */
	frlast = replay->wsize - 1;
	wsizeb = replay->wsize << 3;

	/* sequence number of 0 is invalid */
	if (seq == 0)
		return 0;

	/* first time is always okay */
	if (replay->count == 0)
		return 1;

	if (seq > replay->lastseq) {
		/* larger sequences are okay */
		return 1;
	} else {
		/* seq is equal or less than lastseq. */
		diff = replay->lastseq - seq;

		/* over range to check, i.e. too old or wrapped */
		if (diff >= wsizeb)
			return 0;

		fr = frlast - diff / 8;

		/* this packet already seen ? */
		if ((replay->bitmap)[fr] & (1 << (diff % 8)))
			return 0;

		/* out of order but good */
		return 1;
	}
}

int
ipsec_updatereplay(seq, sav)
	u_int32_t seq;
	struct secasvar *sav;
{
	struct secreplay *replay;
	u_int32_t diff;
	int fr;
	u_int32_t wsizeb;	/* constant: bits of window size */
	int frlast;		/* constant: last frame */

	/* sanity check */
	if (sav == NULL)
		printf("ipsec_chkreplay: NULL pointer was passed.\n");

	replay = sav->replay;

	if (replay->wsize == 0)
		goto ok;	/* no need to check replay. */

	/* constant */
	frlast = replay->wsize - 1;
	wsizeb = replay->wsize << 3;

	/* sequence number of 0 is invalid */
	if (seq == 0)
		return 0;

	/* first time */
	if (replay->count == 0) {
		replay->lastseq = seq;
		bzero(replay->bitmap, replay->wsize);
		(replay->bitmap)[frlast] = 1;
		goto ok;
	}

	if (seq > replay->lastseq) {
		/* seq is larger than lastseq. */
		diff = seq - replay->lastseq;

		/* new larger sequence number */
		if (diff < wsizeb) {
			/* In window */
			/* set bit for this packet */
			vshiftl(replay->bitmap, diff, replay->wsize);
			(replay->bitmap)[frlast] |= 1;
		} else {
			/* this packet has a "way larger" */
			bzero(replay->bitmap, replay->wsize);
			(replay->bitmap)[frlast] = 1;
		}
		replay->lastseq = seq;

		/* larger is good */
	} else {
		/* seq is equal or less than lastseq. */
		diff = replay->lastseq - seq;

		/* over range to check, i.e. too old or wrapped */
		if (diff >= wsizeb)
			return 0;

		fr = frlast - diff / 8;

		/* this packet already seen ? */
		if ((replay->bitmap)[fr] & (1 << (diff % 8)))
			return 0;

		/* mark as seen */
		(replay->bitmap)[fr] |= (1 << (diff % 8));

		/* out of order but good */
	}

ok:
	if (replay->count == ~0
	 && (sav->flags & SADB_X_EXT_CYCSEQ) == 0) {
	 	return 1;	/* don't increment, no more packets accepted */
	}

	replay->count++;

	return 1;
}

/*
 * shift variable length bunffer to left.
 * IN:	bitmap: pointer to the buffer
 * 	nbit:	the number of to shift.
 *	wsize:	buffer size (bytes).
 */
static void
vshiftl(bitmap, nbit, wsize)
	unsigned char *bitmap;
	int nbit, wsize;
{
	int s, j, i;
	unsigned char over;

	for (j = 0; j < nbit; j += 8) {
		s = (nbit - j < 8) ? (nbit - j): 8;
		bitmap[0] <<= s;
		for (i = 1; i < wsize; i++) {
			over = (bitmap[i] >> (8 - s));
			bitmap[i] <<= s;
			bitmap[i-1] |= over;
		}
	}

	return;
}

const char *
ipsec4_logpacketstr(ip, spi)
	struct ip *ip;
	u_int32_t spi;
{
	static char buf[256];
	char *p;
	u_int8_t *s, *d;

	s = (u_int8_t *)(&ip->ip_src);
	d = (u_int8_t *)(&ip->ip_dst);

	snprintf(buf, sizeof(buf), "packet(SPI=%u ", (u_int32_t)ntohl(spi));
	for (p = buf; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), "src=%d.%d.%d.%d",
		s[0], s[1], s[2], s[3]);
	for (/*nothing*/; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), " dst=%d.%d.%d.%d",
		d[0], d[1], d[2], d[3]);
	for (/*nothing*/; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), ")");

	return buf;
}

#ifdef INET6
const char *
ipsec6_logpacketstr(ip6, spi)
	struct ip6_hdr *ip6;
	u_int32_t spi;
{
	static char buf[256];
	char *p;

	snprintf(buf, sizeof(buf), "packet(SPI=%u ", (u_int32_t)ntohl(spi));
	for (p = buf; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), "src=%s",
		ip6_sprintf(&ip6->ip6_src));
	for (/*nothing*/; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), " dst=%s",
		ip6_sprintf(&ip6->ip6_dst));
	for (/*nothing*/; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), ")");

	return buf;
}
#endif /*INET6*/

const char *
ipsec_logsastr(sav)
	struct secasvar *sav;
{
	static char buf[256];
	char *p;
	struct secasindex *saidx = &sav->sah->saidx;

	/* validity check */
	if (sav->sah->saidx.src.ss_family != sav->sah->saidx.dst.ss_family)
		panic("ipsec_logsastr: family mismatched.\n");

	snprintf(buf, sizeof(buf), "SA(SPI=%u ", (u_int32_t)ntohl(sav->spi));
	for (p = buf; p && *p; p++)
		;
	if (saidx->src.ss_family == AF_INET) {
		u_int8_t *s, *d;
		s = (u_int8_t *)&((struct sockaddr_in *)&saidx->src)->sin_addr;
		d = (u_int8_t *)&((struct sockaddr_in *)&saidx->dst)->sin_addr;
		snprintf(p, sizeof(buf) - (p - buf),
			"src=%d.%d.%d.%d dst=%d.%d.%d.%d",
			s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
	}
#ifdef INET6
	else if (saidx->src.ss_family == AF_INET6) {
		snprintf(p, sizeof(buf) - (p - buf),
			"src=%s",
			ip6_sprintf(&((struct sockaddr_in6 *)&saidx->src)->sin6_addr));
		for (/*nothing*/; p && *p; p++)
			;
		snprintf(p, sizeof(buf) - (p - buf),
			" dst=%s",
			ip6_sprintf(&((struct sockaddr_in6 *)&saidx->dst)->sin6_addr));
	}
#endif
	for (/*nothing*/; p && *p; p++)
		;
	snprintf(p, sizeof(buf) - (p - buf), ")");

	return buf;
}

void
ipsec_dumpmbuf(m)
	struct mbuf *m;
{
	int totlen;
	int i;
	u_char *p;

	totlen = 0;
	printf("---\n");
	while (m) {
		p = mtod(m, u_char *);
		for (i = 0; i < m->m_len; i++) {
			printf("%02x ", p[i]);
			totlen++;
			if (totlen % 16 == 0)
				printf("\n");
		}
		m = m->m_next;
	}
	if (totlen % 16 != 0)
		printf("\n");
	printf("---\n");
}

/*
 * IPsec output logic for IPv4.
 */
int
ipsec4_output(state, sp, flags)
	struct ipsec_output_state *state;
	struct secpolicy *sp;
	int flags;
{
	struct ip *ip = NULL;
	struct ipsecrequest *isr = NULL;
	int s;
	int error;
#ifdef IPSEC_SRCSEL
	struct in_ifaddr *ia;
#endif
	struct sockaddr_in *dst4;

	if (!state)
		panic("state == NULL in ipsec4_output");
	if (!state->m)
		panic("state->m == NULL in ipsec4_output");
	if (!state->ro)
		panic("state->ro == NULL in ipsec4_output");
	if (!state->dst)
		panic("state->dst == NULL in ipsec4_output");

	ip = mtod(state->m, struct ip *);

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec4_output: applyed SP\n");
		kdebug_secpolicy(sp));

	for (isr = sp->req; isr != NULL; isr = isr->next) {

		if ((error = key_checkrequest(isr)) != 0) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
			ipsecstat.out_nosa++;
			goto bad;
		}

		/* validity check */
		if (isr->sav == NULL) {
			switch (ipsec_get_reqlevel(isr)) {
			case IPSEC_LEVEL_USE:
				continue;
			case IPSEC_LEVEL_REQUIRE:
				/* must be not reached here. */
				panic("ipsec4_output: no SA found, but required.");
			}
		}

		if (isr->sav->state != SADB_SASTATE_MATURE
		 && isr->sav->state != SADB_SASTATE_DYING) {
			/* If there is no valid SA, we give up to process. */
			ipsecstat.out_nosa++;
			error = EINVAL;
			goto bad;
		}

		/*
		 * There may be the case that SA status will be changed when
		 * we are refering to one. So calling splsoftnet().
		 */
		s = splnet();

		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			/*
			 * build IPsec tunnel.
			 */
			/* XXX should be processed with other familiy */
			if (isr->sav->sah->saidx.src.ss_family != AF_INET) {
				printf("ipsec4_output: family mismatched "
					"between inner and outer spi=%u\n",
					(u_int32_t)ntohl(isr->sav->spi));
				splx(s);
				error = EAFNOSUPPORT;
				goto bad;
			}

			ip = mtod(state->m, struct ip *);

			state->m = ipsec4_splithdr(state->m);
			if (!state->m) {
				splx(s);
				error = ENOMEM;
				goto bad;
			}
			error = ipsec4_encapsulate(state->m, isr->sav);
			splx(s);
			if (error) {
				state->m = NULL;
				goto bad;
			}
			ip = mtod(state->m, struct ip *);

			state->ro = &isr->sav->sah->sa_route;
			state->dst = (struct sockaddr *)&state->ro->ro_dst;
			dst4 = (struct sockaddr_in *)state->dst;
			if (state->ro->ro_rt
			 && ((state->ro->ro_rt->rt_flags & RTF_UP) == 0
			  || dst4->sin_addr.s_addr != ip->ip_dst.s_addr)) {
				RTFREE(state->ro->ro_rt);
				bzero((caddr_t)state->ro, sizeof (*state->ro));
			}
			if (state->ro->ro_rt == 0) {
				dst4->sin_family = AF_INET;
				dst4->sin_len = sizeof(*dst4);
				dst4->sin_addr = ip->ip_dst;
				rtalloc(state->ro);
			}
			if (state->ro->ro_rt == 0) {
				ipstat.ips_noroute++;
				error = EHOSTUNREACH;
				goto bad;
			}

#ifdef IPSEC_SRCSEL
			/*
			 * Which address in SA or in routing table should I
			 * select from ?  But I had set from SA at
			 * ipsec4_encapsulate().
			 */
			ia = (struct in_ifaddr *)(state->ro->ro_rt->rt_ifa);
			if (state->ro->ro_rt->rt_flags & RTF_GATEWAY) {
				state->dst = (struct sockaddr *)state->ro->ro_rt->rt_gateway;
				dst4 = (struct sockaddr_in *)state->dst;
			}
			ip->ip_src = IA_SIN(ia)->sin_addr;
#endif
		} else
			splx(s);

		state->m = ipsec4_splithdr(state->m);
		if (!state->m) {
			error = ENOMEM;
			goto bad;
		}
		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
#ifdef IPSEC_ESP
			if ((error = esp4_output(state->m, isr)) != 0) {
				state->m = NULL;
				goto bad;
			}
			break;
#else
			m_freem(state->m);
			state->m = NULL;
			error = EINVAL;
			goto bad;
#endif
		case IPPROTO_AH:
			if ((error = ah4_output(state->m, isr)) != 0) {
				state->m = NULL;
				goto bad;
			}
			break;
		default:
			printf("ipsec4_output: unknown ipsec protocol %d\n",
				isr->saidx.proto);
			m_freem(state->m);
			state->m = NULL;
			error = EINVAL;
			goto bad;
		}

		if (state->m == 0) {
			error = ENOMEM;
			goto bad;
		}
		ip = mtod(state->m, struct ip *);
	}

	return 0;

bad:
	m_freem(state->m);
	state->m = NULL;
	return error;
}

#ifdef INET6
/*
 * IPsec output logic for IPv6, transport mode.
 */
int
ipsec6_output_trans(state, nexthdrp, mprev, sp, flags, tun)
	struct ipsec_output_state *state;
	u_char *nexthdrp;
	struct mbuf *mprev;
	struct secpolicy *sp;
	int flags;
	int *tun;
{
	struct ip6_hdr *ip6;
	struct ipsecrequest *isr = NULL;
	int error = 0;
	int plen;

	if (!state)
		panic("state == NULL in ipsec6_output");
	if (!state->m)
		panic("state->m == NULL in ipsec6_output");
	if (!nexthdrp)
		panic("nexthdrp == NULL in ipsec6_output");
	if (!mprev)
		panic("mprev == NULL in ipsec6_output");
	if (!sp)
		panic("sp == NULL in ipsec6_output");
	if (!tun)
		panic("tun == NULL in ipsec6_output");

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec6_output_trans: applyed SP\n");
		kdebug_secpolicy(sp));

	*tun = 0;
	for (isr = sp->req; isr; isr = isr->next) {
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			/* the rest will be handled by ipsec6_output_tunnel() */
			break;
		}

		if (key_checkrequest(isr) == ENOENT) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
			ipsec6stat.out_nosa++;
			error = ENOENT;
			goto bad;
		}

		/* validity check */
		if (isr->sav == NULL) {
			switch (ipsec_get_reqlevel(isr)) {
			case IPSEC_LEVEL_USE:
				continue;
			case IPSEC_LEVEL_REQUIRE:
				/* must be not reached here. */
				panic("ipsec6_output_trans: no SA found, but required.");
			}
		}

		if (isr->sav->state != SADB_SASTATE_MATURE
		 && isr->sav->state != SADB_SASTATE_DYING) {
			/* If there is no valid SA, we give up to process. */
			ipsec6stat.out_nosa++;
			error = EINVAL;
			goto bad;
		}

		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
#ifdef IPSEC_ESP
			error = esp6_output(state->m, nexthdrp, mprev->m_next, isr);
#else
			m_freem(state->m);
			error = EINVAL;
#endif
			break;
		case IPPROTO_AH:
			error = ah6_output(state->m, nexthdrp, mprev->m_next, isr);
			break;
		default:
			printf("ipsec6_output_trans: unknown ipsec protocol %d\n", isr->saidx.proto);
			m_freem(state->m);
			error = EINVAL;
			break;
		}
		if (error) {
			state->m = NULL;
			goto bad;
		}
		plen = state->m->m_pkthdr.len - sizeof(struct ip6_hdr);
		if (plen > IPV6_MAXPACKET) {
			printf("ipsec6_output: IPsec with IPv6 jumbogram is not supported\n");
			ipsec6stat.out_inval++;
			error = EINVAL;	/*XXX*/
			goto bad;
		}
		ip6 = mtod(state->m, struct ip6_hdr *);
		ip6->ip6_plen = htons(plen);
	}

	/* if we have more to go, we need a tunnel mode processing */
	if (isr != NULL)
		*tun = 1;

	return 0;

bad:
	m_freem(state->m);
	state->m = NULL;
	return error;
}

/*
 * IPsec output logic for IPv6, tunnel mode.
 */
int
ipsec6_output_tunnel(state, sp, flags)
	struct ipsec_output_state *state;
	struct secpolicy *sp;
	int flags;
{
	struct ip6_hdr *ip6;
	struct ipsecrequest *isr = NULL;
	int error = 0;
	int plen;
#ifdef IPSEC_SRCSEL
	struct in6_addr *ia6;
#endif
	struct sockaddr_in6* dst6;
	int s;

	if (!state)
		panic("state == NULL in ipsec6_output");
	if (!state->m)
		panic("state->m == NULL in ipsec6_output");
	if (!sp)
		panic("sp == NULL in ipsec6_output");

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec6_output_tunnel: applyed SP\n");
		kdebug_secpolicy(sp));

	/*
	 * transport mode ipsec (before the 1st tunnel mode) is already
	 * processed by ipsec6_output_trans().
	 */
	for (isr = sp->req; isr; isr = isr->next) {
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL)
			break;
	}

	for (/*already initialized*/; isr; isr = isr->next) {
		if (key_checkrequest(isr) == ENOENT) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
			ipsec6stat.out_nosa++;
			error = ENOENT;
			goto bad;
		}

		/* validity check */
		if (isr->sav == NULL) {
			switch (ipsec_get_reqlevel(isr)) {
			case IPSEC_LEVEL_USE:
				continue;
			case IPSEC_LEVEL_REQUIRE:
				/* must be not reached here. */
				panic("ipsec6_output_tunnel: no SA found, but required.");
			}
		}

		if (isr->sav->state != SADB_SASTATE_MATURE
		 && isr->sav->state != SADB_SASTATE_DYING) {
			/* If there is no valid SA, we give up to process. */
			ipsec6stat.out_nosa++;
			error = EINVAL;
			goto bad;
		}

		/*
		 * There may be the case that SA status will be changed when
		 * we are refering to one. So calling splsoftnet().
		 */
		s = splnet();

		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			/*
			 * build IPsec tunnel.
			 */
			/* XXX should be processed with other familiy */
			if (isr->sav->sah->saidx.src.ss_family != AF_INET6) {
				printf("ipsec4_output: family mismatched "
					"between inner and outer, spi=%u\n",
					(u_int32_t)ntohl(isr->sav->spi));
				printf("ipsec6_output_tunnel: family mismatched "
					"between inner and outer, spi=%u\n",
					(u_int32_t)ntohl(isr->sav->spi));
				splx(s);
				error = EAFNOSUPPORT;
				goto bad;
			}

			ip6 = mtod(state->m, struct ip6_hdr *);

			state->m = ipsec6_splithdr(state->m);
			if (!state->m) {
				splx(s);
				error = ENOMEM;
				goto bad;
			}
			error = ipsec6_encapsulate(state->m, isr->sav);
			splx(s);
			if (error) {
				state->m = 0;
				goto bad;
			}
			ip6 = mtod(state->m, struct ip6_hdr *);

			state->ro = &isr->sav->sah->sa_route;
			state->dst = (struct sockaddr *)&state->ro->ro_dst;
			dst6 = (struct sockaddr_in6 *)state->dst;
			if (state->ro->ro_rt
			 && ((state->ro->ro_rt->rt_flags & RTF_UP) == 0
			  || !IN6_ARE_ADDR_EQUAL(&dst6->sin6_addr, &ip6->ip6_dst))) {
				RTFREE(state->ro->ro_rt);
				bzero((caddr_t)state->ro, sizeof (*state->ro));
			}
			if (state->ro->ro_rt == 0) {
				bzero(dst6, sizeof(*dst6));
				dst6->sin6_family = AF_INET6;
				dst6->sin6_len = sizeof(*dst6);
				dst6->sin6_addr = ip6->ip6_dst;
				rtalloc(state->ro);
			}
			if (state->ro->ro_rt == 0) {
				ip6stat.ip6s_noroute++;
				error = EHOSTUNREACH;
				goto bad;
			}
#ifdef IPSEC_SRCSEL
			/*
			 * Which address in SA or in routing table should I
			 * select from ?  But I had set from SA at
			 * ipsec6_encapsulate().
			 */
			ia6 = in6_selectsrc(dst6, NULL, NULL,
					    (struct route_in6 *)state->ro,
					    NULL, &error);
			if (ia6 == NULL)
				goto bad;
			ip6->ip6_src = *ia6;
#endif
		} else
			splx(s);

		state->m = ipsec6_splithdr(state->m);
		if (!state->m) {
			error = ENOMEM;
			goto bad;
		}
		ip6 = mtod(state->m, struct ip6_hdr *);
		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
#ifdef IPSEC_ESP
			error = esp6_output(state->m, &ip6->ip6_nxt, state->m->m_next, isr);
#else
			m_freem(state->m);
			error = EINVAL;
#endif
			break;
		case IPPROTO_AH:
			error = ah6_output(state->m, &ip6->ip6_nxt, state->m->m_next, isr);
			break;
		default:
			printf("ipsec6_output_tunnel: unknown ipsec protocol %d\n", isr->saidx.proto);
			m_freem(state->m);
			error = EINVAL;
			break;
		}
		if (error) {
			state->m = NULL;
			goto bad;
		}
		plen = state->m->m_pkthdr.len - sizeof(struct ip6_hdr);
		if (plen > IPV6_MAXPACKET) {
			printf("ipsec6_output_tunnel: IPsec with IPv6 jumbogram is not supported\n");
			ipsec6stat.out_inval++;
			error = EINVAL;	/*XXX*/
			goto bad;
		}
		ip6 = mtod(state->m, struct ip6_hdr *);
		ip6->ip6_plen = htons(plen);
	}

	return 0;

bad:
	m_freem(state->m);
	state->m = NULL;
	return error;
}
#endif /*INET6*/

/*
 * Chop IP header and option off from the payload.
 */
static struct mbuf *
ipsec4_splithdr(m)
	struct mbuf *m;
{
	struct mbuf *mh;
	struct ip *ip;
	int hlen;

	if (m->m_len < sizeof(struct ip))
		panic("ipsec4_splithdr: first mbuf too short");
	ip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif
	if (m->m_len > hlen) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);
		if (!mh) {
			m_freem(m);
			return NULL;
		}
		M_COPY_PKTHDR(mh, m);
		MH_ALIGN(mh, hlen);
		m->m_flags &= ~M_PKTHDR;
		m->m_len -= hlen;
		m->m_data += hlen;
		mh->m_next = m;
		m = mh;
		m->m_len = hlen;
		bcopy((caddr_t)ip, mtod(m, caddr_t), hlen);
	} else if (m->m_len < hlen) {
		m = m_pullup(m, hlen);
		if (!m)
			return NULL;
	}
	return m;
}

#ifdef INET6
static struct mbuf *
ipsec6_splithdr(m)
	struct mbuf *m;
{
	struct mbuf *mh;
	struct ip6_hdr *ip6;
	int hlen;

	if (m->m_len < sizeof(struct ip6_hdr))
		panic("ipsec6_splithdr: first mbuf too short");
	ip6 = mtod(m, struct ip6_hdr *);
	hlen = sizeof(struct ip6_hdr);
	if (m->m_len > hlen) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);
		if (!mh) {
			m_freem(m);
			return NULL;
		}
		M_COPY_PKTHDR(mh, m);
		MH_ALIGN(mh, hlen);
		m->m_flags &= ~M_PKTHDR;
		m->m_len -= hlen;
		m->m_data += hlen;
		mh->m_next = m;
		m = mh;
		m->m_len = hlen;
		bcopy((caddr_t)ip6, mtod(m, caddr_t), hlen);
	} else if (m->m_len < hlen) {
		m = m_pullup(m, hlen);
		if (!m)
			return NULL;
	}
	return m;
}
#endif

/* validate inbound IPsec tunnel packet. */
int
ipsec4_tunnel_validate(ip, nxt0, sav)
	struct ip *ip;
	u_int nxt0;
	struct secasvar *sav;
{
	u_int8_t nxt = nxt0 & 0xff;
	struct sockaddr_in *sin;
	int hlen;

	if (nxt != IPPROTO_IPV4)
		return 0;
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif
	if (hlen != sizeof(struct ip))
		return 0;
	switch (sav->sah->saidx.dst.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&sav->sah->saidx.dst;
		if (bcmp(&ip->ip_dst, &sin->sin_addr, sizeof(ip->ip_dst)) != 0)
			return 0;
		break;
#ifdef INET6
	case AF_INET6:
		/* should be supported, but at this moment we don't. */
		/*FALLTHROUGH*/
#endif
	default:
		return 0;
	}

	return 1;
}

#ifdef INET6
/* validate inbound IPsec tunnel packet. */
int
ipsec6_tunnel_validate(ip6, nxt0, sav)
	struct ip6_hdr *ip6;
	u_int nxt0;
	struct secasvar *sav;
{
	u_int8_t nxt = nxt0 & 0xff;
	struct sockaddr_in6 *sin6;

	if (nxt != IPPROTO_IPV6)
		return 0;
	switch (sav->sah->saidx.dst.ss_family) {
	case AF_INET6:
		sin6 = ((struct sockaddr_in6 *)&sav->sah->saidx.dst);
		if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &sin6->sin6_addr))
			return 0;
		break;
	case AF_INET:
		/* should be supported, but at this moment we don't. */
		/*FALLTHROUGH*/
	default:
		return 0;
	}

	return 1;
}
#endif

/*
 * Make a mbuf chain for encryption.
 * If the original mbuf chain contains a mbuf with a cluster,
 * allocate a new cluster and copy the data to the new cluster.
 * XXX: this hack is inefficient, but is necessary to handle cases
 * of TCP retransmission...
 */
struct mbuf *
ipsec_copypkt(m)
	struct mbuf *m;
{
	struct mbuf *n, **mpp, *mnew;

	for (n = m, mpp = &m; n; n = n->m_next) {
		if (n->m_flags & M_EXT) {
			/*
			 * Make a copy only if there are more than one references
			 * to the cluster.
			 * XXX: is this approach effective?
			 */
			if (
				n->m_ext.ext_free ||
				mclrefcnt[mtocl(n->m_ext.ext_buf)] > 1
			    )
			{
				int remain, copied;
				struct mbuf *mm;

				if (n->m_flags & M_PKTHDR) {
					MGETHDR(mnew, M_DONTWAIT, MT_HEADER);
					if (mnew == NULL)
						goto fail;
					mnew->m_pkthdr = n->m_pkthdr;
					mnew->m_flags = n->m_flags & M_COPYFLAGS;
				}
				else {
					MGET(mnew, M_DONTWAIT, MT_DATA);
					if (mnew == NULL)
						goto fail;
				}
				mnew->m_len = 0;
				mm = mnew;

				/*
				 * Copy data. If we don't have enough space to
				 * store the whole data, allocate a cluster
				 * or additional mbufs.
				 * XXX: we don't use m_copyback(), since the
				 * function does not use clusters and thus is
				 * inefficient.
				 */
				remain = n->m_len;
				copied = 0;
				while(1) {
					int len;
					struct mbuf *mn;

					if (remain <= (mm->m_flags & M_PKTHDR ? MHLEN : MLEN))
						len = remain;
					else { /* allocate a cluster */
						MCLGET(mm, M_DONTWAIT);
						if (!(mm->m_flags & M_EXT)) {
							m_free(mm);
							goto fail;
						}
						len = remain < MCLBYTES ?
							remain : MCLBYTES;
					}

					bcopy(n->m_data + copied, mm->m_data,
					      len);

					copied += len;
					remain -= len;
					mm->m_len = len;

					if (remain <= 0) /* completed? */
						break;

					/* need another mbuf */
					MGETHDR(mn, M_DONTWAIT, MT_HEADER);
					if (mn == NULL)
						goto fail;
					mm->m_next = mn;
					mm = mn;
				}

				/* adjust chain */
				mm->m_next = m_free(n);
				n = mm;
				*mpp = mnew;
				mpp = &n->m_next;

				continue;
			}
		}
		*mpp = n;
		mpp = &n->m_next;
	}

	return(m);
  fail:
	m_freem(m);
	return(NULL);
}
