/*
 * Copyright (C) 1993-1998 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 */
#if !defined(lint)
static const char sccsid[] = "@(#)ip_frag.c	1.11 3/24/96 (C) 1993-1995 Darren Reed";
/*static const char rcsid[] = "@(#)$Id: ip_frag.c,v 2.4.2.4 1999/11/28 04:52:10 darrenr Exp $";*/
static const char rcsid[] = "@(#)$FreeBSD: src/sys/netinet/ip_frag.c,v 1.10 2000/02/10 21:29:09 guido Exp $";
#endif

#if defined(KERNEL) && !defined(_KERNEL)
# define      _KERNEL
#endif

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/file.h>
#if !defined(_KERNEL) && !defined(KERNEL)
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
#endif
#if defined(_KERNEL) && (__FreeBSD_version >= 220000)
# include <sys/filio.h>
# include <sys/fcntl.h>
#else
# include <sys/ioctl.h>
#endif
#include <sys/uio.h>
#ifndef linux
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL) && !defined(linux)
# include <sys/systm.h>
#endif
#if !defined(__SVR4) && !defined(__svr4__)
# if defined(_KERNEL) && !defined(__sgi)
#  include <sys/kernel.h>
# endif
# ifndef linux
#  include <sys/mbuf.h>
# endif
#else
# include <sys/byteorder.h>
# ifdef _KERNEL
#  include <sys/dditypes.h>
# endif
# include <sys/stream.h>
# include <sys/kmem.h>
#endif
#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifndef linux
# include <netinet/ip_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_proxy.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_auth.h"
#if (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
# if (defined(KERNEL) || defined(_KERNEL))
#  ifndef IPFILTER_LKM
#   include <sys/libkern.h>
#   include <sys/systm.h>
# endif
extern struct callout_handle ipfr_slowtimer_ch;
# endif
#endif


ipfr_t	*ipfr_heads[IPFT_SIZE];
ipfr_t	*ipfr_nattab[IPFT_SIZE];
ipfrstat_t ipfr_stats;
int	ipfr_inuse = 0,
	fr_ipfrttl = 120;	/* 60 seconds */
#ifdef _KERNEL
# if SOLARIS2 >= 7
extern	timeout_id_t	ipfr_timer_id;
# else
extern	int	ipfr_timer_id;
# endif
#endif
#if	(SOLARIS || defined(__sgi)) && defined(_KERNEL)
extern	KRWLOCK_T	ipf_frag, ipf_natfrag, ipf_nat, ipf_mutex;
# if	SOLARIS
extern	KRWLOCK_T	ipf_solaris;
# else
KRWLOCK_T	ipf_solaris;
# endif
extern	kmutex_t	ipf_rw;
#endif


static ipfr_t *ipfr_new __P((ip_t *, fr_info_t *, u_int, ipfr_t **));
static ipfr_t *ipfr_lookup __P((ip_t *, fr_info_t *, ipfr_t **));
static void ipfr_delete __P((ipfr_t *));


ipfrstat_t *ipfr_fragstats()
{
	ipfr_stats.ifs_table = ipfr_heads;
	ipfr_stats.ifs_nattab = ipfr_nattab;
	ipfr_stats.ifs_inuse = ipfr_inuse;
	return &ipfr_stats;
}


/*
 * add a new entry to the fragment cache, registering it as having come
 * through this box, with the result of the filter operation.
 */
static ipfr_t *ipfr_new(ip, fin, pass, table)
ip_t *ip;
fr_info_t *fin;
u_int pass;
ipfr_t *table[];
{
	ipfr_t	**fp, *fra, frag;
	u_int	idx;

	frag.ipfr_p = ip->ip_p;
	idx = ip->ip_p;
	frag.ipfr_id = ip->ip_id;
	idx += ip->ip_id;
	frag.ipfr_tos = ip->ip_tos;
	frag.ipfr_src.s_addr = ip->ip_src.s_addr;
	idx += ip->ip_src.s_addr;
	frag.ipfr_dst.s_addr = ip->ip_dst.s_addr;
	idx += ip->ip_dst.s_addr;
	idx *= 127;
	idx %= IPFT_SIZE;

	/*
	 * first, make sure it isn't already there...
	 */
	for (fp = &table[idx]; (fra = *fp); fp = &fra->ipfr_next)
		if (!bcmp((char *)&frag.ipfr_src, (char *)&fra->ipfr_src,
			  IPFR_CMPSZ)) {
			ATOMIC_INC(ipfr_stats.ifs_exists);
			return NULL;
		}

	/*
	 * allocate some memory, if possible, if not, just record that we
	 * failed to do so.
	 */
	KMALLOC(fra, ipfr_t *);
	if (fra == NULL) {
		ATOMIC_INC(ipfr_stats.ifs_nomem);
		return NULL;
	}

	if ((fra->ipfr_rule = fin->fin_fr) != NULL) {
		ATOMIC_INC(fin->fin_fr->fr_ref);
	}


	/*
	 * Instert the fragment into the fragment table, copy the struct used
	 * in the search using bcopy rather than reassign each field.
	 * Set the ttl to the default and mask out logging from "pass"
	 */
	if ((fra->ipfr_next = table[idx]))
		table[idx]->ipfr_prev = fra;
	fra->ipfr_prev = NULL;
	fra->ipfr_data = NULL;
	table[idx] = fra;
	bcopy((char *)&frag.ipfr_src, (char *)&fra->ipfr_src, IPFR_CMPSZ);
	fra->ipfr_ttl = fr_ipfrttl;
	/*
	 * Compute the offset of the expected start of the next packet.
	 */
	fra->ipfr_off = (ip->ip_off & IP_OFFMASK) + (fin->fin_dlen >> 3);
	ATOMIC_INC(ipfr_stats.ifs_new);
	ATOMIC_INC(ipfr_inuse);
	return fra;
}


int ipfr_newfrag(ip, fin, pass)
ip_t *ip;
fr_info_t *fin;
u_int pass;
{
	ipfr_t	*ipf;

	WRITE_ENTER(&ipf_frag);
	ipf = ipfr_new(ip, fin, pass, ipfr_heads);
	RWLOCK_EXIT(&ipf_frag);
	return ipf ? 0 : -1;
}


int ipfr_nat_newfrag(ip, fin, pass, nat)
ip_t *ip;
fr_info_t *fin;
u_int pass;
nat_t *nat;
{
	ipfr_t	*ipf;

	WRITE_ENTER(&ipf_natfrag);
	ipf = ipfr_new(ip, fin, pass, ipfr_nattab);
	if (ipf != NULL) {
		ipf->ipfr_data = nat;
		nat->nat_data = ipf;
	}
	RWLOCK_EXIT(&ipf_natfrag);
	return ipf ? 0 : -1;
}


/*
 * check the fragment cache to see if there is already a record of this packet
 * with its filter result known.
 */
static ipfr_t *ipfr_lookup(ip, fin, table)
ip_t *ip;
fr_info_t *fin;
ipfr_t *table[];
{
	ipfr_t	*f, frag;
	u_int	idx;

	/*
	 * For fragments, we record protocol, packet id, TOS and both IP#'s
	 * (these should all be the same for all fragments of a packet).
	 *
	 * build up a hash value to index the table with.
	 */
	frag.ipfr_p = ip->ip_p;
	idx = ip->ip_p;
	frag.ipfr_id = ip->ip_id;
	idx += ip->ip_id;
	frag.ipfr_tos = ip->ip_tos;
	frag.ipfr_src.s_addr = ip->ip_src.s_addr;
	idx += ip->ip_src.s_addr;
	frag.ipfr_dst.s_addr = ip->ip_dst.s_addr;
	idx += ip->ip_dst.s_addr;
	idx *= 127;
	idx %= IPFT_SIZE;

	/*
	 * check the table, careful to only compare the right amount of data
	 */
	for (f = table[idx]; f; f = f->ipfr_next)
		if (!bcmp((char *)&frag.ipfr_src, (char *)&f->ipfr_src,
			  IPFR_CMPSZ)) {
			u_short	atoff, off;

			if (f != table[idx]) {
				/*
				 * move fragment info. to the top of the list
				 * to speed up searches.
				 */
				if ((f->ipfr_prev->ipfr_next = f->ipfr_next))
					f->ipfr_next->ipfr_prev = f->ipfr_prev;
				f->ipfr_next = table[idx];
				table[idx]->ipfr_prev = f;
				f->ipfr_prev = NULL;
				table[idx] = f;
			}
			off = ip->ip_off & IP_OFFMASK;
			atoff = off + (fin->fin_dlen >> 3);
			/*
			 * If we've follwed the fragments, and this is the
			 * last (in order), shrink expiration time.
			 */
			if (off == f->ipfr_off) {
				if (!(ip->ip_off & IP_MF))
					f->ipfr_ttl = 1;
				else
					f->ipfr_off = atoff;
			}
			ATOMIC_INC(ipfr_stats.ifs_hits);
			return f;
		}
	return NULL;
}


/*
 * functional interface for NAT lookups of the NAT fragment cache
 */
nat_t *ipfr_nat_knownfrag(ip, fin)
ip_t *ip;
fr_info_t *fin;
{
	nat_t	*nat;
	ipfr_t	*ipf;

	READ_ENTER(&ipf_natfrag);
	ipf = ipfr_lookup(ip, fin, ipfr_nattab);
	if (ipf != NULL) {
		nat = ipf->ipfr_data;
		/*
		 * This is the last fragment for this packet.
		 */
		if ((ipf->ipfr_ttl == 1) && (nat != NULL)) {
			nat->nat_data = NULL;
			ipf->ipfr_data = NULL;
		}
	} else
		nat = NULL;
	RWLOCK_EXIT(&ipf_natfrag);
	return nat;
}


/*
 * functional interface for normal lookups of the fragment cache
 */
frentry_t *ipfr_knownfrag(ip, fin)
ip_t *ip;
fr_info_t *fin;
{
	frentry_t *fr = NULL;
	ipfr_t	*fra;

	READ_ENTER(&ipf_frag);
	fra = ipfr_lookup(ip, fin, ipfr_heads);
	if (fra != NULL)
		fr = fra->ipfr_rule;
	RWLOCK_EXIT(&ipf_frag);
	return fr;
}


/*
 * forget any references to this external object.
 */
void ipfr_forget(nat)
void *nat;
{
	ipfr_t	*fr;
	int	idx;

	WRITE_ENTER(&ipf_natfrag);
	for (idx = IPFT_SIZE - 1; idx >= 0; idx--)
		for (fr = ipfr_heads[idx]; fr; fr = fr->ipfr_next)
			if (fr->ipfr_data == nat)
				fr->ipfr_data = NULL;

	RWLOCK_EXIT(&ipf_natfrag);
}


static void ipfr_delete(fra)
ipfr_t *fra;
{
	frentry_t *fr;

	fr = fra->ipfr_rule;
	if (fr != NULL) {
		ATOMIC_DEC(fr->fr_ref);
		if (fr->fr_ref == 0)
			KFREE(fr);
	}
	if (fra->ipfr_prev)
		fra->ipfr_prev->ipfr_next = fra->ipfr_next;
	if (fra->ipfr_next)
		fra->ipfr_next->ipfr_prev = fra->ipfr_prev;
	KFREE(fra);
}


/*
 * Free memory in use by fragment state info. kept.
 */
void ipfr_unload()
{
	ipfr_t	**fp, *fra;
	nat_t	*nat;
	int	idx;

	WRITE_ENTER(&ipf_frag);
	for (idx = IPFT_SIZE - 1; idx >= 0; idx--)
		for (fp = &ipfr_heads[idx]; (fra = *fp); ) {
			*fp = fra->ipfr_next;
			ipfr_delete(fra);
		}
	RWLOCK_EXIT(&ipf_frag);

	WRITE_ENTER(&ipf_nat);
	WRITE_ENTER(&ipf_natfrag);
	for (idx = IPFT_SIZE - 1; idx >= 0; idx--)
		for (fp = &ipfr_nattab[idx]; (fra = *fp); ) {
			*fp = fra->ipfr_next;
			nat = fra->ipfr_data;
			if (nat != NULL) {
				if (nat->nat_data == fra)
					nat->nat_data = NULL;
			}
			ipfr_delete(fra);
		}
	RWLOCK_EXIT(&ipf_natfrag);
	RWLOCK_EXIT(&ipf_nat);
}


#ifdef	_KERNEL
/*
 * Slowly expire held state for fragments.  Timeouts are set * in expectation
 * of this being called twice per second.
 */
# if (BSD >= 199306) || SOLARIS || defined(__sgi)
#  if defined(SOLARIS2) && (SOLARIS2 < 7)
void ipfr_slowtimer()
#  else
void ipfr_slowtimer __P((void *ptr))
#  endif
# else
int ipfr_slowtimer()
# endif
{
	ipfr_t	**fp, *fra;
	nat_t	*nat;
	int	idx;
#if defined(_KERNEL)
# if !SOLARIS
	int	s;
# else
	extern	int	fr_running;

	if (fr_running <= 0) 
		return;
# endif
#endif

	READ_ENTER(&ipf_solaris);
#ifdef __sgi
	ipfilter_sgi_intfsync();
#endif

	SPL_NET(s);
	WRITE_ENTER(&ipf_frag);

	/*
	 * Go through the entire table, looking for entries to expire,
	 * decreasing the ttl by one for each entry.  If it reaches 0,
	 * remove it from the chain and free it.
	 */
	for (idx = IPFT_SIZE - 1; idx >= 0; idx--)
		for (fp = &ipfr_heads[idx]; (fra = *fp); ) {
			--fra->ipfr_ttl;
			if (fra->ipfr_ttl == 0) {
				*fp = fra->ipfr_next;
				ipfr_delete(fra);
				ATOMIC_INC(ipfr_stats.ifs_expire);
				ATOMIC_DEC(ipfr_inuse);
			} else
				fp = &fra->ipfr_next;
		}
	RWLOCK_EXIT(&ipf_frag);

	/*
	 * Same again for the NAT table, except that if the structure also
	 * still points to a NAT structure, and the NAT structure points back
	 * at the one to be free'd, NULL the reference from the NAT struct.
	 * NOTE: We need to grab both mutex's early, and in this order so as
	 * to prevent a deadlock if both try to expire at the same time.
	 */
	WRITE_ENTER(&ipf_nat);
	WRITE_ENTER(&ipf_natfrag);
	for (idx = IPFT_SIZE - 1; idx >= 0; idx--)
		for (fp = &ipfr_nattab[idx]; (fra = *fp); ) {
			--fra->ipfr_ttl;
			if (fra->ipfr_ttl == 0) {
				ATOMIC_INC(ipfr_stats.ifs_expire);
				ATOMIC_DEC(ipfr_inuse);
				nat = fra->ipfr_data;
				if (nat != NULL) {
					if (nat->nat_data == fra)
						nat->nat_data = NULL;
				}
				*fp = fra->ipfr_next;
				ipfr_delete(fra);
			} else
				fp = &fra->ipfr_next;
		}
	RWLOCK_EXIT(&ipf_natfrag);
	RWLOCK_EXIT(&ipf_nat);
	SPL_X(s);
	fr_timeoutstate();
	ip_natexpire();
	fr_authexpire();
# if	SOLARIS
	ipfr_timer_id = timeout(ipfr_slowtimer, NULL, drv_usectohz(500000));
# else
#  ifndef linux
#   if (__FreeBSD_version >= 300000)
	ipfr_slowtimer_ch = timeout(ipfr_slowtimer, NULL, hz/2);
#   else
	timeout(ipfr_slowtimer, NULL, hz/2);
#   endif
#  endif
#  if (BSD < 199306) && !defined(__sgi)
	return 0;
#  endif
# endif
	RWLOCK_EXIT(&ipf_solaris);
}
#endif /* defined(_KERNEL) */
