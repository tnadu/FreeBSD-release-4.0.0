/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD: src/sys/kern/kern_jail.c,v 1.6 2000/02/12 13:41:55 rwatson Exp $
 *
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>

MALLOC_DEFINE(M_PRISON, "prison", "Prison structures");

SYSCTL_NODE(, OID_AUTO, jail, CTLFLAG_RW, 0,
    "Jail rules");

int	jail_set_hostname_allowed = 1;	// sysctl to allow/disallow processes in jail to change the hostname of the jail
SYSCTL_INT(_jail, OID_AUTO, set_hostname_allowed, CTLFLAG_RW,
    &jail_set_hostname_allowed, 0,
    "Processes in jail can set their hostnames");

int
jail(p, uap)
        struct proc *p; 			// process to be placed in a jail, which performed the syscall
        struct jail_args /* {		// contains pointer to the jail struct passed by p
                syscallarg(struct jail *) jail;
        } */ *uap;
{
	int error;
	struct prison *pr;	// pointer to prison struct in p
	struct jail j;		// copy of the jail from user-space
	struct chroot_args ca;	// contains path which is passed to chroot

	error = suser(p);	// check if the calling process is a host root (jail() cannot be called from a process already in a jail)
	if (error)
		return (error);
	error = copyin(uap->jail, &j, sizeof j);	// copy the jail from user space
	if (error)
		return (error);
	if (j.version != 0)		// current implementation is at version 0
		return (EINVAL);
	MALLOC(pr, struct prison *, sizeof *pr , M_PRISON, M_WAITOK);	// allocate prison for process p
	bzero((caddr_t)pr, sizeof *pr);		// probably zero-out the allocated memory?
	error = copyinstr(j.hostname, &pr->pr_host, sizeof pr->pr_host, 0);		// copy hostname provided in jail to prison
	if (error) 
		goto bail;
	pr->pr_ip = j.ip_number;	// copy IP address provided in jail to prison

	ca.path = j.path;	// prepare the chroot call
	error = chroot(p, &ca);		// p->p_fd->fd_rdir will now be the provided path (root dir of p)
	if (error)
		goto bail;

	pr->pr_ref++;
	p->p_prison = pr;	// attach prison to p
	p->p_flag |= P_JAILED;	// add flag to mark p as jailed
	// &p->p_prison gets copied to any forks of p
	return (0);

bail:
	FREE(pr, M_PRISON);
	return (error);
}

int
prison_ip(struct proc *p, int flag, u_int32_t *ip)
{
    // ip -> ip_obisnuit / 0.0.0.0
    // ip_obisnuit verifica daca e ip-ul prisonului
    // 0.0.0.0 iti da ip-ul prisonului
    //
	u_int32_t tmp;

	if (!p->p_prison)
		return (0);
	if (flag) 
		tmp = *ip;
	else
		tmp = ntohl(*ip);
	if (tmp == INADDR_ANY) {
		if (flag) 
			*ip = p->p_prison->pr_ip;
		else
			*ip = htonl(p->p_prison->pr_ip);
		return (0);
	}
	if (p->p_prison->pr_ip != tmp)
		return (1);
	return (0);
}

void
prison_remote_ip(struct proc *p, int flag, u_int32_t *ip)
{
    // daca e 127.0.0.1 -> ip prsion
    //
	u_int32_t tmp;

	if (!p || !p->p_prison)
		return;

	if (flag)
		tmp = *ip;
	else
		tmp = ntohl(*ip);

	if (tmp == 0x7f000001) {
		if (flag)
			*ip = p->p_prison->pr_ip;
		else
			*ip = htonl(p->p_prison->pr_ip);
		return;
	}
	return;
}

int
prison_if(struct proc *p, struct sockaddr *sa)
{
	struct sockaddr_in *sai = (struct sockaddr_in*) sa;
	int ok;

	if (sai->sin_family != AF_INET)
		ok = 0;
	else if (p->p_prison->pr_ip != ntohl(sai->sin_addr.s_addr))
		ok = 1;
	else
		ok = 0;
	return (ok);
}
