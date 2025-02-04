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
                                    // changes to the sysctl tree were implemented as well, by adding this new subtree
                                    //
                                    // only privileged processes within jail are allowed to manage this aspect
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
	// used in in_pcb.c/in_pcbbind(), which binds
	// an IP address and a port to a socket;
	// redirects attempts to bind to all IP addresses
	// on all interfaces (0.0.0.0) to the prison IP
	// address, in case process p is jailed;
	// forbids jailed process p to bind to any other
	// address other than that of its prison, and
	// returns an error in such a case;
	u_int32_t tmp;

	if (!p->p_prison)	// process is not jailed
		return (0);		// no need to redirect or perform extra checks
	if (flag) 			// when caller is certain no IP address format conversions need to be performed
		tmp = *ip;
	else
		tmp = ntohl(*ip);	// network to host IP address format translation
	if (tmp == INADDR_ANY) {	// ip is 0.0.0.0
		// redirect ip to prison IP address
		if (flag) 		// when caller is certain no IP address format conversions need to be performed
			*ip = p->p_prison->pr_ip;
		else
			*ip = htonl(p->p_prison->pr_ip); // host to network IP address format translation
		return (0);
	}
	if (p->p_prison->pr_ip != tmp)	// p attempts to bind to a valid IP address, other than that of its jail
		return (1);					// this is forbidden
	return (0);						// p attempts to bind to the IP address of its prison, which is allowed
}

void
prison_remote_ip(struct proc *p, int flag, u_int32_t *ip)
{
    // used in tcp_usrreq.c/tcp_usr_connect() and in
	// udp_usrreq.c/udp_connect() when initiating
	// outgoing connections;
	// redirects attempts to reach localhost (127.0.0.1)
	// to the prison IP address, in case process p is jailed;
	// will not forbid attempts to reach other valid IP
	// addresses of the host, since this is handled via
	// routing tables;
	u_int32_t tmp;

	if (!p || !p->p_prison)	// process is not jailed
		return;

	if (flag)		// when caller is certain no IP address format conversions need to be performed
		tmp = *ip;
	else
		tmp = ntohl(*ip); // network to host IP address format translation

	if (tmp == 0x7f000001) {	// ip is 127.0.0.1
		// redirect ip to prison IP address
		if (flag)	// when caller is certain no IP address format conversions need to be performed
			*ip = p->p_prison->pr_ip;
		else
			*ip = htonl(p->p_prison->pr_ip); // host to network IP address format translation
		return;
	}
	return;	// ip is the IP address of the prison, an invalid IP address or another valid IP address of the host
}

int
prison_if(struct proc *p, struct sockaddr *sa)
{
	// used in if.c/ifconf() and in rtsock.c/sysctl_iflist(),
	// to filter out any network interfaces which correspond
	// to IP addresses other than that of the prison of p;
	struct sockaddr_in *sai = (struct sockaddr_in*) sa;
	int ok;

	if (sai->sin_family != AF_INET)	// if the socket is not IPv4
		ok = 0;						// all is well
	// socket is IPv4 and IP addresses differ between the socket
	// and the prison
	else if (p->p_prison->pr_ip != ntohl(sai->sin_addr.s_addr))
		ok = 1;		// make socket invisible to p
	// socket is IPv4 and IP addresses coincide between the socket
	// and the prison
	else
		ok = 0;		// all is well
	return (ok);
}
