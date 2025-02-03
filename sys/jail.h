/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD: src/sys/sys/jail.h,v 1.8 2000/02/12 13:41:56 rwatson Exp $
 *
 */

#ifndef _SYS_JAIL_H_
#define _SYS_JAIL_H_

struct jail {
	u_int32_t	version;	// in case future jail struct changes
	char		*path;		// root path for the jail
	char		*hostname;	// hostname of the jail (can/can't be modified from within the jail based on the `jail_set_hostname_allowed` sysctl)
	u_int32_t	ip_number;	// IP address assigned to the jail (unique)
};

#ifndef _KERNEL

int jail __P((struct jail *));

#else /* _KERNEL */

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_PRISON);
#endif

/*
 * This structure describes a prison.  It is pointed to by all struct
 * proc's of the inmates.  pr_ref keeps track of them and is used to
 * delete the struture when the last inmate is dead.
 */

struct prison {
	// path is missing, because chroot() will simply adjust
	// the root directory (rdir and jdir vnode pointers) of
	// the filedesc struct the process uses to access the filesystem
	int		pr_ref;			// number of processes referencing this struct
	char 		pr_host[MAXHOSTNAMELEN]; // passed from jail struct
	u_int32_t	pr_ip;		// passed from jail struct
	void		*pr_linux;	// used in i386 version to store info about a Linux compatibility layer (i386/linux/linux_mib.c)
};

/*
 * Sysctl-set variables that determine global jail policy
 */
extern int	jail_set_hostname_allowed;

#endif /* !_KERNEL */
#endif /* !_SYS_JAIL_H_ */
