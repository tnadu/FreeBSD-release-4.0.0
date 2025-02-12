/*-
 * Copyright (c) 1999 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer 
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/i386/linux/linux_mib.c,v 1.3 2000/01/10 13:09:08 marcel Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/jail.h>

#include <i386/linux/linux.h>
#include <i386/linux/linux_mib.h>

struct linux_prison {
	char	pr_osname[LINUX_MAX_UTSNAME];
	char	pr_osrelease[LINUX_MAX_UTSNAME];
	int	pr_oss_version;
};

SYSCTL_NODE(_compat, OID_AUTO, linux, CTLFLAG_RW, 0,
	    "Linux mode");

static char	linux_osname[LINUX_MAX_UTSNAME] = "Linux";

static int
linux_sysctl_osname SYSCTL_HANDLER_ARGS
{
	char osname[LINUX_MAX_UTSNAME];
	int error;

	strcpy(osname, linux_get_osname(req->p));
	error = sysctl_handle_string(oidp, osname, LINUX_MAX_UTSNAME, req);
	if (error || req->newptr == NULL)
		return (error);
	error = linux_set_osname(req->p, osname);
	return (error);
}

SYSCTL_PROC(_compat_linux, OID_AUTO, osname,
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_PRISON,
	    0, 0, linux_sysctl_osname, "A",
	    "Linux kernel OS name");

static char	linux_osrelease[LINUX_MAX_UTSNAME] = "2.2.12";

static int
linux_sysctl_osrelease SYSCTL_HANDLER_ARGS
{
	char osrelease[LINUX_MAX_UTSNAME];
	int error;

	strcpy(osrelease, linux_get_osrelease(req->p));
	error = sysctl_handle_string(oidp, osrelease, LINUX_MAX_UTSNAME, req);
	if (error || req->newptr == NULL)
		return (error);
	error = linux_set_osrelease(req->p, osrelease);
	return (error);
}

SYSCTL_PROC(_compat_linux, OID_AUTO, osrelease,
	    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_PRISON,
	    0, 0, linux_sysctl_osrelease, "A",
	    "Linux kernel OS release");

static int	linux_oss_version = 0x030600;

static int
linux_sysctl_oss_version SYSCTL_HANDLER_ARGS
{
	int oss_version;
	int error;

	oss_version = linux_get_oss_version(req->p);
	error = sysctl_handle_int(oidp, &oss_version, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	error = linux_set_oss_version(req->p, oss_version);
	return (error);
}

SYSCTL_PROC(_compat_linux, OID_AUTO, oss_version,
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_PRISON,
	    0, 0, linux_sysctl_oss_version, "I",
	    "Linux OSS version");

static struct linux_prison *
get_prison(struct proc *p)
{
	register struct prison *pr;
	register struct linux_prison *lpr;

	pr = p->p_prison;
	if (pr == NULL)
		return (NULL);

	if (pr->pr_linux == NULL) {
		MALLOC(lpr, struct linux_prison *, sizeof *lpr,
		       M_PRISON, M_WAITOK);
		bzero((caddr_t)lpr, sizeof *lpr);
		pr->pr_linux = lpr;
	}

	return (pr->pr_linux);
}

char *
linux_get_osname(p)
	struct proc *p;
{
	register struct prison *pr;
	register struct linux_prison *lpr;

	pr = p->p_prison;
	if (pr != NULL && pr->pr_linux != NULL) {
		lpr = pr->pr_linux;
		if (lpr->pr_osname[0])
			return (lpr->pr_osname);
	}

	return (linux_osname);
}

int
linux_set_osname(p, osname)
	struct proc *p;
	char *osname;
{
	register struct linux_prison *lpr;

	lpr = get_prison(p);
	if (lpr != NULL)
		strcpy(lpr->pr_osname, osname);
	else
		strcpy(linux_osname, osname);

	return (0);
}

char *
linux_get_osrelease(p)
	struct proc *p;
{
	register struct prison *pr;
	register struct linux_prison *lpr;

	pr = p->p_prison;
	if (pr != NULL && pr->pr_linux != NULL) {
		lpr = pr->pr_linux;
		if (lpr->pr_osrelease[0])
			return (lpr->pr_osrelease);
	}

	return (linux_osrelease);
}

int
linux_set_osrelease(p, osrelease)
	struct proc *p;
	char *osrelease;
{
	register struct linux_prison *lpr;

	lpr = get_prison(p);
	if (lpr != NULL)
		strcpy(lpr->pr_osrelease, osrelease);
	else
		strcpy(linux_osrelease, osrelease);

	return (0);
}

int
linux_get_oss_version(p)
	struct proc *p;
{
	register struct prison *pr;
	register struct linux_prison *lpr;

	pr = p->p_prison;
	if (pr != NULL && pr->pr_linux != NULL) {
		lpr = pr->pr_linux;
		if (lpr->pr_oss_version)
			return (lpr->pr_oss_version);
	}

	return (linux_oss_version);
}

int
linux_set_oss_version(p, oss_version)
	struct proc *p;
	int oss_version;
{
	register struct linux_prison *lpr;

	lpr = get_prison(p);
	if (lpr != NULL)
		lpr->pr_oss_version = oss_version;
	else
		linux_oss_version = oss_version;

	return (0);
}
