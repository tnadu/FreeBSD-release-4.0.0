/*-
 * Copyright (c) 1994-1995 S�ren Schmidt
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
 * $FreeBSD: src/sys/i386/linux/linux_misc.c,v 1.77 2000/03/09 17:52:01 marcel Exp $
 */

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/imgact_aout.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/signalvar.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_zone.h>

#include <machine/frame.h>
#include <machine/psl.h>
#include <machine/sysarch.h>
#include <machine/segments.h>

#include <i386/linux/linux.h>
#include <i386/linux/linux_proto.h>
#include <i386/linux/linux_util.h>
#include <i386/linux/linux_mib.h>

#include <posix4/sched.h>

#define BSD_TO_LINUX_SIGNAL(sig)	\
	(((sig) <= LINUX_SIGTBLSZ) ? bsd_to_linux_signal[_SIG_IDX(sig)] : sig)

static unsigned int linux_to_bsd_resource[LINUX_RLIM_NLIMITS] =
{ RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
  RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
  RLIMIT_MEMLOCK, -1
};

int
linux_alarm(struct proc *p, struct linux_alarm_args *args)
{
    struct itimerval it, old_it;
    struct timeval tv;
    int s;

#ifdef DEBUG
    printf("Linux-emul(%ld): alarm(%u)\n", (long)p->p_pid, args->secs);
#endif
    if (args->secs > 100000000)
	return EINVAL;
    it.it_value.tv_sec = (long)args->secs;
    it.it_value.tv_usec = 0;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    s = splsoftclock();
    old_it = p->p_realtimer;
    getmicrouptime(&tv);
    if (timevalisset(&old_it.it_value))
	untimeout(realitexpire, (caddr_t)p, p->p_ithandle);
    if (it.it_value.tv_sec != 0) {
	p->p_ithandle = timeout(realitexpire, (caddr_t)p, tvtohz(&it.it_value));
	timevaladd(&it.it_value, &tv);
    }
    p->p_realtimer = it;
    splx(s);
    if (timevalcmp(&old_it.it_value, &tv, >)) {
	timevalsub(&old_it.it_value, &tv);
	if (old_it.it_value.tv_usec != 0)
	    old_it.it_value.tv_sec++;
	p->p_retval[0] = old_it.it_value.tv_sec;
    }
    return 0;
}

int
linux_brk(struct proc *p, struct linux_brk_args *args)
{
#if 0
    struct vmspace *vm = p->p_vmspace;
    vm_offset_t new, old;
    int error;

    if ((vm_offset_t)args->dsend < (vm_offset_t)vm->vm_daddr)
	return EINVAL;
    if (((caddr_t)args->dsend - (caddr_t)vm->vm_daddr)
	> p->p_rlimit[RLIMIT_DATA].rlim_cur)
	return ENOMEM;

    old = round_page((vm_offset_t)vm->vm_daddr) + ctob(vm->vm_dsize);
    new = round_page((vm_offset_t)args->dsend);
    p->p_retval[0] = old;
    if ((new-old) > 0) {
	if (swap_pager_full)
	    return ENOMEM;
	error = vm_map_find(&vm->vm_map, NULL, 0, &old, (new-old), FALSE,
			VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error)
	    return error;
	vm->vm_dsize += btoc((new-old));
	p->p_retval[0] = (int)(vm->vm_daddr + ctob(vm->vm_dsize));
    }
    return 0;
#else
    struct vmspace *vm = p->p_vmspace;
    vm_offset_t new, old;
    struct obreak_args /* {
	char * nsize;
    } */ tmp;

#ifdef DEBUG
    printf("Linux-emul(%ld): brk(%p)\n", (long)p->p_pid, (void *)args->dsend);
#endif
    old = (vm_offset_t)vm->vm_daddr + ctob(vm->vm_dsize);
    new = (vm_offset_t)args->dsend;
    tmp.nsize = (char *) new;
    if (((caddr_t)new > vm->vm_daddr) && !obreak(p, &tmp))
	p->p_retval[0] = (int)new;
    else
	p->p_retval[0] = (int)old;

    return 0;
#endif
}

int
linux_uselib(struct proc *p, struct linux_uselib_args *args)
{
    struct nameidata ni;
    struct vnode *vp;
    struct exec *a_out;
    struct vattr attr;
    vm_offset_t vmaddr;
    unsigned long file_offset;
    vm_offset_t buffer;
    unsigned long bss_size;
    int error;
    caddr_t sg;
    int locked;

    sg = stackgap_init();
    CHECKALTEXIST(p, &sg, args->library);

#ifdef DEBUG
    printf("Linux-emul(%ld): uselib(%s)\n", (long)p->p_pid, args->library);
#endif

    a_out = NULL;
    locked = 0;
    vp = NULL;

    NDINIT(&ni, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE, args->library, p);
    error = namei(&ni);
    if (error)
	goto cleanup;

    vp = ni.ni_vp;
    /*
     * XXX This looks like a bogus check - a LOCKLEAF namei should not succeed
     * without returning a vnode.
     */
    if (vp == NULL) {
	error = ENOEXEC;	/* ?? */
	goto cleanup;
    }
    NDFREE(&ni, NDF_ONLY_PNBUF);

    /*
     * From here on down, we have a locked vnode that must be unlocked.
     */
    locked++;

    /*
     * Writable?
     */
    if (vp->v_writecount) {
	error = ETXTBSY;
	goto cleanup;
    }

    /*
     * Executable?
     */
    error = VOP_GETATTR(vp, &attr, p->p_ucred, p);
    if (error)
	goto cleanup;

    if ((vp->v_mount->mnt_flag & MNT_NOEXEC) ||
	((attr.va_mode & 0111) == 0) ||
	(attr.va_type != VREG)) {
	    error = ENOEXEC;
	    goto cleanup;
    }

    /*
     * Sensible size?
     */
    if (attr.va_size == 0) {
	error = ENOEXEC;
	goto cleanup;
    }

    /*
     * Can we access it?
     */
    error = VOP_ACCESS(vp, VEXEC, p->p_ucred, p);
    if (error)
	goto cleanup;

    error = VOP_OPEN(vp, FREAD, p->p_ucred, p);
    if (error)
	goto cleanup;

    /*
     * Lock no longer needed
     */
    VOP_UNLOCK(vp, 0, p);
    locked = 0;

    /*
     * Pull in executable header into kernel_map
     */
    error = vm_mmap(kernel_map, (vm_offset_t *)&a_out, PAGE_SIZE,
	    	    VM_PROT_READ, VM_PROT_READ, 0, (caddr_t)vp, 0);
    if (error)
	goto cleanup;

    /*
     * Is it a Linux binary ?
     */
    if (((a_out->a_magic >> 16) & 0xff) != 0x64) {
	error = ENOEXEC;
	goto cleanup;
    }

    /* While we are here, we should REALLY do some more checks */

    /*
     * Set file/virtual offset based on a.out variant.
     */
    switch ((int)(a_out->a_magic & 0xffff)) {
    case 0413:	/* ZMAGIC */
	file_offset = 1024;
	break;
    case 0314:	/* QMAGIC */
	file_offset = 0;
	break;
    default:
	error = ENOEXEC;
	goto cleanup;
    }

    bss_size = round_page(a_out->a_bss);

    /*
     * Check various fields in header for validity/bounds.
     */
    if (a_out->a_text & PAGE_MASK || a_out->a_data & PAGE_MASK) {
	error = ENOEXEC;
	goto cleanup;
    }

    /* text + data can't exceed file size */
    if (a_out->a_data + a_out->a_text > attr.va_size) {
	error = EFAULT;
	goto cleanup;
    }

    /*
     * text/data/bss must not exceed limits
     * XXX: this is not complete. it should check current usage PLUS
     * the resources needed by this library.
     */
    if (a_out->a_text > MAXTSIZ ||
	a_out->a_data + bss_size > p->p_rlimit[RLIMIT_DATA].rlim_cur) {
	error = ENOMEM;
	goto cleanup;
    }

    /*
     * prevent more writers
     */
    vp->v_flag |= VTEXT;

    /*
     * Check if file_offset page aligned,.
     * Currently we cannot handle misalinged file offsets,
     * and so we read in the entire image (what a waste).
     */
    if (file_offset & PAGE_MASK) {
#ifdef DEBUG
printf("uselib: Non page aligned binary %lu\n", file_offset);
#endif
	/*
	 * Map text+data read/write/execute
	 */

	/* a_entry is the load address and is page aligned */
	vmaddr = trunc_page(a_out->a_entry);

	/* get anon user mapping, read+write+execute */
	error = vm_map_find(&p->p_vmspace->vm_map, NULL, 0, &vmaddr,
		    	    a_out->a_text + a_out->a_data, FALSE,
			    VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error)
	    goto cleanup;

	/* map file into kernel_map */
	error = vm_mmap(kernel_map, &buffer,
			round_page(a_out->a_text + a_out->a_data + file_offset),
		   	VM_PROT_READ, VM_PROT_READ, 0,
			(caddr_t)vp, trunc_page(file_offset));
	if (error)
	    goto cleanup;

	/* copy from kernel VM space to user space */
	error = copyout((caddr_t)(void *)(uintptr_t)(buffer + file_offset),
			(caddr_t)vmaddr, a_out->a_text + a_out->a_data);

	/* release temporary kernel space */
	vm_map_remove(kernel_map, buffer,
		      buffer + round_page(a_out->a_text + a_out->a_data + file_offset));

	if (error)
	    goto cleanup;
    }
    else {
#ifdef DEBUG
printf("uselib: Page aligned binary %lu\n", file_offset);
#endif
	/*
	 * for QMAGIC, a_entry is 20 bytes beyond the load address
	 * to skip the executable header
	 */
	vmaddr = trunc_page(a_out->a_entry);

	/*
	 * Map it all into the process's space as a single copy-on-write
	 * "data" segment.
	 */
	error = vm_mmap(&p->p_vmspace->vm_map, &vmaddr,
		   	a_out->a_text + a_out->a_data,
			VM_PROT_ALL, VM_PROT_ALL, MAP_PRIVATE | MAP_FIXED,
			(caddr_t)vp, file_offset);
	if (error)
	    goto cleanup;
    }
#ifdef DEBUG
printf("mem=%08x = %08x %08x\n", vmaddr, ((int*)vmaddr)[0], ((int*)vmaddr)[1]);
#endif
    if (bss_size != 0) {
        /*
	 * Calculate BSS start address
	 */
	vmaddr = trunc_page(a_out->a_entry) + a_out->a_text + a_out->a_data;

	/*
	 * allocate some 'anon' space
	 */
	error = vm_map_find(&p->p_vmspace->vm_map, NULL, 0, &vmaddr,
			    bss_size, FALSE,
			    VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error)
	    goto cleanup;
    }

cleanup:
    /*
     * Unlock vnode if needed
     */
    if (locked)
	VOP_UNLOCK(vp, 0, p);

    /*
     * Release the kernel mapping.
     */
    if (a_out)
	vm_map_remove(kernel_map, (vm_offset_t)a_out, (vm_offset_t)a_out + PAGE_SIZE);

    return error;
}

/* XXX move */
struct linux_select_argv {
	int nfds;
	fd_set *readfds;
	fd_set *writefds;
	fd_set *exceptfds;
	struct timeval *timeout;
};

int
linux_select(struct proc *p, struct linux_select_args *args)
{
    struct linux_select_argv linux_args;
    struct linux_newselect_args newsel;
    int error;

#ifdef SELECT_DEBUG
    printf("Linux-emul(%ld): select(%x)\n", (long)p->p_pid, args->ptr);
#endif
    if ((error = copyin((caddr_t)args->ptr, (caddr_t)&linux_args,
			sizeof(linux_args))))
	return error;

    newsel.nfds = linux_args.nfds;
    newsel.readfds = linux_args.readfds;
    newsel.writefds = linux_args.writefds;
    newsel.exceptfds = linux_args.exceptfds;
    newsel.timeout = linux_args.timeout;

    return linux_newselect(p, &newsel);
}

int
linux_newselect(struct proc *p, struct linux_newselect_args *args)
{
    struct select_args bsa;
    struct timeval tv0, tv1, utv, *tvp;
    caddr_t sg;
    int error;

#ifdef DEBUG
    printf("Linux-emul(%ld): newselect(%d, %p, %p, %p, %p)\n",
  	(long)p->p_pid, args->nfds, (void *)args->readfds,
	(void *)args->writefds, (void *)args->exceptfds,
	(void *)args->timeout);
#endif
    error = 0;
    bsa.nd = args->nfds;
    bsa.in = args->readfds;
    bsa.ou = args->writefds;
    bsa.ex = args->exceptfds;
    bsa.tv = args->timeout;

    /*
     * Store current time for computation of the amount of
     * time left.
     */
    if (args->timeout) {
	if ((error = copyin(args->timeout, &utv, sizeof(utv))))
	    goto select_out;
#ifdef DEBUG
	printf("Linux-emul(%ld): incoming timeout (%ld/%ld)\n",
	    (long)p->p_pid, utv.tv_sec, utv.tv_usec);
#endif
	if (itimerfix(&utv)) {
	    /*
	     * The timeval was invalid.  Convert it to something
	     * valid that will act as it does under Linux.
	     */
	    sg = stackgap_init();
	    tvp = stackgap_alloc(&sg, sizeof(utv));
	    utv.tv_sec += utv.tv_usec / 1000000;
	    utv.tv_usec %= 1000000;
	    if (utv.tv_usec < 0) {
		utv.tv_sec -= 1;
		utv.tv_usec += 1000000;
	    }
	    if (utv.tv_sec < 0)
		timevalclear(&utv);
	    if ((error = copyout(&utv, tvp, sizeof(utv))))
		goto select_out;
	    bsa.tv = tvp;
	}
	microtime(&tv0);
    }

    error = select(p, &bsa);
#ifdef DEBUG
    printf("Linux-emul(%ld): real select returns %d\n", (long)p->p_pid, error);
#endif

    if (error) {
	/*
	 * See fs/select.c in the Linux kernel.  Without this,
	 * Maelstrom doesn't work.
	 */
	if (error == ERESTART)
	    error = EINTR;
	goto select_out;
    }

    if (args->timeout) {
	if (p->p_retval[0]) {
	    /*
	     * Compute how much time was left of the timeout,
	     * by subtracting the current time and the time
	     * before we started the call, and subtracting
	     * that result from the user-supplied value.
	     */
	    microtime(&tv1);
	    timevalsub(&tv1, &tv0);
	    timevalsub(&utv, &tv1);
	    if (utv.tv_sec < 0)
		timevalclear(&utv);
	} else
	    timevalclear(&utv);
#ifdef DEBUG
	printf("Linux-emul(%ld): outgoing timeout (%ld/%ld)\n",
	    (long)p->p_pid, utv.tv_sec, utv.tv_usec);
#endif
	if ((error = copyout(&utv, args->timeout, sizeof(utv))))
	    goto select_out;
    }

select_out:
#ifdef DEBUG
    printf("Linux-emul(%ld): newselect_out -> %d\n", (long)p->p_pid, error);
#endif
    return error;
}

int
linux_getpgid(struct proc *p, struct linux_getpgid_args *args)
{
    struct proc *curp;

#ifdef DEBUG
    printf("Linux-emul(%ld): getpgid(%d)\n", (long)p->p_pid, args->pid);
#endif
    if (args->pid != p->p_pid) {
	if (!(curp = pfind(args->pid)))
	    return ESRCH;
    }
    else
	curp = p;
    p->p_retval[0] = curp->p_pgid;
    return 0;
}

int
linux_fork(struct proc *p, struct linux_fork_args *args)
{
    int error;

#ifdef DEBUG
    printf("Linux-emul(%ld): fork()\n", (long)p->p_pid);
#endif
    if ((error = fork(p, (struct fork_args *)args)) != 0)
	return error;
    if (p->p_retval[1] == 1)
	p->p_retval[0] = 0;
    return 0;
}

int
linux_vfork(struct proc *p, struct linux_vfork_args *args)
{
	int error;

#ifdef DEBUG
	printf("Linux-emul(%ld): vfork()\n", (long)p->p_pid);
#endif

	if ((error = vfork(p, (struct vfork_args *)args)) != 0)
		return error;
	/* Are we the child? */
	if (p->p_retval[1] == 1)
		p->p_retval[0] = 0;
	return 0;
}

#define CLONE_VM	0x100
#define CLONE_FS	0x200
#define CLONE_FILES	0x400
#define CLONE_SIGHAND	0x800
#define CLONE_PID	0x1000

int
linux_clone(struct proc *p, struct linux_clone_args *args)
{
    int error, ff = RFPROC;
    struct proc *p2;
    int            exit_signal;
    vm_offset_t    start;
    struct rfork_args rf_args;

#ifdef DEBUG
    if (args->flags & CLONE_PID)
	printf("linux_clone(%ld): CLONE_PID not yet supported\n",
	       (long)p->p_pid);
    printf("linux_clone(%ld): invoked with flags %x and stack %x\n",
	   (long)p->p_pid, (unsigned int)args->flags,
	   (unsigned int)args->stack);
#endif

    if (!args->stack)
        return (EINVAL);

    exit_signal = args->flags & 0x000000ff;
    if (exit_signal >= LINUX_NSIG)
	return EINVAL;

    if (exit_signal <= LINUX_SIGTBLSZ)
	exit_signal = linux_to_bsd_signal[_SIG_IDX(exit_signal)];

    /* RFTHREAD probably not necessary here, but it shouldn't hurt either */
    ff |= RFTHREAD;

    if (args->flags & CLONE_VM)
	ff |= RFMEM;
    if (args->flags & CLONE_SIGHAND)
	ff |= RFSIGSHARE;
    if (!(args->flags & CLONE_FILES))
	ff |= RFFDG;

    error = 0;
    start = 0;

    rf_args.flags = ff;
    if ((error = rfork(p, &rf_args)) != 0)
	return error;

    p2 = pfind(p->p_retval[0]);
    if (p2 == 0)
 	return ESRCH;

    p2->p_sigparent = exit_signal;
    p2->p_md.md_regs->tf_esp = (unsigned int)args->stack;

#ifdef DEBUG
    printf ("linux_clone(%ld): successful rfork to %ld\n",
	    (long)p->p_pid, (long)p2->p_pid);
#endif
    return 0;
}

/* XXX move */
struct linux_mmap_argv {
	linux_caddr_t addr;
	int len;
	int prot;
	int flags;
	int fd;
	int pos;
};

#define STACK_SIZE  (2 * 1024 * 1024)
#define GUARD_SIZE  (4 * PAGE_SIZE)
int
linux_mmap(struct proc *p, struct linux_mmap_args *args)
{
    struct mmap_args /* {
	caddr_t addr;
	size_t len;
	int prot;
	int flags;
	int fd;
	long pad;
	off_t pos;
    } */ bsd_args;
    int error;
    struct linux_mmap_argv linux_args;

    if ((error = copyin((caddr_t)args->ptr, (caddr_t)&linux_args,
			sizeof(linux_args))))
	return error;
#ifdef DEBUG
    printf("Linux-emul(%ld): mmap(%p, %d, %d, %08x, %d, %d)\n",
	(long)p->p_pid, (void *)linux_args.addr, linux_args.len,
	linux_args.prot, linux_args.flags, linux_args.fd, linux_args.pos);
#endif
    bsd_args.flags = 0;
    if (linux_args.flags & LINUX_MAP_SHARED)
	bsd_args.flags |= MAP_SHARED;
    if (linux_args.flags & LINUX_MAP_PRIVATE)
	bsd_args.flags |= MAP_PRIVATE;
    if (linux_args.flags & LINUX_MAP_FIXED)
	bsd_args.flags |= MAP_FIXED;
    if (linux_args.flags & LINUX_MAP_ANON)
	bsd_args.flags |= MAP_ANON;
    if (linux_args.flags & LINUX_MAP_GROWSDOWN) {
	bsd_args.flags |= MAP_STACK;      

	/* The linux MAP_GROWSDOWN option does not limit auto
	 * growth of the region.  Linux mmap with this option
	 * takes as addr the inital BOS, and as len, the initial
	 * region size.  It can then grow down from addr without
	 * limit.  However, linux threads has an implicit internal
	 * limit to stack size of STACK_SIZE.  Its just not
	 * enforced explicitly in linux.  But, here we impose
	 * a limit of (STACK_SIZE - GUARD_SIZE) on the stack
	 * region, since we can do this with our mmap.
	 *
	 * Our mmap with MAP_STACK takes addr as the maximum
	 * downsize limit on BOS, and as len the max size of
	 * the region.  It them maps the top SGROWSIZ bytes,
	 * and autgrows the region down, up to the limit
	 * in addr.
	 *
	 * If we don't use the MAP_STACK option, the effect
	 * of this code is to allocate a stack region of a
	 * fixed size of (STACK_SIZE - GUARD_SIZE).
	 */

	/* This gives us TOS */
	bsd_args.addr = linux_args.addr + linux_args.len;

	/* This gives us our maximum stack size */
	if (linux_args.len > STACK_SIZE - GUARD_SIZE)
	    bsd_args.len = linux_args.len;
	else
	    bsd_args.len  = STACK_SIZE - GUARD_SIZE;

	/* This gives us a new BOS.  If we're using VM_STACK, then
	 * mmap will just map the top SGROWSIZ bytes, and let
	 * the stack grow down to the limit at BOS.  If we're
	 * not using VM_STACK we map the full stack, since we
	 * don't have a way to autogrow it.
	 */
	bsd_args.addr -= bsd_args.len;

    } else {
	bsd_args.addr = linux_args.addr;
	bsd_args.len  = linux_args.len;
    }

    bsd_args.prot = linux_args.prot | PROT_READ;	/* always required */
    bsd_args.fd = linux_args.fd;
    bsd_args.pos = linux_args.pos;
    bsd_args.pad = 0;
    return mmap(p, &bsd_args);
}

int     
linux_mremap(struct proc *p, struct linux_mremap_args *args)
{
	struct munmap_args /* {
		void *addr;
		size_t len;
	} */ bsd_args; 
	int error = 0;
 
#ifdef DEBUG
	printf("Linux-emul(%ld): mremap(%p, %08x, %08x, %08x)\n",
	    (long)p->p_pid, (void *)args->addr, args->old_len, args->new_len,
	    args->flags);
#endif
	args->new_len = round_page(args->new_len);
	args->old_len = round_page(args->old_len);

	if (args->new_len > args->old_len) {
		p->p_retval[0] = 0;
		return ENOMEM;
	}

	if (args->new_len < args->old_len) {
		bsd_args.addr = args->addr + args->new_len;
		bsd_args.len = args->old_len - args->new_len;
		error = munmap(p, &bsd_args);
	}

	p->p_retval[0] = error ? 0 : (int)args->addr;
	return error;
}

int
linux_msync(struct proc *p, struct linux_msync_args *args)
{
	struct msync_args bsd_args;

	bsd_args.addr = args->addr;
	bsd_args.len = args->len;
	bsd_args.flags = 0;	/* XXX ignore */

	return msync(p, &bsd_args);
}

int
linux_pipe(struct proc *p, struct linux_pipe_args *args)
{
    int error;
    int reg_edx;

#ifdef DEBUG
    printf("Linux-emul(%ld): pipe(*)\n", (long)p->p_pid);
#endif
    reg_edx = p->p_retval[1];
    error = pipe(p, 0);
    if (error) {
	p->p_retval[1] = reg_edx;
	return error;
    }

    error = copyout(p->p_retval, args->pipefds, 2*sizeof(int));
    if (error) {
	p->p_retval[1] = reg_edx;
	return error;
    }
     
    p->p_retval[1] = reg_edx;
    p->p_retval[0] = 0;
    return 0;
}

int
linux_time(struct proc *p, struct linux_time_args *args)
{
    struct timeval tv;
    linux_time_t tm;
    int error;

#ifdef DEBUG
    printf("Linux-emul(%ld): time(*)\n", (long)p->p_pid);
#endif
    microtime(&tv);
    tm = tv.tv_sec;
    if (args->tm && (error = copyout(&tm, args->tm, sizeof(linux_time_t))))
	return error;
    p->p_retval[0] = tm;
    return 0;
}

struct linux_times_argv {
    long    tms_utime;
    long    tms_stime;
    long    tms_cutime;
    long    tms_cstime;
};

#define CLK_TCK 100	/* Linux uses 100 */
#define CONVTCK(r)	(r.tv_sec * CLK_TCK + r.tv_usec / (1000000 / CLK_TCK))

int
linux_times(struct proc *p, struct linux_times_args *args)
{
    struct timeval tv;
    struct linux_times_argv tms;
    struct rusage ru;
    int error;

#ifdef DEBUG
    printf("Linux-emul(%ld): times(*)\n", (long)p->p_pid);
#endif
    calcru(p, &ru.ru_utime, &ru.ru_stime, NULL);

    tms.tms_utime = CONVTCK(ru.ru_utime);
    tms.tms_stime = CONVTCK(ru.ru_stime);

    tms.tms_cutime = CONVTCK(p->p_stats->p_cru.ru_utime);
    tms.tms_cstime = CONVTCK(p->p_stats->p_cru.ru_stime);

    if ((error = copyout((caddr_t)&tms, (caddr_t)args->buf,
	    	    sizeof(struct linux_times_argv))))
	return error;

    microuptime(&tv);
    p->p_retval[0] = (int)CONVTCK(tv);
    return 0;
}

int
linux_newuname(struct proc *p, struct linux_newuname_args *args)
{
	struct linux_new_utsname utsname;
	char *osrelease, *osname;

#ifdef DEBUG
	printf("Linux-emul(%ld): newuname(*)\n", (long)p->p_pid);
#endif

	osname = linux_get_osname(p);
	osrelease = linux_get_osrelease(p);

	bzero(&utsname, sizeof(struct linux_new_utsname));
	strncpy(utsname.sysname, osname, LINUX_MAX_UTSNAME-1);
	strncpy(utsname.nodename, hostname, LINUX_MAX_UTSNAME-1);
	strncpy(utsname.release, osrelease, LINUX_MAX_UTSNAME-1);
	strncpy(utsname.version, version, LINUX_MAX_UTSNAME-1);
	strncpy(utsname.machine, machine, LINUX_MAX_UTSNAME-1);
	strncpy(utsname.domainname, domainname, LINUX_MAX_UTSNAME-1);

	return (copyout((caddr_t)&utsname, (caddr_t)args->buf,
			sizeof(struct linux_new_utsname)));
}

struct linux_utimbuf {
	linux_time_t l_actime;
	linux_time_t l_modtime;
};

int
linux_utime(struct proc *p, struct linux_utime_args *args)
{
    struct utimes_args /* {
	char	*path;
	struct	timeval *tptr;
    } */ bsdutimes;
    struct timeval tv[2], *tvp;
    struct linux_utimbuf lut;
    int error;
    caddr_t sg;

    sg = stackgap_init();
    CHECKALTEXIST(p, &sg, args->fname);

#ifdef DEBUG
    printf("Linux-emul(%ld): utime(%s, *)\n", (long)p->p_pid, args->fname);
#endif
    if (args->times) {
	if ((error = copyin(args->times, &lut, sizeof lut)))
	    return error;
	tv[0].tv_sec = lut.l_actime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = lut.l_modtime;
	tv[1].tv_usec = 0;
	/* so that utimes can copyin */
	tvp = (struct timeval *)stackgap_alloc(&sg, sizeof(tv));
	if ((error = copyout(tv, tvp, sizeof(tv))))
	    return error;
	bsdutimes.tptr = tvp;
    } else
	bsdutimes.tptr = NULL;

    bsdutimes.path = args->fname;
    return utimes(p, &bsdutimes);
}

#define __WCLONE 0x80000000

int
linux_waitpid(struct proc *p, struct linux_waitpid_args *args)
{
    struct wait_args /* {
	int pid;
	int *status;
	int options;
	struct	rusage *rusage;
    } */ tmp;
    int error, tmpstat;

#ifdef DEBUG
    printf("Linux-emul(%ld): waitpid(%d, %p, %d)\n",
	(long)p->p_pid, args->pid, (void *)args->status, args->options);
#endif
    tmp.pid = args->pid;
    tmp.status = args->status;
    tmp.options = (args->options & (WNOHANG | WUNTRACED));
    /* WLINUXCLONE should be equal to __WCLONE, but we make sure */
    if (args->options & __WCLONE)
	tmp.options |= WLINUXCLONE;
    tmp.rusage = NULL;

    if ((error = wait4(p, &tmp)) != 0)
	return error;

    if (args->status) {
	if ((error = copyin(args->status, &tmpstat, sizeof(int))) != 0)
	    return error;
	tmpstat &= 0xffff;
	if (WIFSIGNALED(tmpstat))
	    tmpstat = (tmpstat & 0xffffff80) |
		      BSD_TO_LINUX_SIGNAL(WTERMSIG(tmpstat));
	else if (WIFSTOPPED(tmpstat))
	    tmpstat = (tmpstat & 0xffff00ff) |
		      (BSD_TO_LINUX_SIGNAL(WSTOPSIG(tmpstat)) << 8);
	return copyout(&tmpstat, args->status, sizeof(int));
    } else
	return 0;
}

int
linux_wait4(struct proc *p, struct linux_wait4_args *args)
{
    struct wait_args /* {
	int pid;
	int *status;
	int options;
	struct	rusage *rusage;
    } */ tmp;
    int error, tmpstat;

#ifdef DEBUG
    printf("Linux-emul(%ld): wait4(%d, %p, %d, %p)\n",
	(long)p->p_pid, args->pid, (void *)args->status, args->options,
	(void *)args->rusage);
#endif
    tmp.pid = args->pid;
    tmp.status = args->status;
    tmp.options = (args->options & (WNOHANG | WUNTRACED));
    /* WLINUXCLONE should be equal to __WCLONE, but we make sure */
    if (args->options & __WCLONE)
	tmp.options |= WLINUXCLONE;
    tmp.rusage = args->rusage;

    if ((error = wait4(p, &tmp)) != 0)
	return error;

    SIGDELSET(p->p_siglist, SIGCHLD);

    if (args->status) {
	if ((error = copyin(args->status, &tmpstat, sizeof(int))) != 0)
	    return error;
	tmpstat &= 0xffff;
	if (WIFSIGNALED(tmpstat))
	    tmpstat = (tmpstat & 0xffffff80) |
		  BSD_TO_LINUX_SIGNAL(WTERMSIG(tmpstat));
	else if (WIFSTOPPED(tmpstat))
	    tmpstat = (tmpstat & 0xffff00ff) |
		  (BSD_TO_LINUX_SIGNAL(WSTOPSIG(tmpstat)) << 8);
	return copyout(&tmpstat, args->status, sizeof(int));
    } else
	return 0;
}

int
linux_mknod(struct proc *p, struct linux_mknod_args *args)
{
	caddr_t sg;
	struct mknod_args bsd_mknod;
	struct mkfifo_args bsd_mkfifo;

	sg = stackgap_init();

	CHECKALTCREAT(p, &sg, args->path);

#ifdef DEBUG
	printf("Linux-emul(%ld): mknod(%s, %d, %d)\n",
	   (long)p->p_pid, args->path, args->mode, args->dev);
#endif

	if (args->mode & S_IFIFO) {
		bsd_mkfifo.path = args->path;
		bsd_mkfifo.mode = args->mode;
		return mkfifo(p, &bsd_mkfifo);
	} else {
		bsd_mknod.path = args->path;
		bsd_mknod.mode = args->mode;
		bsd_mknod.dev = args->dev;
		return mknod(p, &bsd_mknod);
	}
}

/*
 * UGH! This is just about the dumbest idea I've ever heard!!
 */
int
linux_personality(struct proc *p, struct linux_personality_args *args)
{
#ifdef DEBUG
	printf("Linux-emul(%ld): personality(%d)\n",
	   (long)p->p_pid, args->per);
#endif
	if (args->per != 0)
		return EINVAL;

	/* Yes Jim, it's still a Linux... */
	p->p_retval[0] = 0;
	return 0;
}

/*
 * Wrappers for get/setitimer for debugging..
 */
int
linux_setitimer(struct proc *p, struct linux_setitimer_args *args)
{
	struct setitimer_args bsa;
	struct itimerval foo;
	int error;

#ifdef DEBUG
	printf("Linux-emul(%ld): setitimer(%p, %p)\n",
	    (long)p->p_pid, (void *)args->itv, (void *)args->oitv);
#endif
	bsa.which = args->which;
	bsa.itv = args->itv;
	bsa.oitv = args->oitv;
	if (args->itv) {
	    if ((error = copyin((caddr_t)args->itv, (caddr_t)&foo,
			sizeof(foo))))
		return error;
#ifdef DEBUG
	    printf("setitimer: value: sec: %ld, usec: %ld\n",
		foo.it_value.tv_sec, foo.it_value.tv_usec);
	    printf("setitimer: interval: sec: %ld, usec: %ld\n",
		foo.it_interval.tv_sec, foo.it_interval.tv_usec);
#endif
	}
	return setitimer(p, &bsa);
}

int
linux_getitimer(struct proc *p, struct linux_getitimer_args *args)
{
	struct getitimer_args bsa;
#ifdef DEBUG
	printf("Linux-emul(%ld): getitimer(%p)\n",
	    (long)p->p_pid, (void *)args->itv);
#endif
	bsa.which = args->which;
	bsa.itv = args->itv;
	return getitimer(p, &bsa);
}

int
linux_ioperm(struct proc *p, struct linux_ioperm_args *args)
{
	struct sysarch_args sa;
	struct i386_ioperm_args *iia;
	caddr_t sg;

	sg = stackgap_init();
	iia = stackgap_alloc(&sg, sizeof(struct i386_ioperm_args));
	iia->start = args->start;
	iia->length = args->length;
	iia->enable = args->enable;
	sa.op = I386_SET_IOPERM;
	sa.parms = (char *)iia;
	return sysarch(p, &sa);
}

int
linux_iopl(struct proc *p, struct linux_iopl_args *args)
{
	int error;

	if (args->level < 0 || args->level > 3)
		return (EINVAL);
	if ((error = suser(p)) != 0)
		return (error);
	if (securelevel > 0)
		return (EPERM);
	p->p_md.md_regs->tf_eflags = (p->p_md.md_regs->tf_eflags & ~PSL_IOPL) |
		(args->level * (PSL_IOPL / 3));
	return (0);
}

int
linux_nice(struct proc *p, struct linux_nice_args *args)
{
	struct setpriority_args	bsd_args;

	bsd_args.which = PRIO_PROCESS;
	bsd_args.who = 0;	/* current process */
	bsd_args.prio = args->inc;
	return setpriority(p, &bsd_args);
}

int
linux_setgroups(p, uap)
	struct proc *p;
	struct linux_setgroups_args *uap;
{
	struct pcred *pc;
	linux_gid_t linux_gidset[NGROUPS];
	gid_t *bsd_gidset;
	int ngrp, error;

	pc = p->p_cred;
	ngrp = uap->gidsetsize;

	/*
	 * cr_groups[0] holds egid. Setting the whole set from
	 * the supplied set will cause egid to be changed too.
	 * Keep cr_groups[0] unchanged to prevent that.
	 */

	if ((error = suser(p)) != 0)
		return (error);

	if (ngrp >= NGROUPS)
		return (EINVAL);

	pc->pc_ucred = crcopy(pc->pc_ucred);
	if (ngrp > 0) {
		error = copyin((caddr_t)uap->gidset, (caddr_t)linux_gidset,
			       ngrp * sizeof(linux_gid_t));
		if (error)
			return (error);

		pc->pc_ucred->cr_ngroups = ngrp + 1;

		bsd_gidset = pc->pc_ucred->cr_groups;
		ngrp--;
		while (ngrp >= 0) {
			bsd_gidset[ngrp + 1] = linux_gidset[ngrp];
			ngrp--;
		}
	}
	else
		pc->pc_ucred->cr_ngroups = 1;

	setsugid(p);
	return (0);
}

int
linux_getgroups(p, uap)
	struct proc *p;
	struct linux_getgroups_args *uap;
{
	struct pcred *pc;
	linux_gid_t linux_gidset[NGROUPS];
	gid_t *bsd_gidset;
	int bsd_gidsetsz, ngrp, error;

	pc = p->p_cred;
	bsd_gidset = pc->pc_ucred->cr_groups;
	bsd_gidsetsz = pc->pc_ucred->cr_ngroups - 1;

	/*
	 * cr_groups[0] holds egid. Returning the whole set
	 * here will cause a duplicate. Exclude cr_groups[0]
	 * to prevent that.
	 */

	if ((ngrp = uap->gidsetsize) == 0) {
		p->p_retval[0] = bsd_gidsetsz;
		return (0);
	}

	if (ngrp < bsd_gidsetsz)
		return (EINVAL);

	ngrp = 0;
	while (ngrp < bsd_gidsetsz) {
		linux_gidset[ngrp] = bsd_gidset[ngrp + 1];
		ngrp++;
	}

	if ((error = copyout((caddr_t)linux_gidset, (caddr_t)uap->gidset,
	    ngrp * sizeof(linux_gid_t))))
		return (error);

	p->p_retval[0] = ngrp;
	return (0);
}

int
linux_setrlimit(p, uap)
     struct proc *p;
     struct linux_setrlimit_args *uap;
{
    struct osetrlimit_args bsd;

#ifdef DEBUG
    printf("Linux-emul(%ld): setrlimit(%d, %p)\n",
	   (long)p->p_pid, uap->resource, (void *)uap->rlim);
#endif

    if (uap->resource >= LINUX_RLIM_NLIMITS)
	return EINVAL;

    bsd.which = linux_to_bsd_resource[uap->resource];

    if (bsd.which == -1)
	return EINVAL;

    bsd.rlp = uap->rlim;
    return osetrlimit(p, &bsd);
}

int
linux_getrlimit(p, uap)
     struct proc *p;
     struct linux_getrlimit_args *uap;
{
    struct ogetrlimit_args bsd;

#ifdef DEBUG
    printf("Linux-emul(%ld): getrlimit(%d, %p)\n",
	   (long)p->p_pid, uap->resource, (void *)uap->rlim);
#endif

    if (uap->resource >= LINUX_RLIM_NLIMITS)
	return EINVAL;

    bsd.which = linux_to_bsd_resource[uap->resource];

    if (bsd.which == -1)
	return EINVAL;

    bsd.rlp = uap->rlim;
    return ogetrlimit(p, &bsd);
}

int
linux_sched_setscheduler(p, uap)
	struct proc *p;
	struct linux_sched_setscheduler_args *uap;
{
	struct sched_setscheduler_args bsd;

#ifdef DEBUG
	printf("Linux-emul(%ld): sched_setscheduler(%d, %d, %p)\n",
	    (long)p->p_pid, uap->pid, uap->policy, (const void *)uap->param);
#endif

	switch (uap->policy) {
	case LINUX_SCHED_OTHER:
		bsd.policy = SCHED_OTHER;
		break;
	case LINUX_SCHED_FIFO:
		bsd.policy = SCHED_FIFO;
		break;
	case LINUX_SCHED_RR:
		bsd.policy = SCHED_RR;
		break;
	default:
		return EINVAL;
	}

	bsd.pid = uap->pid;
	bsd.param = uap->param;
	return sched_setscheduler(p, &bsd);
}

int
linux_sched_getscheduler(p, uap)
	struct proc *p;
	struct linux_sched_getscheduler_args *uap;
{
	struct sched_getscheduler_args bsd;
	int error;

#ifdef DEBUG
	printf("Linux-emul(%ld): sched_getscheduler(%d)\n",
	       (long)p->p_pid, uap->pid);
#endif

	bsd.pid = uap->pid;
	error = sched_getscheduler(p, &bsd);

	switch (p->p_retval[0]) {
	case SCHED_OTHER:
		p->p_retval[0] = LINUX_SCHED_OTHER;
		break;
	case SCHED_FIFO:
		p->p_retval[0] = LINUX_SCHED_FIFO;
		break;
	case SCHED_RR:
		p->p_retval[0] = LINUX_SCHED_RR;
		break;
	}

	return error;
}

struct linux_descriptor {
	unsigned int  entry_number;
	unsigned long base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
};

int
linux_modify_ldt(p, uap)
	struct proc *p;
	struct linux_modify_ldt_args *uap;
{
	int error;
	caddr_t sg;
	struct sysarch_args args;
	struct i386_ldt_args *ldt;
	struct linux_descriptor ld;
	union descriptor *desc;

	sg = stackgap_init();

	if (uap->ptr == NULL)
		return (EINVAL);

	switch (uap->func) {
	case 0x00: /* read_ldt */
		ldt = stackgap_alloc(&sg, sizeof(*ldt));
		ldt->start = 0;
		ldt->descs = uap->ptr;
		ldt->num = uap->bytecount / sizeof(union descriptor);
		args.op = I386_GET_LDT;
		args.parms = (char*)ldt;
		error = sysarch(p, &args);
		p->p_retval[0] *= sizeof(union descriptor);
		break;
	case 0x01: /* write_ldt */
	case 0x11: /* write_ldt */
		if (uap->bytecount != sizeof(ld))
			return (EINVAL);

		error = copyin(uap->ptr, &ld, sizeof(ld));
		if (error)
			return (error);

		ldt = stackgap_alloc(&sg, sizeof(*ldt));
		desc = stackgap_alloc(&sg, sizeof(*desc));
		ldt->start = ld.entry_number;
		ldt->descs = desc;
		ldt->num = 1;
		desc->sd.sd_lolimit = (ld.limit & 0x0000ffff);
		desc->sd.sd_hilimit = (ld.limit & 0x000f0000) >> 16;
		desc->sd.sd_lobase = (ld.base_addr & 0x00ffffff);
		desc->sd.sd_hibase = (ld.base_addr & 0xff000000) >> 24;
		desc->sd.sd_type = SDT_MEMRO | ((ld.read_exec_only ^ 1) << 1) |
			(ld.contents << 2);
		desc->sd.sd_dpl = 3;
		desc->sd.sd_p = (ld.seg_not_present ^ 1);
		desc->sd.sd_xx = 0;
		desc->sd.sd_def32 = ld.seg_32bit;
		desc->sd.sd_gran = ld.limit_in_pages;
		args.op = I386_SET_LDT;
		args.parms = (char*)ldt;
		error = sysarch(p, &args);
		break;
	default:
		error = EINVAL;
		break;
	}

	if (error == EOPNOTSUPP) {
		printf("linux: modify_ldt needs kernel option USER_LDT\n");
		error = ENOSYS;
	}

	return (error);
}
