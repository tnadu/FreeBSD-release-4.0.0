# Bookmarks to files relevant to the Jail implementation

## Jail

### Files

#### 📌 [`jail.h`](sys/jail.h)

```c
- struct jail;
- struct prison;
```

#### 📌 [`kern_jail.c`](kern/kern_jail.c)

```c
- int jail(struct proc *p, struct jail_args *uap);
```


## CHROOT

### Basic flow

```
chroot() → change_dir() → namei() → lookup()
```

### Files

#### 📌 [`vfs_syscalls.c`](kern/vfs_syscall.c)

```c
- int chroot(struct proc *p, struct chroot_args *uap);
- static int change_dir(register struct nameidata *ndp, struct proc *p);
- static int chroot_refuse_vdir_fds(struct filedesc *fdp);
- int fchdir(struct proc *p, struct fchdir_args *uap);
```

#### 📌 [`vfs_lookup.c`](kern/vfs_lookup.c)

```c
- int namei(register struct nameidata *ndp);
- int lookup(register struct nameidata *ndp);
```


## Networking

### Basic flow
#### Binding
```
in_pcbbind() → prison_ip()
```

#### Initializing connections
```
tcp_usr_connect()/udp_connect() → prison_remote_ip()
```

#### Listing network interfaces
```
ifconf()/sysctl_iflist() → prison_if()
```

### Files
#### 📌 [`kern_jail.c`](kern/kern_jail.c)

```c
- int prison_ip(struct proc *p, int flag, u_int32_t *ip);
- void prison_remote_ip(struct proc *p, int flag, u_int32_t *ip);
- int prison_if(struct proc *p, struct sockaddr *sa);
```


## Processes
### Basic flow
```
either
FUNC -> p_trespass() -> PRISON_CHECK()
-> this case is used whenever superuser privileges are needed

or
FUNC -> PRISON_CHECK()

* where FUNC := any function that requests other proc's resources
```

### Files
#### 📌 [`kern_prot.c`](kern/kern_prot.c)

```c
- int p_trespass(struct proc *p1, struct proc *p2);
- int suser_xxx(cred, proc, flag);
```

#### 📌 [`proc.h`](sys/proc.h)

```c
- #define PRISON_CHECK(p1, p2) ((!(p1)->p_prison) || (p1)->p_prison == (p2)->p_prison)
```

#### 📌 [`procfs_vnops.c`](miscfs/procfs/procfs_vnops.c)
