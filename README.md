# **CHROOT in FreeBSD**

## **Basic flow**

chroot() → change_dir() → namei() → lookup()
---

## **Relevant Kernel Files and Functions**

### **📌 `kern/vfs_syscalls.c` **

```c

- int chroot               
- static int change_dir    
- static int chroot_refuse_vdir_fds 
- int fchdir                

```

### **📌 `kern/vfs_lookup.c` **

```c

- int namei                
- int lookup

```
