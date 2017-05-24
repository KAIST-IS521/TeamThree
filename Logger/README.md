# Logger

Logger for sla check with sandbox.

# Run

`./logger [ip addr] [port] [testcase dir] [logfile]`

# Sandbox

Following lists can be updated even after `checkpoint #1` because we can
sure what to allow when all other sla checkers are implemented. Note that
syscalls not in any list cannot be used.

### List of allowed syscalls

- arch_prctl
- brk
- close
- execve
- exit_group
- fstat
- fstat64
- getcwd
- getdents
- getegid
- geteuid
- getgid
- getrlimit
- getuid
- ioctl
- lseek
- lstat
- mmap
- mmap2
- mprotect
- munmap
- open
- read
- readlink
- recvfrom
- rt_sigaction
- rt_sigprocmask
- sendto
- set_robust_list
- set_thread_area
- set_tid_address
- setsockopt
- socket
- stat
- stat64
- sysinfo
- uname
- write

### Restricted syscalls

- access : always return -1
