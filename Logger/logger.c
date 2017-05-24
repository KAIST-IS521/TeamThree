#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

// Directory check
#include <sys/stat.h>

// Sandbox
#include <sys/prctl.h>
#include <seccomp.h>

// Unix timestamp
#include <time.h>

#define SYSALLOW(s) \
    do {\
      rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(s), 0); \
      if (rc < 0) goto out; \
    } while (0)

void secureExec(const char* pathname, char *args[], char *envp[])
{
    int rc = -1;
    scmp_filter_ctx ctx;

    // ensure none of our children will ever be granted more priv
    // (via setuid, capabilities, ...)
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // ensure no escape is possible via ptrace
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    ctx = seccomp_init(SCMP_ACT_KILL); // kill if filtered syscall used

    // whitelist
    SYSALLOW(arch_prctl);
    SYSALLOW(brk);
    SYSALLOW(close);
    SYSALLOW(execve);
    SYSALLOW(exit_group);
    SYSALLOW(fstat);
    SYSALLOW(fstat64);
    SYSALLOW(getcwd);
    SYSALLOW(getdents);
    SYSALLOW(getegid);
    SYSALLOW(geteuid);
    SYSALLOW(getgid);
    SYSALLOW(getrlimit);
    SYSALLOW(getuid);
    SYSALLOW(ioctl);
    SYSALLOW(lseek);
    SYSALLOW(lstat);
    SYSALLOW(mmap);
    SYSALLOW(mmap2);
    SYSALLOW(mprotect);
    SYSALLOW(munmap);
    SYSALLOW(open);
    SYSALLOW(read);
    SYSALLOW(readlink);
    SYSALLOW(recvfrom);
    SYSALLOW(rt_sigaction);
    SYSALLOW(rt_sigprocmask);
    SYSALLOW(sendto);
    SYSALLOW(set_robust_list);
    SYSALLOW(set_thread_area);
    SYSALLOW(set_tid_address);
    SYSALLOW(setsockopt);
    SYSALLOW(socket);
    SYSALLOW(stat);
    SYSALLOW(stat64);
    SYSALLOW(sysinfo);
    SYSALLOW(uname);
    SYSALLOW(write);

    // make access check fail
    // We cannot kill because kernel uses it automatically for ld-preload
    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(-1), SCMP_SYS(access), 0);
    if (rc < 0) goto out;

    rc = seccomp_load(ctx);
    if (rc < 0) goto out;

    execve(pathname, args, envp);
    rc = -1;
out:
    seccomp_release(ctx);
    return;
}

int isDirAt(int dfd, const char* pathname)
{
    struct stat sb;
    return fstatat(dfd, pathname, &sb, 0) == 0 && S_ISDIR(sb.st_mode);
}

int main(int argc, char *argv[], char *envp[])
{
    char *args[4];
    DIR *pDir;
    struct dirent *pDirent;
    FILE *logfile;
    pid_t pid;

    if (argc < 5)
    {
        printf("%s [ip addr] [port] [testcase dir] [logfile]\n", argv[0]);
        return EXIT_FAILURE;
    }

    args[1] = argv[1]; // ip
    args[2] = argv[2]; // port
    args[3] = NULL;    // Terminate

    pDir = opendir(argv[3]);
    if (pDir == NULL)
    {
        perror("opendir");
        return EXIT_FAILURE;
    }

    logfile = fopen(argv[4], "w");
    if (logfile == NULL)
    {
        perror("fopen");
        closedir(pDir);
        return EXIT_FAILURE;
    }

    while ((pDirent = readdir(pDir)) != NULL)
    {
        int dfd = dirfd(pDir);

        // skip dir
        if (isDirAt(dfd, pDirent->d_name)) continue;

        // skip non-executable file
        if (faccessat(dfd, pDirent->d_name, X_OK, 0) != 0) continue;

        pid = fork();
        if (pid == -1)
        {
            perror("fork");
            closedir(pDir);
            return EXIT_FAILURE;
        }
        else if (pid == 0) // Child process
        {
            char* path;
            closedir(pDir);
            fclose(logfile);

            // get real pathname from dirname and filename
            path = (char*)malloc(strlen(argv[3]) + strlen(pDirent->d_name) + 2);
            strcpy(path, argv[3]);
            strcat(path, "/");
            strcat(path, pDirent->d_name);

            // set args. ip, port are already set
            args[0] = path;

            // TODO: check whether we need environment
#ifndef DEBUG
            secureExec(path, args, envp);
#else
            execve(path, args, envp);
#endif

            // if Error, return status will be 2.
            return 2;
        }
        else // Parent process
        {
            int status;
            waitpid(pid, &status, 0);

            // TODO: check for other cases - e.g. stop by signal
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                fprintf(logfile, "%u, %s, %s, %s\n",\
                        (unsigned)time(NULL), args[1], args[2], "up");
            } else {
                fprintf(logfile, "%u, %s, %s, %s\n",\
                        (unsigned)time(NULL), args[1], args[2], "down");
            }
            fflush(logfile);
        }
    }
    closedir(pDir);
    fclose(logfile);
    return EXIT_SUCCESS;
}
