#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

int isDirAt(int dirfd, const char* pathname)
{
    return 1;
}

int main(int argc, char **argv)
{
    char *ip, *port;
    DIR *pDir;
    struct dirent *pDirent;
    FILE *logfile;
    pid_t pid;

    if (argc <= 5)
    {
        printf("%s [ip addr] [port] [testcase dir] [logfile]\n", argv[0]);
        return EXIT_FAILURE;
    }

    ip = argv[1];
    port = argv[2];

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
        else if (pid == 0)
        {
            //TODO: child
        }
        else
        {
            //TODO: parent
        }
    }
    closedir(pDir);
}
