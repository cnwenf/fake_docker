#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>


int main()
{
    char* cmd;
    int netns = 1024
    sprintf(cmd, "ip netns exec %d ip link set dev lo up", netns);
}

