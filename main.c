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

#define STACK_SIZE (1024 * 1024)

static char container_stack[STACK_SIZE];
char* const container_args[] = {
        "/bin/bash",
        "-l",
        NULL
};
int pipefd[2];


int container_main(void* arg)
{
    printf("Container [%5d] - inside the container!\n", getpid());

    printf("Container: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
           (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());

    /* 等待父进程通知后再往下执行（进程间的同步） */
    char ch;
    close(pipefd[1]);
    read(pipefd[0], &ch, 1);

    printf("Container [%5d] - setup hostname!\n", getpid());
    //set hostname
    sethostname("fake_docker", 10);

    //remount "/proc" to make sure the "top" and "ps" show container's information
    if (mount("proc", "rootfs/proc", "proc", 0, NULL) !=0 ) {
        perror("proc");
    }
    if (mount("sysfs", "rootfs/sys", "sysfs", 0, NULL)!=0) {
        perror("sys");
    }
    if (mount("none", "rootfs/tmp", "tmpfs", 0, NULL)!=0) {
        perror("tmp");
    }
    if (mount("udev", "rootfs/dev", "devtmpfs", 0, NULL)!=0) {
        perror("dev");
    }
    if (mount("devpts", "rootfs/dev/pts", "devpts", 0, NULL)!=0) {
        perror("dev/pts");
    }
    if (mount("shm", "rootfs/dev/shm", "tmpfs", 0, NULL)!=0) {
        perror("dev/shm");
    }
    if (mount("tmpfs", "rootfs/run", "tmpfs", 0, NULL)!=0) {
        perror("run");
    }
    /* 
     * 模仿Docker的从外向容器里mount相关的配置文件 
     * 你可以查看：/var/lib/docker/containers/<container_id>/目录，
     * 你会看到docker的这些文件的。
     */
    if (mount("conf/hosts", "rootfs/etc/hosts", "none", MS_BIND, NULL)!=0 ||
        mount("conf/hostname", "rootfs/etc/hostname", "none", MS_BIND, NULL)!=0 ||
        mount("conf/resolv.conf", "rootfs/etc/resolv.conf", "none", MS_BIND, NULL)!=0 ) {
        perror("conf");
    }
    /* 模仿docker run命令中的 -v, --volume=[] 参数干的事 */
    if (mount("/tmp/t1", "rootfs/mnt", "none", MS_BIND, NULL)!=0) {
        perror("mnt");
    }

    /* chroot 隔离目录 */
    if ( chdir("./rootfs") != 0 || chroot("./") != 0 ){
        perror("chdir/chroot");
    }

    /* 关于execv，
     * 参见https://stackoverflow.com/questions/1653340/differences-between-fork-and-exec
     * */
    execv(container_args[0], container_args);
    perror("exec");
    printf("Something's wrong!\n");
    return 1;
}

int print_system(char* cmd)
{
    printf("%s\n", cmd);
    return system(cmd);
}

int main()
{
    printf("Parent [%5d] - start a container!\n", getpid());
    const int gid=getgid(), uid=getuid();

    printf("Parent: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
           (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());

    pipe(pipefd);

    /*
     * CLONE_NEWUTS: hostname及domainname隔离
     * CLONE_NEWIPC：IPC隔离
     * CLONE_NEWPID：PID隔离，容器内进程号显示为1
     * CLONE_NEWNS：mount隔离，容器内的挂载信息独立显示
     * CLONE_NEWUSER: User隔离
     * 参考：https://man7.org/linux/man-pages/man2/clone.2.html
     * */
    int container_pid = clone(container_main, container_stack+STACK_SIZE,
                              CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD, NULL);

    if (container_pid < 0) {
        perror("clone error");
        return 1;
    }
    /* 准备容器网络
     * 1. 创建虚机网卡对
     * 2. 虚拟网卡对，外部网卡加到fake_docker0网桥上，内部网卡添加到容器内
     * 3. 激活容器内的lo
     * 4. 修改容器内的网卡名称，便于容器内使用
     * 5. 为容器内的虚机网卡配置IP地址并激活
     * 6. 为容器添加默认路由
     * */
    int netns = container_pid;
    printf("Parent [%5d] - Container [%5d]!\n", getpid(), container_pid);

    char outer[100];
    char inner[100];
    snprintf(outer, 100, "veth%d", netns);
    snprintf(inner, 100, "veth%d.inner", netns);

    char cmd[100];

    snprintf(cmd, 100, "ip link add %s type veth peer name %s", outer, inner);
    print_system(cmd);

    snprintf(cmd, 100, "brctl addif fake_docker0 %s", outer);
    print_system(cmd);
    snprintf(cmd, 100, "ip link set %s netns %d", inner, netns);
    print_system(cmd);

    snprintf(cmd, 100, "ip netns exec %d ip link set dev lo up", netns);
    print_system(cmd);

    snprintf(cmd, 100, "ip netns exec %d ip link set dev %s name eth0", netns, inner);
    print_system(cmd);

    snprintf(cmd, 100, "ip netns exec %d ifconfig eth0 192.168.168.2/24 up", netns);
    print_system(cmd);

    snprintf(cmd, 100, "ip netns exec %d ip route add default via 192.168.168.1", netns);
    print_system(cmd);

    printf("Parent [%5d] - Container [%5d]!\n", getpid(), container_pid);

    /* 通知子进程 */
    close(pipefd[1]);

    waitpid(container_pid, NULL, 0);
    printf("Parent - container stopped!\n");
    return 0;
}