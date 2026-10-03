/* container.c: STUDENT IMPLEMENTATION FILE for Project 2.
 *
 * You implement a minimal container runtime here. main.c parses the command
 * line and calls container_run(); everything after that is yours.
 *
 * The TODOs below are the checklist: what to call and in what order. SPEC.md
 * explains what each mechanism is and why the order matters, and is the
 * contract if the two ever disagree.
 *
 * As shipped, container_run() returns 1 and nothing runs, so no checks pass.
 * Start by getting the command to execute: that needs container_run() and
 * container_init() to spawn it and container_setup() to pivot into the rootfs,
 * because the command lives inside the rootfs.
 *
 * Provided: main.c (argument parsing), util.c (write_file()), net.c (the --net
 * host side), container.h (the struct, the declarations, the stack size).
 */
#define _GNU_SOURCE
#include "container.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/route.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mount.h>

/* ---- Part I: namespaces ----------------------------------------------- */

int container_namespaces(void)
{
    /* TODO(student): return the bitwise-OR of CLONE_NEWUSER, CLONE_NEWPID,
     * CLONE_NEWNS, CLONE_NEWUTS and CLONE_NEWNET. Returning 0 gives no
     * isolation at all. */
     return CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET;
}

int container_write_idmaps(struct container *c, pid_t child)
{
    (void)c; (void)child;
    /* TODO(student): a USER namespace starts with an EMPTY uid/gid map, so the
     * child cannot do anything until you write one. Write, using write_file():
     *   /proc/<child>/uid_map     <- "0 <your-uid> 1"
     *   /proc/<child>/setgroups   <- "deny"      (required before gid_map)
     *   /proc/<child>/gid_map     <- "0 <your-gid> 1"
     * This maps container id 0 (root) to your real id outside. See getuid(2). */
    char path[64];
    char map[64];

    sprintf(path, "/proc/%d/uid_map", (int)child);
    sprintf(map, "0 %d 1", (int) getuid()); 
    if (write_file(path, map) < 0)
        return -1;

    sprintf(path, "/proc/%d/setgroups", (int)child);
    if (write_file(path, "deny") < 0)
        return -1;

    sprintf(path, "/proc/%d/gid_map", (int)child);
    sprintf(map, "0 %d 1", (int) getgid());
    if (write_file(path, map) < 0)
        return -1;

    return 0;
}

/* ---- Part V: cgroup --------------------------------------------------- */

int container_cgroup_init(struct container *c)
{
    /* TODO(student): create this container's cgroup and set its limits (SPEC
     * Part V):
     *   - enable the controllers you need in the BASE cgroup's subtree_control:
     *       write "+pids +memory" to <cgroup_base>/cgroup.subtree_control;
     *   - mkdir <cgroup_base>/<name>  and store that path in c->cg_path
     *     (cleanup needs it);
     *   - write c->pids_max to <cg_path>/pids.max and c->mem_max to
     *     <cg_path>/memory.max (a value < 0 means the literal string "max"), and
     *     write "0" to <cg_path>/memory.swap.max so hitting the memory cap
     *     OOM-kills instead of swapping. */
    char path[PATH_MAX];
    char value[64];
    int n;

    n = snprintf(path, sizeof path, "%s/cgroup.subtree_control",
                 c->cgroup_base);
    if (n < 0 || (size_t)n >= sizeof path || write_file(path, "+pids +memory") < 0)
        return -1;

    n = snprintf(c->cg_path, sizeof c->cg_path, "%s/%s",
                 c->cgroup_base, c->name);
    if (n < 0 || (size_t)n >= sizeof c->cg_path) {
        fprintf(stderr, "container: cgroup path is too long\n");
        c->cg_path[0] = '\0';
        return -1;
    }

    if (mkdir(c->cg_path, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "container: mkdir(%s): %s\n", c->cg_path,
                strerror(errno));
        c->cg_path[0] = '\0';
        return -1;
    }

    n = snprintf(path, sizeof path, "%s/pids.max", c->cg_path);
    if (n < 0 || (size_t)n >= sizeof path ||
        snprintf(value, sizeof value, "%ld", c->pids_max) < 0 ||
        write_file(path, value) < 0)
        return -1;

    n = snprintf(path, sizeof path, "%s/memory.max", c->cg_path);
    if (n < 0 || (size_t)n >= sizeof path)
        return -1;
    if (c->mem_max < 0) {
        strcpy(value, "max");
    } else if (snprintf(value, sizeof value, "%ld", c->mem_max) < 0) {
        return -1;
    }
    if (write_file(path, value) < 0)
        return -1;

    n = snprintf(path, sizeof path, "%s/memory.swap.max", c->cg_path);
    if (n < 0 || (size_t)n >= sizeof path || write_file(path, "0") < 0)
        return -1;

    return 0;
}

int container_cgroup_enter(struct container *c, pid_t child)
{
    /* TODO(student): move `child` into this container's cgroup by writing its
     * pid to <cg_path>/cgroup.procs. */
    char path[PATH_MAX];
    char pid[32];
    int n = snprintf(path, sizeof path, "%s/cgroup.procs", c->cg_path);
    if (n < 0 || (size_t)n >= sizeof path ||
        snprintf(pid, sizeof pid, "%ld", (long)child) < 0 ||
        write_file(path, pid) < 0)
        return -1;

    return 0;
}

/* ---- Parts I/II/III: isolation, run inside the container init --------- */

int container_setup(struct container *c)
{
    (void)c;
    /* Runs inside the container's init, after the parent has written your id
     * maps and put you in the cgroup, and before you launch the command.
     *
     * TODO(student) Part I   - set the hostname to c->hostname (sethostname(2)).
     *
     * TODO(student) Part I   - call container_network() to bring up loopback
     *     (before the capability drop; it needs CAP_NET_ADMIN).
     *
     * TODO(student) Part I   - if c->net_enabled, call container_net_config(c)
     *     to set up the veth the host provided (also before the cap drop).
     *
     * TODO(student) Part II  - isolate the filesystem, pivoting into c->rootfs:
     *     1. make mount propagation private so your mounts don't leak to the
     *        host:  mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
     *     2. bind c->rootfs onto itself, then remount that bind read-only;
     *     3. mount a writable tmpfs on <rootfs>/tmp;
     *     4. mount a tmpfs on <rootfs>/dev and bind /dev/null and /dev/zero in
     *        (you cannot mknod(2) in a user namespace);
     *     5. mount a fresh /proc on <rootfs>/proc, BEFORE switching roots: a
     *        new /proc can only be mounted in a user namespace while another
     *        /proc is still visible, so doing it after detaching the old root
     *        fails with EPERM;
     *     6. pivot_root(2) into c->rootfs and detach the old root, chdir("/").
     *
     * TODO(student) Part III - drop all capabilities so container-root is
     *     powerless: empty the bounding set (prctl PR_CAPBSET_DROP for every cap
     *     0..CAP_LAST_CAP), clear the permitted/effective/inheritable sets
     *     (capset(2)), and set PR_SET_NO_NEW_PRIVS. Do this near-last, so the
     *     steps above still have the privileges they need.
     *
     * TODO(student) Part III - then call container_seccomp() to install the
     *     syscall filter (do it last of all).
     *
     * Return 0 on success, -1 to abort. */
     //set hostname 
    if (sethostname(c->hostname, strlen(c->hostname)) < 0) {
        perror("sethostname");
        return -1;
    }

    container_network(); 

    if(c->net_enabled) {
        container_net_config(c);
    }

    //set up part 2: mounted filesystem

    //make mount propagation private 
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("container: mount private /");
        return -1;
    }

    //bind the rootfs onto itself
    if (mount(c->rootfs, c->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("container: bind rootfs");
        return -1;
    }

    //remount bind  as read-only
    if (mount(NULL, c->rootfs, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
        perror("container: remount rootfs read-only");
        return -1;
    }

    //mount a writable /tmp
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/tmp", c->rootfs);
    if (mount("tmpfs", path, "tmpfs", 0, NULL) < 0) {
        perror("container: mount /tmp");
        return -1;
    }

    //mount /dev 
    snprintf(path, sizeof path, "%s/dev", c->rootfs);
    if (mount("tmpfs", path, "tmpfs", 0, NULL) < 0) {
        perror("container: mount /dev");
        return -1;
    }

    //create empty files dev/null and dev/zero
    snprintf(path, sizeof path, "%s/dev/null", c->rootfs);
    int fd1 = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd1 < 0) {
        perror("container: create /dev/null");
        return -1;
    }
    close(fd1);

    snprintf(path, sizeof path, "%s/dev/zero", c->rootfs);
    int fd2 = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd2 < 0) {
        perror("container: create /dev/zero");
        return -1;
    }
    close(fd2);

    //make each empty file show the host's device instead (use bind mount)
    snprintf(path, sizeof path, "%s/dev/null", c->rootfs);
    if (mount("/dev/null", path, NULL, MS_BIND, NULL) < 0) {
        perror("container: bind /dev/null");
        return -1;
    }

    snprintf(path, sizeof path, "%s/dev/zero", c->rootfs);
    if (mount("/dev/zero", path, NULL, MS_BIND, NULL) < 0) {
        perror("container: bind /dev/zero");
        return -1;
    }

    //mount a fresh /proc 
    snprintf(path, sizeof path, "%s/proc", c->rootfs);
    if (mount("proc", path, "proc", 0, NULL) < 0) {
        perror("container: mount /proc");
        return -1;
    }

    //switch roots 
    if (chdir(c->rootfs) < 0) {
        perror("container: chdir rootfs");
        return -1;
    }
    if (syscall(SYS_pivot_root, ".", ".") < 0) {
        perror("container: pivot_root");
        return -1;
    }
    if (umount2(".", MNT_DETACH) < 0) {
        perror("container: detach old root");
        return -1;
    }
    if (chdir("/") < 0) {
        perror("container: chdir /");
        return -1;
    }

    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
            fprintf(stderr, "container: prctl(PR_CAPBSET_DROP, %d): %s\n",
                    cap, strerror(errno));
            return -1;
        }
    }

    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}, {0}};

    if (syscall(SYS_capset, &hdr, data) != 0) {
        fprintf(stderr, "container: capset(): %s\n", strerror(errno));
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "container: prctl(PR_SET_NO_NEW_PRIVS): %s\n",
                strerror(errno));
        return -1;
    }

    if (container_seccomp() < 0) {
        return -1;
    }

    return 0;
}

int container_network(void)
{
    /* TODO(student) Part I: the container has its own NET namespace, so it starts
     * with only a `lo` interface that is DOWN. Bring it UP so localhost works:
     * open an AF_INET SOCK_DGRAM socket, fill a `struct ifreq` with ifr_name
     * "lo", ioctl(SIOCGIFFLAGS) to read its flags, OR in IFF_UP | IFF_RUNNING,
     * and ioctl(SIOCSIFFLAGS) to set them. Best-effort: this needs CAP_NET_ADMIN,
     * so call it before dropping capabilities. */
     int fd = socket(AF_INET, SOCK_DGRAM, 0);
     if (fd < 0) {
         perror("socket");
         return 0; 
     }
     struct ifreq ifr; 
     memset(&ifr, 0, sizeof(ifr));
 
     strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
 
     if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
         perror("SIOCGIFFLAGS");
         close(fd);
         return 0;
     }
 
     ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
 
     if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
         perror("SIOCSIFFLAGS");
         close(fd);
         return 0;
     }

     close(fd);
    return 0;
}

int container_net_config(struct container *c)
{
    (void)c;
    /* TODO(student) Part I (--net only): the provided container_net_host_setup()
     * has put an interface named c->net_ifname in this namespace. Configure it
     * (same ioctls as loopback, plus an address and a route):
     *   - ioctl(SIOCSIFADDR)   with c->net_ip;
     *   - ioctl(SIOCSIFNETMASK) with the mask for c->net_prefix;
     *   - ioctl(SIOCSIFFLAGS)  with IFF_UP | IFF_RUNNING;
     *   - add a default route via c->net_gw: fill a `struct rtentry`
     *     (rt_dst/rt_genmask 0.0.0.0, rt_gateway = c->net_gw,
     *     rt_flags = RTF_UP | RTF_GATEWAY) and ioctl(SIOCADDRT).
     * Needs CAP_NET_ADMIN, so container_setup() calls this before the cap drop. */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        return -1; 
    }

    struct ifreq ifr;
    struct sockaddr_in *sin; 
    
    //ip addr
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, c->net_ifname, IFNAMSIZ - 1);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET; 
    inet_pton(AF_INET, c->net_ip, &sin->sin_addr);
    ioctl(fd, SIOCSIFADDR, &ifr);

    //netmask 
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, c->net_ifname, IFNAMSIZ - 1);
    sin = (struct sockaddr_in *)&ifr.ifr_netmask; 
    sin->sin_family = AF_INET; 
    sin->sin_addr.s_addr = htonl(~0u << (32 -c->net_prefix));
    ioctl(fd, SIOCSIFNETMASK, &ifr);

    //flags
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, c->net_ifname, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING; 
    ioctl(fd, SIOCSIFFLAGS, &ifr);

    //default route via net gateway 
    struct rtentry rt;
    memset(&rt, 0, sizeof rt);
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
    sin = (struct sockaddr_in *)&rt.rt_gateway;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, c->net_gw, &sin->sin_addr);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    ioctl(fd, SIOCADDRT, &rt);
    
    close(fd);    

    
    return 0;
}

int container_seccomp(void)
{
    /* Deny dangerous syscalls by returning EPERM, while allowing every other
     * call. The filter also rejects any syscall coming from a foreign CPU ABI.
     */
    int arch;
#if defined(__x86_64__)
    arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    arch = AUDIT_ARCH_AARCH64;
#else
# error "Unsupported build architecture for seccomp filter"
#endif

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umount2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chroot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setns, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_reboot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_swapon, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_swapoff, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kexec_load, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_init_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_finit_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_delete_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        fprintf(stderr, "container: seccomp filter install failed: %s\n",
                strerror(errno));
        return -1;
    }

    return 0;
}

int container_init(struct container *c)
{

    /* TODO(student) Part IV: this is the container's init, PID 1 in a fresh PID
     * namespace. It runs in the cloned child. Do, in order:
     *   1. wait for the parent to release you: close c->sync[1], then read one
     *      byte from c->sync[0] (it blocks until main's parent writes id-maps
     *      and enters you in the cgroup), then close c->sync[0];
     *   2. call container_setup(c) to isolate this process;
     *   3. fork(). In the child, execvp(c->argv[0], c->argv) -- that is the
     *      command. The parent (you) STAYS as init;
     *   4. loop waitpid(-1, ...): reap every child that dies (adopted orphans
     *      included). Stop when the command itself is reaped; return its exit
     *      status (WEXITSTATUS, or 128+signal if it was killed).
     * The value you return here is what the container exits with. */
    
    char ch;

    close(c->sync[1]);
    if (read(c->sync[0], &ch, 1) != 1) {
        fprintf(stderr, "container: failed to read sync byte\n");
        return 1;
    }
    close(c->sync[0]);

    if (container_setup(c) < 0) {
        return 1;
    }

    pid_t cmd_pid = fork();
    if (cmd_pid < 0) {
        fprintf(stderr, "container: fork(): %s\n", strerror(errno));
        return 1;
    }

    if (cmd_pid == 0) {
        execvp(c->argv[0], c->argv);
        fprintf(stderr, "container: execvp(%s): %s\n", c->argv[0], strerror(errno));
        _exit(127);
    }

    while (1) {
        int st;
        pid_t pid = waitpid(-1, &st, 0);
        if (pid < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "container: waitpid(): %s\n", strerror(errno));
            return 1;
        }

        if (pid == cmd_pid) {
            if (WIFEXITED(st))
                return WEXITSTATUS(st);
            if (WIFSIGNALED(st))
                return 128 + WTERMSIG(st);
            return 1;
        }
    }
}

static int container_clone_trampoline(void *arg)
{
    return container_init((struct container *)arg);
}

/* ---- the whole lifecycle: main.c calls only this ----------------------- */

int container_run(struct container *c)
{
    /* TODO(student): drive the container's whole lifecycle and return the
     * command's exit status. In order:
     *   1. container_cgroup_init(c)                      (Part V);
     *   2. pipe(c->sync)                                 (the release pipe);
     *   3. clone() a child into fresh namespaces: allocate a stack of
     *      CONTAINER_STACK_SIZE bytes, and clone a small trampoline that calls
     *      container_init(c), with flags container_namespaces() | SIGCHLD.
     *      (clone wants an int(*)(void*); the stack grows down, so pass the
     *      TOP of the buffer: stack + CONTAINER_STACK_SIZE.);
     *   4. container_write_idmaps(c, child)              (Part I);
     *   5. container_cgroup_enter(c, child)              (Part V);
     *   6. if c->net_enabled, call the PROVIDED container_net_host_setup(c, child)
     *      here (after the cgroup step, before releasing the child): it sets up
     *      the bridge + veth and moves one end into the child's netns;
     *   7. release the child: close c->sync[0], write a byte to c->sync[1];
     *   8. waitpid(child): the child (your init) exits with the command's
     *      status; turn that into a 0-255 return value;
     *   9. if c->net_enabled, call container_net_host_teardown(c), then
     *      container_cleanup(c)                          (Part VI);
     *  10. return the status.
     *
     * As shipped this returns 1 and nothing runs. Start here. */

    /* Keep the "container: " prefix on anything you print here: the test
     * harness reads the container's output and skips lines starting with it. */
    if (!c)
        return 1;

    if (container_cgroup_init(c) < 0)
        return 1;

    if (pipe(c->sync) < 0) {
        fprintf(stderr, "container: pipe(): %s\n", strerror(errno));
        return 1;
    }

    char stack[CONTAINER_STACK_SIZE];
    pid_t child = clone(container_clone_trampoline, stack + CONTAINER_STACK_SIZE,
                        container_namespaces() | SIGCHLD, c);
    if (child < 0) {
        fprintf(stderr, "container: clone(): %s\n", strerror(errno));
        return 1;
    }

    if (container_write_idmaps(c, child) < 0)
        return 1;

    if (container_cgroup_enter(c, child) < 0)
        return 1;

    if (c->net_enabled && container_net_host_setup(c, child) < 0)
        return 1;

    close(c->sync[0]);
    if (write(c->sync[1], "x", 1) != 1) {
        fprintf(stderr, "container: write(sync): %s\n", strerror(errno));
        close(c->sync[1]);
        return 1;
    }
    close(c->sync[1]);

    int st = 0;
    if (waitpid(child, &st, 0) < 0) {
        fprintf(stderr, "container: waitpid(child): %s\n", strerror(errno));
        return 1;
    }

    int status = 0;
    if (WIFEXITED(st))
        status = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        status = 128 + WTERMSIG(st);
    else
        status = 1;

    if (c->net_enabled)
        container_net_host_teardown(c);

    if (container_cleanup(c) < 0)
        return 1;

    return status & 0xff;
}

/* ---- Part VI: teardown ------------------------------------------------- */

int container_cleanup(struct container *c)
{
    if (!c)
        return 0;

    if (c->cg_path[0] == '\0')
        return 0;
    
    if (rmdir(c->cg_path) < 0 && errno != ENOENT) {
        fprintf(stderr, "container: rmdir(%s): %s\n", c->cg_path,
                strerror(errno));
        return -1;
    }

    return 0;
}
