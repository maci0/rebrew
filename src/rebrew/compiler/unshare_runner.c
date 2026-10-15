#define _GNU_SOURCE
/* Experimental one-shot Linux runner. Generated OCI profiles only; not a
 * general OCI runtime. */
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/openat2.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child_pid = -1;
static volatile sig_atomic_t interrupted;
static void fail(const char *s) {
  fprintf(stderr, "rebrew-unshare: %s: %s\n", s, strerror(errno));
  exit(125);
}
static void reject(const char *s) {
  fprintf(stderr, "rebrew-unshare: unsupported/invalid %s\n", s);
  exit(125);
}
static json_object *field(json_object *o, const char *k) {
  json_object *v = NULL;
  if (!json_object_object_get_ex(o, k, &v))
    reject(k);
  return v;
}
static const char *string(json_object *v) {
  if (!json_object_is_type(v, json_type_string))
    reject("string");
  const char *s = json_object_get_string(v);
  if (strlen(s) != (size_t)json_object_get_string_len(v))
    reject("embedded NUL");
  return s;
}
static const char *strfield(json_object *o, const char *k) {
  return string(field(o, k));
}
static void keys(json_object *o, const char *allowed) {
  if (!json_object_is_type(o, json_type_object))
    reject("object");
  json_object_object_foreach(o, key, value) {
    (void)value;
    char match[128];
    if (snprintf(match, sizeof(match), "|%s|", key) >= (int)sizeof(match) ||
        !strstr(allowed, match))
      reject(key);
  }
}
static void absolute(const char *p) {
  if (p[0] != '/')
    reject("absolute path");
  char *s = strdup(p), *save = NULL;
  if (!s)
    fail("strdup");
  for (char *t = strtok_r(s, "/", &save); t; t = strtok_r(NULL, "/", &save))
    if (!strcmp(t, ".."))
      reject("parent traversal");
  free(s);
}
static char **strings(json_object *a) {
  if (!json_object_is_type(a, json_type_array) ||
      json_object_array_length(a) > 4096)
    reject("string array");
  size_t n = json_object_array_length(a);
  char **out = calloc(n + 1, sizeof(char *));
  if (!out)
    fail("calloc");
  for (size_t i = 0; i < n; i++)
    out[i] = (char *)string(json_object_array_get_idx(a, i));
  return out;
}
static void write_all(int fd, const void *v, size_t n) {
  const char *p = v;
  while (n) {
    ssize_t k = write(fd, p, n);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      fail("write");
    p += k;
    n -= k;
  }
}
static void write_file(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    fail(path);
  write_all(fd, s, strlen(s));
  if (close(fd))
    fail("close");
}
static int wait_child(pid_t pid) {
  int status;
  while (waitpid(pid, &status, 0) < 0)
    if (errno != EINTR)
      fail("waitpid");
  return interrupted         ? 128 + interrupted
         : WIFEXITED(status) ? WEXITSTATUS(status)
                             : 128 + WTERMSIG(status);
}
static void stop_child(int sig) {
  interrupted = sig;
  if (child_pid > 0)
    kill(child_pid, SIGKILL);
}
static int namespace_flag(const char *s) {
  if (!strcmp(s, "mount"))
    return CLONE_NEWNS;
  if (!strcmp(s, "network"))
    return CLONE_NEWNET;
  if (!strcmp(s, "ipc"))
    return CLONE_NEWIPC;
  if (!strcmp(s, "uts"))
    return CLONE_NEWUTS;
  if (!strcmp(s, "user"))
    return CLONE_NEWUSER;
  if (!strcmp(s, "pid"))
    return CLONE_NEWPID;
  if (!strcmp(s, "cgroup"))
    return CLONE_NEWCGROUP;
  reject("namespace");
  return 0;
}
static json_object *load(const char *path) {
  json_object *cfg = json_object_from_file(path);
  if (!cfg)
    reject("config.json");
  keys(cfg,
       "|ociVersion||process||root||hostname||mounts||linux||annotations|");
  if (strcmp(strfield(cfg, "ociVersion"), "1.0.0"))
    reject("OCI version");
  json_object *p = field(cfg, "process"), *root = field(cfg, "root"),
              *linux_cfg = field(cfg, "linux");
  keys(p, "|terminal||user||args||env||cwd||capabilities||rlimits||"
          "noNewPrivileges|");
  if (json_object_get_boolean(field(p, "terminal")) ||
      !json_object_get_boolean(field(p, "noNewPrivileges")))
    reject("terminal/noNewPrivileges");
  json_object *u = field(p, "user");
  keys(u, "|uid||gid|");
  if (json_object_get_int(field(u, "uid")) != 1000 ||
      json_object_get_int(field(u, "gid")) != 1000)
    reject("process uid/gid (requires 1000)");
  char **argv = strings(field(p, "args"));
  if (!argv[0])
    reject("empty argv");
  absolute(argv[0]);
  free(argv);
  char **env = strings(field(p, "env"));
  for (size_t i = 0; env[i]; i++)
    if (!strchr(env[i], '='))
      reject("environment");
  free(env);
  absolute(strfield(p, "cwd"));
  json_object *caps = field(p, "capabilities");
  keys(caps, "|bounding||effective||inheritable||permitted||ambient|");
  json_object_object_foreach(caps, k, v) {
    (void)k;
    if (!json_object_is_type(v, json_type_array) || json_object_array_length(v))
      reject("nonempty capabilities");
  }
  json_object *limits = field(p, "rlimits");
  if (!json_object_is_type(limits, json_type_array))
    reject("rlimits");
  for (size_t i = 0; i < json_object_array_length(limits); i++) {
    json_object *r = json_object_array_get_idx(limits, i);
    keys(r, "|type||hard||soft|");
    if (strcmp(strfield(r, "type"), "RLIMIT_NOFILE"))
      reject("rlimit type");
    int64_t hard = json_object_get_int64(field(r, "hard")),
            soft = json_object_get_int64(field(r, "soft"));
    if (soft < 1 || hard < soft || hard > 1048576)
      reject("rlimit bounds");
  }
  keys(root, "|path||readonly|");
  if (!json_object_get_boolean(field(root, "readonly")))
    reject("writable rootfs");
  (void)strfield(root, "path");
  keys(linux_cfg,
       "|namespaces||uidMappings||gidMappings||maskedPaths||readonlyPaths|");
  const char *mapping_keys[] = {"uidMappings", "gidMappings"};
  for (int i = 0; i < 2; i++) {
    json_object *a = field(linux_cfg, mapping_keys[i]);
    if (!json_object_is_type(a, json_type_array) ||
        json_object_array_length(a) != 1)
      reject("id mapping count");
    json_object *m = json_object_array_get_idx(a, 0);
    keys(m, "|containerID||hostID||size|");
    if (json_object_get_int64(field(m, "containerID")) != 1000 ||
        json_object_get_int64(field(m, "hostID")) !=
            (i ? getgid() : getuid()) ||
        json_object_get_int64(field(m, "size")) != 1)
      reject("id mapping");
  }
  int flags = 0;
  json_object *ns = field(linux_cfg, "namespaces");
  if (!json_object_is_type(ns, json_type_array))
    reject("namespaces");
  for (size_t i = 0; i < json_object_array_length(ns); i++) {
    json_object *n = json_object_array_get_idx(ns, i);
    keys(n, "|type|");
    int f = namespace_flag(strfield(n, "type"));
    if (flags & f)
      reject("duplicate namespace");
    flags |= f;
  }
  if (flags != (CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS |
                CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWCGROUP))
    reject("required namespaces");
  const char *path_keys[] = {"maskedPaths", "readonlyPaths"};
  for (int i = 0; i < 2; i++) {
    char **paths = strings(field(linux_cfg, path_keys[i]));
    for (size_t j = 0; paths[j]; j++)
      absolute(paths[j]);
    free(paths);
  }
  json_object *mounts = field(cfg, "mounts");
  if (!json_object_is_type(mounts, json_type_array))
    reject("mounts");
  const char *destinations[] = {"/proc",           "/dev",        "/dev/pts",
                                "/dev/shm",        "/work",       "/tmp",
                                "/opt/wineprefix", "/home/rebrew"};
  const char *types[] = {"proc", "tmpfs", "devpts", "tmpfs",
                         "bind", "tmpfs", "bind",   "bind"};
  unsigned seen = 0;
  if (json_object_array_length(mounts) < 8)
    reject("required mount set");
  for (size_t i = 0; i < json_object_array_length(mounts); i++) {
    json_object *m = json_object_array_get_idx(mounts, i);
    keys(m, "|source||destination||type||options|");
    const char *destination = strfield(m, "destination");
    absolute(destination);
    const char *type = strfield(m, "type");
    int index = -1;
    for (int j = 0; j < 8; j++)
      if (!strcmp(destination, destinations[j]))
        index = j;
    if (index < 0) {
      if (strcmp(type, "bind"))
        reject("extra mount must be a readonly bind");
      for (int j = 0; j < 8; j++) {
        size_t n = strlen(destinations[j]), d = strlen(destination);
        if ((!strncmp(destination, destinations[j], n) &&
             (destination[n] == '/' || !destination[n])) ||
            (!strncmp(destinations[j], destination, d) &&
             (destinations[j][d] == '/' || !destinations[j][d])))
          reject("extra mount overlaps runtime mount");
      }
      json_object *options = field(m, "options");
      bool readonly = false;
      for (size_t j = 0; j < json_object_array_length(options); j++)
        if (!strcmp(string(json_object_array_get_idx(options, j)), "ro"))
          readonly = true;
      if (!readonly)
        reject("writable external include mount");
    } else {
      if ((seen & (1u << index)) || strcmp(type, types[index]))
        reject("runtime mount destination/type");
      seen |= 1u << index;
    }
    if ((index == 2 || index == 3) && !(seen & 2u))
      reject("/dev mount must precede its children");
    if (strcmp(type, "proc") && strcmp(type, "tmpfs") &&
        strcmp(type, "devpts") && strcmp(type, "bind"))
      reject("mount type");
    if (!strcmp(type, "bind"))
      absolute(strfield(m, "source"));
    json_object *opts = NULL;
    if (json_object_object_get_ex(m, "options", &opts)) {
      char **s = strings(opts);
      for (size_t j = 0; s[j]; j++) {
        bool flag = !strcmp(s[j], "ro") || !strcmp(s[j], "rw") ||
                    !strcmp(s[j], "nosuid") || !strcmp(s[j], "nodev") ||
                    !strcmp(s[j], "noexec") || !strcmp(s[j], "strictatime");
        bool bind = !strcmp(type, "bind");
        bool specific =
            bind ? (!strcmp(s[j], "bind") || !strcmp(s[j], "rbind"))
                 : (!strncmp(s[j], "mode=", 5) || !strncmp(s[j], "size=", 5) ||
                    !strncmp(s[j], "ptmxmode=", 9) ||
                    !strcmp(s[j], "newinstance"));
        if (!flag && !specific)
          reject("mount option");
      }
      free(s);
    }
  }
  if (seen != 255u)
    reject("missing runtime mount");
  return cfg;
}
static const char *runtime_root;
static int target_fd(int rootfd, const char *path) {
  struct open_how how = {.flags = O_PATH | O_CLOEXEC,
                         .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS};
  return syscall(SYS_openat2, rootfd, path, &how, sizeof(how));
}
static void fd_path(char *out, size_t n, int fd) {
  if (snprintf(out, n, "/proc/self/fd/%d", fd) >= (int)n)
    reject("fd path");
}
static void do_mount(json_object *m, int rootfd) {
  const char *dest = strfield(m, "destination"), *type = strfield(m, "type"),
             *source = strfield(m, "source");
  int fd = target_fd(rootfd, dest);
  if (fd < 0 && errno == ENOENT) {
    char partial[PATH_MAX] = "", *copy = strdup(dest), *save = NULL;
    if (!copy)
      fail("strdup");
    for (char *part = strtok_r(copy, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
      char parent[PATH_MAX];
      snprintf(parent, sizeof(parent), "%s", partial[0] ? partial : "/");
      if (strlen(partial) + strlen(part) + 2 >= sizeof(partial))
        reject("mount target size");
      strcat(partial, "/");
      strcat(partial, part);
      int next = target_fd(rootfd, partial);
      if (next >= 0) {
        close(next);
        continue;
      }
      if (errno != ENOENT)
        fail("mount target resolution");
      int pfd = target_fd(rootfd, parent);
      if (pfd < 0)
        fail("mount target parent");
      if (mkdirat(pfd, part, 0755) && errno != EEXIST)
        fail("mount target mkdir");
      close(pfd);
    }
    free(copy);
    fd = target_fd(rootfd, dest);
  }
  if (fd < 0)
    fail(dest);
  char target[64];
  fd_path(target, sizeof(target), fd);
  unsigned long flags = 0;
  bool bind = false, recursive = false;
  char data[1024] = "";
  json_object *opts = NULL;
  if (json_object_object_get_ex(m, "options", &opts))
    for (size_t j = 0; j < json_object_array_length(opts); j++) {
      const char *o = string(json_object_array_get_idx(opts, j));
      if (!strcmp(o, "ro"))
        flags |= MS_RDONLY;
      else if (!strcmp(o, "rw"))
        flags &= ~MS_RDONLY;
      else if (!strcmp(o, "nosuid"))
        flags |= MS_NOSUID;
      else if (!strcmp(o, "nodev"))
        flags |= MS_NODEV;
      else if (!strcmp(o, "noexec"))
        flags |= MS_NOEXEC;
      else if (!strcmp(o, "strictatime"))
        flags |= MS_STRICTATIME;
      else if (!strcmp(o, "bind"))
        bind = true;
      else if (!strcmp(o, "rbind")) {
        bind = true;
        recursive = true;
      } else if (!strncmp(o, "mode=", 5) || !strncmp(o, "size=", 5) ||
                 !strncmp(o, "ptmxmode=", 9) || !strcmp(o, "newinstance")) {
        if (strlen(data) + strlen(o) + 2 >= sizeof(data))
          reject("mount options size");
        if (data[0])
          strcat(data, ",");
        strcat(data, o);
      } else
        reject("mount option");
    }
  if (!strcmp(type, "bind"))
    bind = true;
  if (bind) {
    if (!strcmp(dest, "/home/rebrew") || !strcmp(dest, "/opt/wineprefix")) {
      char expected[PATH_MAX];
      if (snprintf(expected, sizeof(expected), "%s%s", runtime_root, dest) >=
              (int)sizeof(expected) ||
          strcmp(source, expected))
        reject("runtime state bind source");
      source = target;
    }
    if (mount(source, target, NULL, MS_BIND | (recursive ? MS_REC : 0), NULL))
      fail("bind mount");
    close(fd);
    fd = target_fd(rootfd, dest);
    if (fd < 0)
      fail("reopen bind mount");
    fd_path(target, sizeof(target), fd);
    if (mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | flags, NULL))
      fail("bind remount");
  } else if (mount(source, target, type, flags, data[0] ? data : NULL))
    fail(dest);
  close(fd);
}
static void default_devices(int rootfd) {
  int fd = target_fd(rootfd, "/dev");
  if (fd < 0)
    fail("/dev");
  const char *names[] = {"null", "zero", "full", "random", "urandom", "tty"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    int out = openat(fd, names[i], O_CREAT | O_WRONLY | O_CLOEXEC, 0666);
    if (out < 0)
      fail("device placeholder");
    close(out);
    char src[64], dst[96];
    snprintf(src, sizeof(src), "/dev/%s", names[i]);
    snprintf(dst, sizeof(dst), "/proc/self/fd/%d/%s", fd, names[i]);
    if (mount(src, dst, NULL, MS_BIND, NULL))
      fail("device bind");
  }
  const char *names2[] = {"fd", "stdin", "stdout", "stderr", "ptmx"};
  const char *links[] = {"/proc/self/fd", "/proc/self/fd/0", "/proc/self/fd/1",
                         "/proc/self/fd/2", "pts/ptmx"};
  for (size_t i = 0; i < 5; i++)
    if (symlinkat(links[i], fd, names2[i]) && errno != EEXIST)
      fail("device symlink");
  close(fd);
}
static void paths(json_object *a, int rootfd, bool readonly) {
  for (size_t i = 0; i < json_object_array_length(a); i++) {
    const char *p = string(json_object_array_get_idx(a, i));
    int fd = target_fd(rootfd, p);
    if (fd < 0) {
      if (errno == ENOENT || errno == ENOTDIR)
        continue;
      fail(p);
    }
    struct stat st;
    if (fstat(fd, &st))
      fail("fstat");
    char dst[64];
    fd_path(dst, sizeof(dst), fd);
    if (readonly) {
      if (mount(dst, dst, NULL, MS_BIND | MS_REC, NULL))
        fail("readonly bind");
      close(fd);
      fd = target_fd(rootfd, p);
      if (fd < 0)
        fail("reopen readonly path");
      fd_path(dst, sizeof(dst), fd);
      if (mount(NULL, dst, NULL,
                MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV |
                    MS_NOEXEC,
                NULL))
        fail("readonly path");
    } else if (S_ISDIR(st.st_mode)) {
      if (mount("tmpfs", dst, "tmpfs",
                MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                "size=4096,mode=000"))
        fail("mask directory");
    } else if (mount("/dev/null", dst, NULL, MS_BIND, NULL))
      fail("mask file");
    close(fd);
  }
}
static void apply_process(json_object *cfg) {
  json_object *p = field(cfg, "process"), *limits = field(p, "rlimits");
  for (size_t i = 0; i < json_object_array_length(limits); i++) {
    json_object *r = json_object_array_get_idx(limits, i);
    struct rlimit l = {(rlim_t)json_object_get_int64(field(r, "soft")),
                       (rlim_t)json_object_get_int64(field(r, "hard"))};
    if (setrlimit(RLIMIT_NOFILE, &l))
      fail("setrlimit");
  }
  if (chdir(strfield(p, "cwd")))
    fail("process cwd");
  if (getuid() != 1000 || getgid() != 1000)
    reject("effective user mapping");
  for (int c = 0; c <= CAP_LAST_CAP; c++)
    if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) && errno != EINVAL)
      fail("drop capability bounding set");
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
    fail("clear ambient capabilities");
  struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3,
                                       .pid = 0};
  struct __user_cap_data_struct data[2] = {{0}, {0}};
  if (syscall(SYS_capset, &h, data))
    fail("capset");
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    fail("no_new_privs");
}
static void exec_process(json_object *cfg) {
  char **argv = strings(field(field(cfg, "process"), "args")),
       **env = strings(field(field(cfg, "process"), "env"));
  if (syscall(SYS_close_range, 3u, ~0u, 0))
    fail("close_range");
  execve(argv[0], argv, env);
  fail("execve");
}
struct child_context {
  json_object *cfg;
  const char *rootfs, *lower, *upper, *overlay_work;
  int go_read, go_write, ready_read, ready_write, parentfd;
};
static int init_child(void *opaque) {
  struct child_context *c = opaque;
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0))
    fail("parent death signal");
  struct pollfd pp = {.fd = c->parentfd, .events = POLLIN};
  if (poll(&pp, 1, 0) > 0)
    _exit(125);
  close(c->go_write);
  close(c->ready_read);
  char go;
  if (read(c->go_read, &go, 1) != 1)
    _exit(125);
  close(c->go_read);
  close(c->parentfd);
  if (unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS |
              CLONE_NEWCGROUP))
    fail("unshare");
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
    fail("private mounts");
  if (sethostname(strfield(c->cfg, "hostname"),
                  strlen(strfield(c->cfg, "hostname"))))
    fail("hostname");
  char overlay[PATH_MAX * 3 + 128];
  if (snprintf(overlay, sizeof(overlay),
               "lowerdir=%s,upperdir=%s,workdir=%s,userxattr", c->lower,
               c->upper, c->overlay_work) >= (int)sizeof(overlay))
    reject("overlay paths size");
  if (mount("overlay", c->rootfs, "overlay", MS_NODEV | MS_NOSUID, overlay))
    fail("rootless overlay mount (requires user-namespace overlayfs)");
  runtime_root = c->rootfs;
  int rootfd = open(c->rootfs, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (rootfd < 0)
    fail("rootfs open");
  json_object *mounts = field(c->cfg, "mounts");
  for (size_t i = 0; i < json_object_array_length(mounts); i++)
    do_mount(json_object_array_get_idx(mounts, i), rootfd);
  default_devices(rootfd);
  json_object *l = field(c->cfg, "linux");
  paths(field(l, "maskedPaths"), rootfd, false);
  paths(field(l, "readonlyPaths"), rootfd, true);
  if (mount(NULL, c->rootfs, NULL,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
    fail("readonly rootfs");
  if (fchdir(rootfd) || syscall(SYS_pivot_root, ".", ".") ||
      umount2(".", MNT_DETACH) || chdir("/"))
    fail("pivot_root");
  close(rootfd);
  apply_process(c->cfg);
  write_all(c->ready_write, "R", 1);
  close(c->ready_write);
  exec_process(c->cfg);
  return 125;
}
static int run(json_object *cfg, const char *config_path) {
  char cfg_real[PATH_MAX], lower[PATH_MAX], rootfs[PATH_MAX], upper[PATH_MAX],
      overlay_work[PATH_MAX], candidate[PATH_MAX];
  if (!realpath(config_path, cfg_real))
    fail("config path");
  char *slash = strrchr(cfg_real, '/');
  *slash = 0;
  const char *root = strfield(field(cfg, "root"), "path");
  if (root[0] == '/')
    snprintf(candidate, sizeof(candidate), "%s", root);
  else if (snprintf(candidate, sizeof(candidate), "%s/%s", cfg_real, root) >=
           (int)sizeof(candidate))
    reject("root path size");
  if (!realpath(candidate, lower))
    fail("rootfs path");
  const char *names[] = {"rootfs", "upper", "overlay-work"};
  char *paths_out[] = {rootfs, upper, overlay_work};
  for (int i = 0; i < 3; i++) {
    if (snprintf(candidate, sizeof(candidate), "%s/%s", cfg_real, names[i]) >=
            (int)sizeof(candidate) ||
        !realpath(candidate, paths_out[i]))
      fail("runtime directory");
  }
  const char *values[] = {lower, rootfs, upper, overlay_work};
  for (int i = 0; i < 4; i++)
    if (strchr(values[i], ',') || strchr(values[i], ':') ||
        strchr(values[i], '\\') || strchr(values[i], '\n') ||
        strchr(values[i], '\r'))
      reject("overlay path contains unsupported separator");
  int go[2], ready[2];
  if (pipe2(go, O_CLOEXEC) || pipe2(ready, O_CLOEXEC))
    fail("pipe2");
  int parentfd = syscall(SYS_pidfd_open, getpid(), 0);
  if (parentfd < 0)
    fail("pidfd_open");
  struct child_context context = {cfg,          rootfs,  lower, upper,
                                  overlay_work, go[0],   go[1], ready[0],
                                  ready[1],     parentfd};
  void *stack = malloc(1024 * 1024);
  if (!stack)
    fail("stack allocation");
  child_pid = clone(init_child, (char *)stack + 1024 * 1024,
                    CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, &context);
  if (child_pid < 0)
    fail("clone user/pid");
  close(go[0]);
  close(ready[1]);
  close(parentfd);
  signal(SIGTERM, stop_child);
  signal(SIGINT, stop_child);
  signal(SIGPIPE, SIG_IGN);
  const char *maps[] = {"uid_map", "gid_map"};
  char path[128], value[128];
  snprintf(path, sizeof(path), "/proc/%d/setgroups", child_pid);
  write_file(path, "deny");
  for (int i = 0; i < 2; i++) {
    snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, maps[i]);
    snprintf(value, sizeof(value), "1000 %u 1\n", i ? getgid() : getuid());
    write_file(path, value);
  }
  write_all(go[1], "G", 1);
  close(go[1]);
  char byte;
  ssize_t n = read(ready[0], &byte, 1);
  close(ready[0]);
  (void)n;
  (void)byte;
  int result = wait_child(child_pid);
  free(stack);
  return result;
}
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: rebrew-unshare CONFIG\n");
    return 125;
  }
  /* A killed caller must not leave this supervisor or its PID namespace alive.
   */
  pid_t parent = getppid();
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0))
    fail("supervisor parent death signal");
  if (parent == 1 || getppid() != parent)
    return 125;
  json_object *cfg = load(argv[1]);
  return run(cfg, argv[1]);
}
