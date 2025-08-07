#include <set>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>

#include <consts.hpp>
#include <base.hpp>
#include <core.hpp>

#include <link.h>

#include "deny.hpp"

using namespace std;

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/vfs.h>

#define VLOGD(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

bool is_rootfs()
{
#define TST_RAMFS_MAGIC    0x858458f6
#define TST_TMPFS_MAGIC    0x01021994
#define TST_OVERLAYFS_MAGIC 0x794c7630
    const char *path= "/";
    struct statfs s;
    statfs(path, &s);

    switch (s.f_type) {
    case TST_TMPFS_MAGIC:
    case TST_RAMFS_MAGIC:
    case TST_OVERLAYFS_MAGIC:
        return true;
    default:
        return false;
    }
}

static bool system_lnk(const char *path){
    char buff[4098];
    ssize_t len = readlink(path, buff, sizeof(buff)-1);
    if (len != -1) {
        return true;
    }
    return false;
}

void recreate_sbin_v2(const char *mirror, bool use_bind_mount) {
    auto dp = xopen_dir(mirror);
    int src = dirfd(dp.get());
    char buf[4096];
    char mbuf[4096];
    for (dirent *entry; (entry = xreaddir(dp.get()));) {
        string sbin_path = "/sbin/"s + entry->d_name;
        struct stat st;
        fstatat(src, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
        sprintf(buf, "%s/%s", mirror, entry->d_name);
        sprintf(mbuf, "%s/%s", get_magisk_tmp(), entry->d_name);
        if (access(mbuf, F_OK) == 0) continue;
        if (S_ISLNK(st.st_mode)) {
            xreadlinkat(src, entry->d_name, buf, sizeof(buf));
            xsymlink(buf, sbin_path.data());
            VLOGD("create", buf, sbin_path.data());
        } else {
            if (use_bind_mount) {
                auto mode = st.st_mode & 0777;
                // Create dummy
                if (S_ISDIR(st.st_mode))
                    xmkdir(sbin_path.data(), mode);
                else
                    close(xopen(sbin_path.data(), O_CREAT | O_WRONLY | O_CLOEXEC, mode));

                bind_mount_(buf, sbin_path.data());
            } else {
                xsymlink(buf, sbin_path.data());
                VLOGD("create", buf, sbin_path.data());
            }
        }
    }
}

int mount_sbin() {
    if (is_rootfs()){
        if (xmount(nullptr, "/", nullptr, MS_REMOUNT, nullptr) != 0) return -1;
        mkdir("/sbin", 0750);
        rm_rf("/root");
        mkdir("/root", 0750);
        clone_attr("/sbin", "/root");
        link_path("/sbin", "/root");
        if (tmpfs_mount("magisk", "/sbin") != 0) return -1;
        setfilecon("/sbin", "u:object_r:rootfs:s0");
        recreate_sbin_v2("/root", false);
        xmount(nullptr, "/", nullptr, MS_REMOUNT | MS_RDONLY, nullptr);
    } else {
        if (tmpfs_mount("magisk", "/sbin") != 0) return -1;
        setfilecon("/sbin", "u:object_r:rootfs:s0");
        xmkdir("/sbin/" INTLROOT, 0755);
        xmkdir("/sbin/" MIRRDIR, 0755);
        xmkdir("/sbin/" MIRRDIR "/system_root", 0755);
        xmount("/", "/sbin/" MIRRDIR "/system_root", nullptr, MS_BIND, nullptr);
        recreate_sbin_v2("/sbin/" MIRRDIR "/system_root/sbin", true);
        umount2("/sbin/" MIRRDIR "/system_root", MNT_DETACH);
    }
    return 0;
}

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("denylist: Unmounted (%s)\n", mountpoint);
}
