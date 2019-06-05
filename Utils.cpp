/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Utils.h"

#include "Process.h"
#include "sehandle.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/fs.h>
#include <logwrap/logwrap.h>
#include <private/android_filesystem_config.h>

#include <mutex>
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/statvfs.h>

#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW    0x00000008  /* Don't follow symlink on umount */
#endif

using android::base::ReadFileToString;
using android::base::StringPrintf;

namespace android {
namespace vold {

security_context_t sBlkidContext = nullptr;
security_context_t sBlkidUntrustedContext = nullptr;
security_context_t sFsckContext = nullptr;
security_context_t sFsckUntrustedContext = nullptr;

bool sSleepOnUnmount = true;

static const char* kBlkidPath = "/system/bin/blkid";
static const char* kKeyPath = "/data/misc/vold";

static const char* kProcFilesystems = "/proc/filesystems";

// Lock used to protect process-level SELinux changes from racing with each
// other between multiple threads.
static std::mutex kSecurityLock;

status_t CreateDeviceNode(const std::string& path, dev_t dev) {
    std::lock_guard<std::mutex> lock(kSecurityLock);
    const char* cpath = path.c_str();
    status_t res = 0;

    char* secontext = nullptr;
    if (sehandle) {
        if (!selabel_lookup(sehandle, &secontext, cpath, S_IFBLK)) {
            setfscreatecon(secontext);
        }
    }

    mode_t mode = 0660 | S_IFBLK;
    if (mknod(cpath, mode, dev) < 0) {
        if (errno != EEXIST) {
            PLOG(ERROR) << "Failed to create device node for " << major(dev)
                    << ":" << minor(dev) << " at " << path;
            res = -errno;
        }
    }

    if (secontext) {
        setfscreatecon(nullptr);
        freecon(secontext);
    }

    return res;
}

status_t DestroyDeviceNode(const std::string& path) {
    const char* cpath = path.c_str();
    if (TEMP_FAILURE_RETRY(unlink(cpath))) {
        return -errno;
    } else {
        return OK;
    }
}

status_t PrepareDir(const std::string& path, mode_t mode, uid_t uid, gid_t gid) {
    std::lock_guard<std::mutex> lock(kSecurityLock);
    const char* cpath = path.c_str();

    char* secontext = nullptr;
    if (sehandle) {
        if (!selabel_lookup(sehandle, &secontext, cpath, S_IFDIR)) {
            setfscreatecon(secontext);
        }
    }

    int res = fs_prepare_dir(cpath, mode, uid, gid);

    if (secontext) {
        setfscreatecon(nullptr);
        freecon(secontext);
    }

    if (res == 0) {
        return OK;
    } else {
        return -errno;
    }
}

status_t ForceUnmount(const std::string& path) {
    const char* cpath = path.c_str();
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    // Apps might still be handling eject request, so wait before
    // we start sending signals
    if (sSleepOnUnmount) sleep(5);

    KillProcessesWithOpenFiles(path, SIGINT);
    if (sSleepOnUnmount) sleep(5);
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }

    KillProcessesWithOpenFiles(path, SIGTERM);
    if (sSleepOnUnmount) sleep(5);
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }

    KillProcessesWithOpenFiles(path, SIGKILL);
    if (sSleepOnUnmount) sleep(5);
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }

    return -errno;
}

status_t KillProcessesUsingPath(const std::string& path) {
    if (KillProcessesWithOpenFiles(path, SIGINT) == 0) {
        return OK;
    }
    if (sSleepOnUnmount) sleep(5);

    if (KillProcessesWithOpenFiles(path, SIGTERM) == 0) {
        return OK;
    }
    if (sSleepOnUnmount) sleep(5);

    if (KillProcessesWithOpenFiles(path, SIGKILL) == 0) {
        return OK;
    }
    if (sSleepOnUnmount) sleep(5);

    // Send SIGKILL a second time to determine if we've
    // actually killed everyone with open files
    if (KillProcessesWithOpenFiles(path, SIGKILL) == 0) {
        return OK;
    }
    PLOG(ERROR) << "Failed to kill processes using " << path;
    return -EBUSY;
}

status_t BindMount(const std::string& source, const std::string& target) {
    if (::mount(source.c_str(), target.c_str(), "", MS_BIND, NULL)) {
        PLOG(ERROR) << "Failed to bind mount " << source << " to " << target;
        return -errno;
    }
    return OK;
}

bool FindValue(const std::string& raw, const std::string& key, std::string* value) {
    auto qual = key + "=\"";
    auto start = raw.find(qual);
    if (start > 0 && raw[start - 1] != ' ') {
        start = raw.find(qual, start + 1);
    }

    if (start == std::string::npos) return false;
    start += qual.length();

    auto end = raw.find("\"", start);
    if (end == std::string::npos) return false;

    *value = raw.substr(start, end - start);
    return true;
}

static status_t readMetadata(const std::string& path, std::string* fsType,
        std::string* fsUuid, std::string* fsLabel, bool untrusted) {
    fsType->clear();
    fsUuid->clear();
    fsLabel->clear();

    std::vector<std::string> cmd;
    cmd.push_back(kBlkidPath);
    cmd.push_back("-c");
    cmd.push_back("/dev/null");
    cmd.push_back("-s");
    cmd.push_back("TYPE");
    cmd.push_back("-s");
    cmd.push_back("UUID");
    cmd.push_back("-s");
    cmd.push_back("LABEL");
    cmd.push_back(path);

    std::vector<std::string> output;
    status_t res = ForkExecvp(cmd, output, untrusted ? sBlkidUntrustedContext : sBlkidContext);
    if (res != OK) {
        LOG(WARNING) << "blkid failed to identify " << path;
        return res;
    }

    for (const auto& line : output) {
        // Extract values from blkid output, if defined
        FindValue(line, "TYPE", fsType);
        FindValue(line, "UUID", fsUuid);
        FindValue(line, "LABEL", fsLabel);
    }

    return OK;
}

status_t ReadMetadata(const std::string& path, std::string* fsType,
        std::string* fsUuid, std::string* fsLabel) {
    return readMetadata(path, fsType, fsUuid, fsLabel, false);
}

status_t ReadMetadataUntrusted(const std::string& path, std::string* fsType,
        std::string* fsUuid, std::string* fsLabel) {
    return readMetadata(path, fsType, fsUuid, fsLabel, true);
}

status_t ForkExecvp(const std::vector<std::string>& args) {
    return ForkExecvp(args, nullptr);
}

status_t ForkExecvp(const std::vector<std::string>& args, security_context_t context) {
    std::lock_guard<std::mutex> lock(kSecurityLock);
    size_t argc = args.size();
    char** argv = (char**) calloc(argc, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }

    if (context) {
        if (setexeccon(context)) {
            LOG(ERROR) << "Failed to setexeccon";
            abort();
        }
    }
    status_t res = android_fork_execvp(argc, argv, NULL, false, true);
    if (context) {
        if (setexeccon(nullptr)) {
            LOG(ERROR) << "Failed to setexeccon";
            abort();
        }
    }

    free(argv);
    return res;
}

status_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output) {
    return ForkExecvp(args, output, nullptr);
}

status_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output, security_context_t context) {
    std::lock_guard<std::mutex> lock(kSecurityLock);
    std::string cmd;
    for (size_t i = 0; i < args.size(); i++) {
        cmd += args[i] + " ";
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }
    output.clear();

    if (context) {
        if (setexeccon(context)) {
            LOG(ERROR) << "Failed to setexeccon";
            abort();
        }
    }
    FILE* fp = popen(cmd.c_str(), "r"); // NOLINT
    if (context) {
        if (setexeccon(nullptr)) {
            LOG(ERROR) << "Failed to setexeccon";
            abort();
        }
    }

    if (!fp) {
        PLOG(ERROR) << "Failed to popen " << cmd;
        return -errno;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        LOG(VERBOSE) << line;
        output.push_back(std::string(line));
    }
    if (pclose(fp) != 0) {
        PLOG(ERROR) << "Failed to pclose " << cmd;
        return -errno;
    }

    return OK;
}

pid_t ForkExecvpAsync(const std::vector<std::string>& args) {
    size_t argc = args.size();
    char** argv = (char**) calloc(argc + 1, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        if (execvp(argv[0], argv)) {
            PLOG(ERROR) << "Failed to exec";
        }

        _exit(1);
    }

    if (pid == -1) {
        PLOG(ERROR) << "Failed to exec";
    }

    free(argv);
    return pid;
}

status_t ReadRandomBytes(size_t bytes, std::string& out) {
    out.resize(bytes);
    return ReadRandomBytes(bytes, &out[0]);
}

status_t ReadRandomBytes(size_t bytes, char* buf) {
    int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd == -1) {
        return -errno;
    }

    size_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], bytes))) > 0) {
        bytes -= n;
        buf += n;
    }
    close(fd);

    if (bytes == 0) {
        return OK;
    } else {
        return -EIO;
    }
}

status_t GenerateRandomUuid(std::string& out) {
    status_t res = ReadRandomBytes(16, out);
    if (res == OK) {
        out[6] &= 0x0f;  /* clear version        */
        out[6] |= 0x40;  /* set to version 4     */
        out[8] &= 0x3f;  /* clear variant        */
        out[8] |= 0x80;  /* set to IETF variant  */
    }
    return res;
}

status_t HexToStr(const std::string& hex, std::string& str) {
    str.clear();
    bool even = true;
    char cur = 0;
    for (size_t i = 0; i < hex.size(); i++) {
        int val = 0;
        switch (hex[i]) {
        case ' ': case '-': case ':': continue;
        case 'f': case 'F': val = 15; break;
        case 'e': case 'E': val = 14; break;
        case 'd': case 'D': val = 13; break;
        case 'c': case 'C': val = 12; break;
        case 'b': case 'B': val = 11; break;
        case 'a': case 'A': val = 10; break;
        case '9': val = 9; break;
        case '8': val = 8; break;
        case '7': val = 7; break;
        case '6': val = 6; break;
        case '5': val = 5; break;
        case '4': val = 4; break;
        case '3': val = 3; break;
        case '2': val = 2; break;
        case '1': val = 1; break;
        case '0': val = 0; break;
        default: return -EINVAL;
        }

        if (even) {
            cur = val << 4;
        } else {
            cur += val;
            str.push_back(cur);
            cur = 0;
        }
        even = !even;
    }
    return even ? OK : -EINVAL;
}

static const char* kLookup = "0123456789abcdef";

status_t StrToHex(const std::string& str, std::string& hex) {
    hex.clear();
    for (size_t i = 0; i < str.size(); i++) {
        hex.push_back(kLookup[(str[i] & 0xF0) >> 4]);
        hex.push_back(kLookup[str[i] & 0x0F]);
    }
    return OK;
}

status_t StrToHex(const KeyBuffer& str, KeyBuffer& hex) {
    hex.clear();
    for (size_t i = 0; i < str.size(); i++) {
        hex.push_back(kLookup[(str.data()[i] & 0xF0) >> 4]);
        hex.push_back(kLookup[str.data()[i] & 0x0F]);
    }
    return OK;
}

status_t NormalizeHex(const std::string& in, std::string& out) {
    std::string tmp;
    if (HexToStr(in, tmp)) {
        return -EINVAL;
    }
    return StrToHex(tmp, out);
}

uint64_t GetFreeBytes(const std::string& path) {
    struct statvfs sb;
    if (statvfs(path.c_str(), &sb) == 0) {
        return (uint64_t) sb.f_bavail * sb.f_frsize;
    } else {
        return -1;
    }
}

// TODO: borrowed from frameworks/native/libs/diskusage/ which should
// eventually be migrated into system/
static int64_t stat_size(struct stat *s) {
    int64_t blksize = s->st_blksize;
    // count actual blocks used instead of nominal file size
    int64_t size = s->st_blocks * 512;

    if (blksize) {
        /* round up to filesystem block size */
        size = (size + blksize - 1) & (~(blksize - 1));
    }

    return size;
}

// TODO: borrowed from frameworks/native/libs/diskusage/ which should
// eventually be migrated into system/
int64_t calculate_dir_size(int dfd) {
    int64_t size = 0;
    struct stat s;
    DIR *d;
    struct dirent *de;

    d = fdopendir(dfd);
    if (d == NULL) {
        close(dfd);
        return 0;
    }

    while ((de = readdir(d))) {
        const char *name = de->d_name;
        if (fstatat(dfd, name, &s, AT_SYMLINK_NOFOLLOW) == 0) {
            size += stat_size(&s);
        }
        if (de->d_type == DT_DIR) {
            int subfd;

            /* always skip "." and ".." */
            if (name[0] == '.') {
                if (name[1] == 0)
                    continue;
                if ((name[1] == '.') && (name[2] == 0))
                    continue;
            }

            subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (subfd >= 0) {
                size += calculate_dir_size(subfd);
            }
        }
    }
    closedir(d);
    return size;
}

uint64_t GetTreeBytes(const std::string& path) {
    int dirfd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        PLOG(WARNING) << "Failed to open " << path;
        return -1;
    } else {
        uint64_t res = calculate_dir_size(dirfd);
        close(dirfd);
        return res;
    }
}

bool IsFilesystemSupported(const std::string& fsType) {
    std::string supported;
    if (!ReadFileToString(kProcFilesystems, &supported)) {
        PLOG(ERROR) << "Failed to read supported filesystems";
        return false;
    }
    return supported.find(fsType + "\n") != std::string::npos;
}

status_t WipeBlockDevice(const std::string& path) {
    status_t res = -1;
    const char* c_path = path.c_str();
    unsigned long nr_sec = 0;
    unsigned long long range[2];

    int fd = TEMP_FAILURE_RETRY(open(c_path, O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << path;
        goto done;
    }

    if ((ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
        PLOG(ERROR) << "Failed to determine size of " << path;
        goto done;
    }

    range[0] = 0;
    range[1] = (unsigned long long) nr_sec * 512;

    LOG(INFO) << "About to discard " << range[1] << " on " << path;
    if (ioctl(fd, BLKDISCARD, &range) == 0) {
        LOG(INFO) << "Discard success on " << path;
        res = 0;
    } else {
        PLOG(ERROR) << "Discard failure on " << path;
    }

done:
    close(fd);
    return res;
}

static bool isValidFilename(const std::string& name) {
    if (name.empty() || (name == ".") || (name == "..")
            || (name.find('/') != std::string::npos)) {
        return false;
    } else {
        return true;
    }
}

std::string BuildKeyPath(const std::string& partGuid) {
    return StringPrintf("%s/expand_%s.key", kKeyPath, partGuid.c_str());
}

std::string BuildDataSystemLegacyPath(userid_t userId) {
    return StringPrintf("%s/system/users/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataSystemCePath(userid_t userId) {
    return StringPrintf("%s/system_ce/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataSystemDePath(userid_t userId) {
    return StringPrintf("%s/system_de/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataMiscLegacyPath(userid_t userId) {
    return StringPrintf("%s/misc/user/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataMiscCePath(userid_t userId) {
    return StringPrintf("%s/misc_ce/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataMiscDePath(userid_t userId) {
    return StringPrintf("%s/misc_de/%u", BuildDataPath("").c_str(), userId);
}

// Keep in sync with installd (frameworks/native/cmds/installd/utils.h)
std::string BuildDataProfilesDePath(userid_t userId) {
    return StringPrintf("%s/misc/profiles/cur/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataVendorCePath(userid_t userId) {
    return StringPrintf("%s/vendor_ce/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataVendorDePath(userid_t userId) {
    return StringPrintf("%s/vendor_de/%u", BuildDataPath("").c_str(), userId);
}

std::string BuildDataPath(const std::string& volumeUuid) {
    // TODO: unify with installd path generation logic
    if (volumeUuid.empty()) {
        return "/data";
    } else {
        CHECK(isValidFilename(volumeUuid));
        return StringPrintf("/mnt/expand/%s", volumeUuid.c_str());
    }
}

std::string BuildDataMediaCePath(const std::string& volumeUuid, userid_t userId) {
    // TODO: unify with installd path generation logic
    std::string data(BuildDataPath(volumeUuid));
    return StringPrintf("%s/media/%u", data.c_str(), userId);
}

std::string BuildDataUserCePath(const std::string& volumeUuid, userid_t userId) {
    // TODO: unify with installd path generation logic
    std::string data(BuildDataPath(volumeUuid));
    if (volumeUuid.empty() && userId == 0) {
        std::string legacy = StringPrintf("%s/data", data.c_str());
        struct stat sb;
        if (lstat(legacy.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)) {
            /* /data/data is dir, return /data/data for legacy system */
            return legacy;
        }
    }
    return StringPrintf("%s/user/%u", data.c_str(), userId);
}

std::string BuildDataUserDePath(const std::string& volumeUuid, userid_t userId) {
    // TODO: unify with installd path generation logic
    std::string data(BuildDataPath(volumeUuid));
    return StringPrintf("%s/user_de/%u", data.c_str(), userId);
}

dev_t GetDevice(const std::string& path) {
    struct stat sb;
    if (stat(path.c_str(), &sb)) {
        PLOG(WARNING) << "Failed to stat " << path;
        return 0;
    } else {
        return sb.st_dev;
    }
}

status_t RestoreconRecursive(const std::string& path) {
    LOG(VERBOSE) << "Starting restorecon of " << path;

    static constexpr const char* kRestoreconString = "selinux.restorecon_recursive";

    android::base::SetProperty(kRestoreconString, "");
    android::base::SetProperty(kRestoreconString, path);

    android::base::WaitForProperty(kRestoreconString, path);

    LOG(VERBOSE) << "Finished restorecon of " << path;
    return OK;
}

bool Readlinkat(int dirfd, const std::string& path, std::string* result) {
    // Shamelessly borrowed from android::base::Readlink()
    result->clear();

    // Most Linux file systems (ext2 and ext4, say) limit symbolic links to
    // 4095 bytes. Since we'll copy out into the string anyway, it doesn't
    // waste memory to just start there. We add 1 so that we can recognize
    // whether it actually fit (rather than being truncated to 4095).
    std::vector<char> buf(4095 + 1);
    while (true) {
        ssize_t size = readlinkat(dirfd, path.c_str(), &buf[0], buf.size());
        // Unrecoverable error?
        if (size == -1)
            return false;
        // It fit! (If size == buf.size(), it may have been truncated.)
        if (static_cast<size_t>(size) < buf.size()) {
            result->assign(&buf[0], size);
            return true;
        }
        // Double our buffer and try again.
        buf.resize(buf.size() * 2);
    }
}

bool IsRunningInEmulator() {
    return android::base::GetBoolProperty("ro.kernel.qemu", false);
}

bool FsyncDirectory(const std::string& dirname) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(dirname.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << dirname;
        return false;
    }
    if (fsync(fd) == -1) {
        if (errno == EROFS || errno == EINVAL) {
            PLOG(WARNING) << "Skip fsync " << dirname
                          << " on a file system does not support synchronization";
        } else {
            PLOG(ERROR) << "Failed to fsync " << dirname;
            return false;
        }
    }
    return true;
}

}  // namespace vold
}  // namespace android
