#ifndef _UAPI_LINUX_FSCRYPT_H
#define _UAPI_LINUX_FSCRYPT_H

// Definitions for FS_IOC_ADD_ENCRYPTION_KEY and FS_IOC_REMOVE_ENCRYPTION_KEY

// TODO: switch to <linux/fscrypt.h> once it's in Bionic

#ifndef FS_IOC_ADD_ENCRYPTION_KEY

#include <linux/types.h>

#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
#define FSCRYPT_KEY_IDENTIFIER_SIZE 16

#define FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR 1
#define FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER 2

struct fscrypt_key_specifier {
    __u32 type;
    __u32 __reserved;
    union {
        __u8 __reserved[32];
        __u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
        __u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
    } u;
};

struct fscrypt_add_key_arg {
    struct fscrypt_key_specifier key_spec;
    __u32 raw_size;
    __u32 __reserved[9];
    __u8 raw[];
};

struct fscrypt_remove_key_arg {
    struct fscrypt_key_specifier key_spec;
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY 0x00000001
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS 0x00000002
    __u32 removal_status_flags;
    __u32 __reserved[5];
};

#define FS_IOC_ADD_ENCRYPTION_KEY _IOWR('f', 23, struct fscrypt_add_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY _IOWR('f', 24, struct fscrypt_remove_key_arg)

#endif /* FS_IOC_ADD_ENCRYPTION_KEY */

#endif /* _UAPI_LINUX_FSCRYPT_H */
