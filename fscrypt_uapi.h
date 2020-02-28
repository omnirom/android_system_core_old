#ifndef _UAPI_LINUX_FSCRYPT_VOLD_H
#define _UAPI_LINUX_FSCRYPT_VOLD_H

#include <linux/fscrypt.h>
#include <linux/types.h>

#define FSCRYPT_ADD_KEY_FLAG_WRAPPED 0x01

struct sys_fscrypt_add_key_arg {
    struct fscrypt_key_specifier key_spec;
    __u32 raw_size;
    __u32 key_id;
    __u32 __reserved[7];
    __u32 flags;
    __u8 raw[];
};

struct sys_fscrypt_provisioning_key_payload {
    __u32 type;
    __u32 __reserved;
    __u8 raw[];
};

#define fscrypt_add_key_arg sys_fscrypt_add_key_arg
#define fscrypt_provisioning_key_payload sys_fscrypt_provisioning_key_payload

#endif  //_UAPI_LINUX_FSCRYPT_VOLD_H
