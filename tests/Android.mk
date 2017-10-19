# Build the unit tests.
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_C_INCLUDES := \
    system/core/fs_mgr/include

LOCAL_STATIC_LIBRARIES := libselinux libvold liblog libcrypto

LOCAL_SRC_FILES := VolumeManager_test.cpp
LOCAL_MODULE := vold_tests
LOCAL_MODULE_TAGS := eng tests

LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

# LOCAL_C_INCLUDES := \
    system/core/fs_mgr/include

LOCAL_STATIC_LIBRARIES := libselinux libvold liblog libcrypto
LOCAL_SHARED_LIBRARIES := \
    libutils \
    libbase \
    libhardware \
    libhardware_legacy \
    libhwbinder \
    libhidlbase \
    libkeystore_binder \
    android.hardware.keymaster@3.0

LOCAL_SRC_FILES := CryptfsScryptHidlizationEquivalence_test.cpp
LOCAL_MODULE := vold_cryptfs_scrypt_hidlization_equivalence_test
LOCAL_MODULE_TAGS := eng tests

include $(BUILD_NATIVE_TEST)
