LOCAL_PATH:= $(call my-dir)

common_src_files := \
	VolumeManager.cpp \
	NetlinkManager.cpp \
	NetlinkHandler.cpp \
	Process.cpp \
	fs/Ext4.cpp \
	fs/F2fs.cpp \
	fs/Vfat.cpp \
	Loop.cpp \
	Devmapper.cpp \
	CheckBattery.cpp \
	Ext4Crypt.cpp \
	VoldUtil.cpp \
	cryptfs.cpp \
	model/Disk.cpp \
	model/VolumeBase.cpp \
	model/PublicVolume.cpp \
	model/PrivateVolume.cpp \
	model/EmulatedVolume.cpp \
	model/ObbVolume.cpp \
	Utils.cpp \
	MoveTask.cpp \
	BenchmarkTask.cpp \
	TrimTask.cpp \
	KeyBuffer.cpp \
	Keymaster.cpp \
	KeyStorage.cpp \
	KeyUtil.cpp \
	ScryptParameters.cpp \
	secontext.cpp \
	EncryptInplace.cpp \
	MetadataCrypt.cpp \
	VoldNativeService.cpp \

common_aidl_files := \
	binder/android/os/IVold.aidl \
	binder/android/os/IVoldListener.aidl \
	binder/android/os/IVoldTaskListener.aidl \

common_aidl_includes := \
	$(LOCAL_PATH)/binder \
	frameworks/native/aidl/binder \

common_c_includes := \
	system/extras/f2fs_utils \
	external/scrypt/lib/crypto \
	external/f2fs-tools/include \
	frameworks/native/include \
	system/security/keystore \

common_shared_libraries := \
	libsysutils \
	libbinder \
	libcutils \
	libkeyutils \
	liblog \
	libdiskconfig \
	libhardware_legacy \
	liblogwrap \
	libext4_utils \
	libf2fs_sparseblock \
	libcrypto_utils \
	libcrypto \
	libselinux \
	libutils \
	libhardware \
	libbase \
	libhwbinder \
	libhidlbase \
	android.hardware.keymaster@3.0 \
	libkeystore_binder

common_static_libraries := \
	libbootloader_message \
	libfs_mgr \
	libfec \
	libfec_rs \
	libsquashfs_utils \
	libscrypt_static \
	libbatteryservice \
	libavb \

# TODO: include "cert-err58-cpp" once 36656327 is fixed
common_local_tidy_enabled := true
common_local_tidy_flags := -warnings-as-errors=clang-analyzer-security*,cert-*
common_local_tidy_checks := -*,clang-analyzer-security*,cert-*,-cert-err58-cpp

vold_conlyflags := -std=c11
vold_cflags := -Werror -Wall -Wno-missing-field-initializers -Wno-unused-variable -Wno-unused-parameter

required_modules :=
ifeq ($(TARGET_USERIMAGES_USE_EXT4), true)
  required_modules += mke2fs
endif

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libvold
LOCAL_CLANG := true
LOCAL_TIDY := $(common_local_tidy_enabled)
LOCAL_TIDY_FLAGS := $(common_local_tidy_flags)
LOCAL_TIDY_CHECKS := $(common_local_tidy_checks)
LOCAL_SRC_FILES := $(common_src_files) $(common_aidl_files)
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_MODULE_TAGS := eng tests
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)
LOCAL_REQUIRED_MODULES := $(required_modules)

LOCAL_AIDL_INCLUDES := $(common_aidl_includes)

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := vold
LOCAL_CLANG := true
LOCAL_TIDY := $(common_local_tidy_enabled)
LOCAL_TIDY_FLAGS := $(common_local_tidy_flags)
LOCAL_TIDY_CHECKS := $(common_local_tidy_checks)
LOCAL_SRC_FILES := \
	main.cpp \
	$(common_src_files) \
	$(common_aidl_files) \

LOCAL_INIT_RC := vold.rc

LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_REQUIRED_MODULES := $(required_modules)

LOCAL_AIDL_INCLUDES := $(common_aidl_includes)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
LOCAL_TIDY := $(common_local_tidy_enabled)
LOCAL_TIDY_FLAGS := $(common_local_tidy_flags)
LOCAL_TIDY_CHECKS := $(common_local_tidy_checks)

LOCAL_SRC_FILES := \
	vdc.cpp \
	$(common_aidl_files) \

LOCAL_MODULE := vdc
LOCAL_SHARED_LIBRARIES := libbase libbinder libcutils libutils
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)
LOCAL_INIT_RC := vdc.rc

LOCAL_AIDL_INCLUDES := $(common_aidl_includes)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
LOCAL_TIDY := $(common_local_tidy_enabled)
LOCAL_TIDY_FLAGS := $(common_local_tidy_flags)
LOCAL_TIDY_CHECKS := $(common_local_tidy_checks)
LOCAL_SRC_FILES:= \
    FileDeviceUtils.cpp \
    secdiscard.cpp \

LOCAL_MODULE:= secdiscard
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

include $(BUILD_EXECUTABLE)

include $(LOCAL_PATH)/tests/Android.mk
