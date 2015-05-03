LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(TARGET_ARCH),x86)
LOCAL_SRC_FILES:= \
    codegen.cpp
else
LOCAL_SRC_FILES:= \
    codegen.cpp.arm
endif

LOCAL_SHARED_LIBRARIES := \
	libcutils \
    libpixelflinger

LOCAL_C_INCLUDES := \
	system/core/libpixelflinger

ifeq ($(TARGET_ARCH),x86)
LOCAL_C_INCLUDES += \
    $(TARGET_OUT_HEADERS)/libenc
endif

LOCAL_MODULE:= test-opengl-codegen

LOCAL_MODULE_TAGS := tests

include $(BUILD_NATIVE_TEST)
