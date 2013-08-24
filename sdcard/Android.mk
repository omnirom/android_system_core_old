LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := sdcard.c
LOCAL_MODULE := libsdcard
LOCAL_CFLAGS := -Wall -Wno-unused-parameter
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := main.c
LOCAL_MODULE := sdcard
LOCAL_CFLAGS := -Wall -Wno-unused-parameter
LOCAL_STATIC_LIBRARIES := libsdcard libc libcutils liblog
include $(BUILD_EXECUTABLE)
