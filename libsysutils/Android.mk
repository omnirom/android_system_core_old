ifneq ($(BUILD_TINY_ANDROID),true)

LOCAL_PATH:= $(call my-dir)

common_src_files :=                           \
                  src/SocketListener.cpp      \
                  src/FrameworkListener.cpp   \
                  src/NetlinkListener.cpp     \
                  src/NetlinkEvent.cpp        \
                  src/FrameworkCommand.cpp    \
                  src/SocketClient.cpp        \
                  src/ServiceManager.cpp      \
                  EventLogTags.logtags


include $(CLEAR_VARS)
LOCAL_SRC_FILES:= $(common_src_files)
LOCAL_MODULE:= libsysutils
LOCAL_C_INCLUDES := $(KERNEL_HEADERS)
LOCAL_CFLAGS :=
LOCAL_SHARED_LIBRARIES := libcutils liblog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= $(common_src_files)
LOCAL_MODULE:= libsysutils
LOCAL_C_INCLUDES := $(KERNEL_HEADERS)
LOCAL_CFLAGS :=
include $(BUILD_STATIC_LIBRARY)

endif
