# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# Override this in the BoardConfig.mk
# to change the default size
# Note: The value is in Kilobytes
AUDITD_MAX_LOG_FILE_SIZEKB ?= 100

LOCAL_SRC_FILES:= \
	auditd.c \
	libaudit.c \
	audit_log.c

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libc

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := auditd
LOCAL_CFLAGS := -DAUDITD_MAX_LOG_FILE_SIZEKB=$(AUDITD_MAX_LOG_FILE_SIZEKB)
include $(BUILD_EXECUTABLE)
