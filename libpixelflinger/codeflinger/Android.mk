ifneq ($(TARGET_ARCH),x86, x86_64)
include $(call all-named-subdir-makefiles,x86/libenc)
endif
