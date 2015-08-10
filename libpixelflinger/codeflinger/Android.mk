ifneq ($(filter x86%,$(TARGET_ARCH)),)
include $(call all-named-subdir-makefiles,x86/libenc)
endif
