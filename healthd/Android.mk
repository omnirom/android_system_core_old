# Copyright 2013 The Android Open Source Project

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := healthd_board_default.cpp
LOCAL_MODULE := libhealthd.default
LOCAL_CFLAGS := -Werror
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	healthd.cpp \
	healthd_mode_android.cpp \
	healthd_mode_charger.cpp \
	BatteryMonitor.cpp \
	BatteryPropertiesRegistrar.cpp

LOCAL_MODULE := healthd
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_CFLAGS := -D__STDC_LIMIT_MACROS -Werror

HEALTHD_PATH := \
    RED_LED_PATH \
    GREEN_LED_PATH \
    BLUE_LED_PATH \
    TW_BRIGHTNESS_PATH \
    TW_SECONDARY_BRIGHTNESS_PATH

$(foreach healthd_charger_define,$(HEALTHD_PATH), \
  $(if $($(healthd_charger_define)), \
    $(eval LOCAL_CFLAGS += -D$(healthd_charger_define)=\"$($(healthd_charger_define))\") \
  ) \
)

ifeq ($(strip $(HEALTHD_FORCE_BACKLIGHT_CONTROL)),true)
LOCAL_CFLAGS += -DHEALTHD_FORCE_BACKLIGHT_CONTROL
endif

ifeq ($(strip $(HEALTHD_ENABLE_TRICOLOR_LED)),true)
LOCAL_CFLAGS += -DHEALTHD_ENABLE_TRICOLOR_LED
endif

ifneq ($(strip $(HEALTHD_BACKLIGHT_ON_LEVEL)),)
LOCAL_CFLAGS += -DHEALTHD_BACKLIGHT_ON_LEVEL=$(HEALTHD_BACKLIGHT_ON_LEVEL)
endif

ifeq ($(strip $(BOARD_CHARGER_DISABLE_INIT_BLANK)),true)
LOCAL_CFLAGS += -DCHARGER_DISABLE_INIT_BLANK
endif

ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_CFLAGS += -DCHARGER_ENABLE_SUSPEND
endif

LOCAL_C_INCLUDES := bootable/recovery

LOCAL_STATIC_LIBRARIES := libbatteryservice libbinder libminui libpng libz libutils libstdc++ libcutils liblog libm libc

ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_STATIC_LIBRARIES += libsuspend
endif

LOCAL_HAL_STATIC_LIBRARIES := libhealthd

# Symlink /charger to /sbin/healthd
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT) \
    && ln -sf /sbin/healthd $(TARGET_ROOT_OUT)/charger

include $(BUILD_EXECUTABLE)


define _add-charger-image
include $$(CLEAR_VARS)
LOCAL_MODULE := system_core_charger_$(notdir $(1))
LOCAL_MODULE_STEM := $(notdir $(1))
_img_modules += $$(LOCAL_MODULE)
LOCAL_SRC_FILES := $1
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $$(TARGET_ROOT_OUT)/res/images/charger
include $$(BUILD_PREBUILT)
endef

_img_modules :=
_images :=
ifneq ($(BOARD_CHARGER_IMG_PATH),)
$(foreach _img, $(call find-subdir-subdir-files, ../../../$(BOARD_CHARGER_IMG_PATH), "*.png"), \
  $(eval $(call _add-charger-image,$(_img))))
else
$(foreach _img, $(call find-subdir-subdir-files, "images", "*.png"), \
  $(eval $(call _add-charger-image,$(_img))))
endif

include $(CLEAR_VARS)
LOCAL_MODULE := charger_res_images
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := $(_img_modules)
include $(BUILD_PHONY_PACKAGE)

_add-charger-image :=
_img_modules :=
