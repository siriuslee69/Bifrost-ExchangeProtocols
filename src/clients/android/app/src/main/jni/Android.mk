LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := bifrost_ame_nim
LOCAL_SRC_FILES := ../../../build/generated/nimJniLibs/$(TARGET_ARCH_ABI)/libbifrost_ame_nim.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := bifrost_ame_jni
LOCAL_SRC_FILES := native_ame_jni.cpp
LOCAL_SHARED_LIBRARIES := bifrost_ame_nim
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
