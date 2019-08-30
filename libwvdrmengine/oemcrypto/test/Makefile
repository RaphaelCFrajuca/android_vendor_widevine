#
# Builds oemcrypto_unittests
#
#PROJECTS_ROOT = ~projects
#
ifndef PROJECTS_ROOT
PROJECTS_ROOT = ../../../../..
endif

CDM_ROOT = $(PROJECTS_ROOT)/cdm
CDM_SRC_PATH = $(CDM_ROOT)/cdm
CDM_BASE_INCLUDE_PATH = $(CDM_SRC_PATH)/include

EUREKA_ROOT = $(PROJECTS_ROOT)/eureka/eureka
CHROME_ROOT = $(EUREKA_ROOT)/src/chromium/src
#
# build outputs should go into Chrome repository, such as ../chromium/src/out
# or some local equivalent.
# WARNING: splitting outputs from CHROME_ROOT can lead to build errors
ifndef CHROME_ROOT
CHROME_ROOT = $(CDM_ROOT)/out
endif

# TARGET_PLATFORM from {x86,eureka}
ifndef TARGET_PLATFORM
TARGET_PLATFORM = x86
endif

# TARGET_BUILD from {debug,release}
ifndef TARGET_BUILD
TARGET_BUILD = debug
endif

ifeq ($(TARGET_PLATFORM),x86)
  BUILDPLATFORM = out_x86_linux
else ifeq ($(TARGET_PLATFORM),eureka)
  BUILDPLATFORM = out_arm_eureka
else
  BUILDPLATFORM = UNKNOWN
endif

ifeq ($(TARGET_BUILD),debug)
  BUILDTYPE = Debug
else ifeq ($(TARGET_BUILD),release)
  BUILDTYPE = Release
else
  BUILDTYPE = UNKNOWN
endif

BUILDPATH = $(CHROME_ROOT)/$(BUILDPLATFORM)/$(BUILDTYPE)
OBJPATH = $(BUILDPATH)/obj

CHROME_THIRD_PARTY_LIBS = $(BUILDPATH)/obj/third_party

# target image file name
TARGET_TEST_EXE = oemcrypto_unittests

TARGET_OBJECTS = oemcrypto_test.o

OBJECTDIR = $(OBJPATH)/oemcrypto_unittests

INSTALLDIR = $(BUILDPATH)

LIBGTEST_INCLUDE = $(CDM_SRC_PATH)/prebuilt/gtest/include
LIBGTEST_LIBS = $(CDM_SRC_PATH)/prebuilt/gtest/$(BUILDPLATFORM)/$(BUILDTYPE)/lib
LIBGTEST_LIBNAME = gtest

INCLUDES = \
        -I$(LIBGTEST_INCLUDE) \
        -I$(CDM_BASE_INCLUDE_PATH)

LIBDIRS = \
        -L$(INSTALLDIR) \
        -L$(LIBGTEST_LIBS)

OBJECTS := $(patsubst %.o,$(OBJECTDIR)/%.o,$(TARGET_OBJECTS))

CXXFLAGS = -m64 -fPIC -W -Wall -g -DCDM_TEST
LINK = $(CXX)
MKDIR = mkdir -p

$(INSTALLDIR)/$(TARGET_TEST_EXE): $(OBJECTDIR) $(INSTALLDIR) $(OBJECTS)
	$(CXX) -v -fPIC -m64 $(OBJECTS) $(LIBDIRS) -loemcrypto_mock \
	-lcrypto -ldl -lrt -lpthread -l$(LIBGTEST_LIBNAME) -o $@
	@echo "[Unit test image: " $(INSTALLDIR)/$(TARGET_TEST_EXE) "]"

$(OBJECTDIR)/%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) $< -o $@

$(OBJECTDIR)/%.o: %.cc
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) $< -o $@

clean:
	$(RM) -rf $(OBJECTDIR)
	$(RM) -rf $(INSTALLDIR)/$(TARGET_TEST_EXE)

$(OBJECTDIR):
	@$(MKDIR) $@

$(INSTALLDIR):
	@$(MKDIR) $@

.PHONY: $(OBJECTDIR)

.PHONY: $(INSTALLDIR)

.PHONY: clean

.PHONY: test
