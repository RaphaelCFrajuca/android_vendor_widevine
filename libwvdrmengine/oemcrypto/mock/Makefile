#
# Builds liboemcrypto_mock.so
#

#PROJECTS_ROOT = ~projects
#
ifndef PROJECTS_ROOT
PROJECTS_ROOT = ../../../..
endif

CDM_ROOT = $(PROJECTS_ROOT)/cdm
CDM_SRC_PATH = $(CDM_ROOT)/cdm
CDM_INCLUDE_PATH = $(CDM_SRC_PATH)/include

EUREKA_ROOT = $(PROJECTS_ROOT)/eureka/eureka/src
CHROME_ROOT = $(EUREKA_ROOT)/chromium/src
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

#primary build target
TARGET_LIB = liboemcrypto_mock.so

LIB_OBJECTS = \
        oemcrypto_mock.o \
        oemcrypto_engine_mock.o \
        oemcrypto_key_mock.o \
        oemcrypto_keybox_mock.o

INCLUDES = \
	-I$(CDM_INCLUDE_PATH)

OBJECTDIR = $(OBJPATH)/mock

INSTALLDIR = $(BUILDPATH)

OBJECTS := $(patsubst %.o,$(OBJECTDIR)/%.o,$(LIB_OBJECTS))

CXXFLAGS = -m64 -fPIC -W -Wall -g -DCDM_TEST
LINK = $(CXX)
MKDIR = mkdir -p

$(INSTALLDIR)/$(TARGET_LIB): $(OBJECTDIR) $(INSTALLDIR) $(OBJECTS)
	$(LINK) -v -fPIC -m64 -shared -static-libgcc $(SHLIBFLAGS) \
	$(OBJECTS) \
	--retain-symbols-file=OECsymbols.txt  \
	-Wl,-Bstatic \
	-Wl,-Bdynamic -lcrypto \
	-o $@

$(OBJECTDIR)/%.o: src/%.cpp
	$(CXX) -c -DCDM_TEST $(CXXFLAGS) $(INCLUDES) $< -o $@

$(OBJECTDIR)/%.o: src/%.cc
	$(CXX) -c -DCDM_TEST $(CXXFLAGS) $(INCLUDES) $< -o $@

test:
	make -C test

clean:
	$(RM) -rf $(OBJECTDIR)
	$(RM) -rf $(INSTALLDIR)/$(TARGET_LIB)

$(OBJECTDIR):
	@$(MKDIR) $@

$(INSTALLDIR):
	@$(MKDIR) $@

.PHONY: $(OBJECTDIR)

.PHONY: $(INSTALLDIR)

.PHONY: clean

.PHONY: test
