
.PHONY: default
default: all

CURDIR := $(shell pwd)
WORKSPACE := $(CURDIR)/..

ARCH ?= arm64
HSM_PATH ?= $(WORKSPACE)/seco_libs
HSM_LIB := $(HSM_PATH)/*.a
HSM_INC := $(HSM_PATH)/include/hsm
NVM_INC := $(HSM_PATH)/include
IDIR := -I$(HSM_INC) -I$(NVM_INC) -Iinc

CCFLAG := -lpthread -ldl -lz -Wall -Wextra
LIBSTATIC := $(HSM_LIB) lib/$(ARCH)/libgomp.a
CCOBJFLAG := -c $(IDIR) -Wall -Wextra -fopenmp

# path macros
BINDIR := $(CURDIR)/bin
OBJDIR := $(CURDIR)/obj
SRC_PATH := $(CURDIR)/src
BIN_PATH := $(BINDIR)/$(ARCH)
OBJ_PATH := $(OBJDIR)/$(ARCH)
# path tests
SRC_TEST_PATH := $(CURDIR)/src/tests
OBJ_TEST_PATH := $(CURDIR)/obj/$(ARCH)/tests

# compile macros
TARGET_NAME := v2x_fw_test

TARGET := $(BIN_PATH)/$(TARGET_NAME)
MAIN_SRC := main.c

# src files & obj files
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# src_tests files & obj tests files ****
SRC_TEST := $(foreach x, $(SRC_TEST_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ_TEST := $(addprefix $(OBJ_TEST_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC_TEST)))))

# clean files list
CLEAN_LIST := $(TARGET)       \
			  $(OBJ)          \
			  $(OBJ_TEST)     \

# create missing directory
MKDIR_P := mkdir -p

OUT_DIR := ${BIN_PATH} ${OBJ_PATH} $(OBJ_TEST_PATH)

${OUT_DIR}:
	@${MKDIR_P} ${OUT_DIR}

# non-phony targets
$(TARGET): $(OBJ) $(OBJ_TEST)
	$(CC) -o $@ $? $(LIBSTATIC) $(CCFLAG)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(CCOBJFLAG) -o $@ $<

# generate rules for tests files ****
$(OBJ_TEST_PATH)/%.o: $(SRC_TEST_PATH)/%.c*
	$(CC) $(CCOBJFLAG) -o $@ $<

.PHONY: all clean directories check-env

check-env:
ifeq ($(origin CC), default)
	$(warning [WARNING] CC not set)
endif

all: check-env directories $(TARGET)

directories: ${OUT_DIR}

clean:
	@echo Cleaning this place...
	@rm -rvf $(BINDIR) $(OBJDIR)

