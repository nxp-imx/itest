
.PHONY: default
default: all

CURDIR := $(shell pwd)
WORKSPACE := $(CURDIR)/..
OPENSSL_VER := 1.1.1h

ARCH ?= arm64
HSM_PATH ?= $(WORKSPACE)/seco_libs
HSM_LIB := $(HSM_PATH)/*.a
HSM_INC := $(HSM_PATH)/include/hsm
NVM_INC := $(HSM_PATH)/include
IDIR := -I$(HSM_INC) -I$(NVM_INC) -Iinc -Ilib/openssl-$(OPENSSL_VER)

CCFLAG := -lpthread -ldl -lz -Wall -Wextra -Werror
LIBSTATIC := $(HSM_LIB) lib/$(ARCH)/libgomp.a lib/$(ARCH)/libcrypto.a lib/$(ARCH)/libssl.a
CCOBJFLAG := -c $(IDIR) -Wall -Wextra -Werror -fopenmp

# path macros
BINDIR := $(CURDIR)/bin
OBJDIR := $(CURDIR)/obj
SRC_PATH := $(CURDIR)/src
BIN_PATH := $(BINDIR)/$(ARCH)
OBJ_PATH := $(OBJDIR)/$(ARCH)
# path tests
SRC_TEST_PATH := $(CURDIR)/src/*tests*
OBJ_TEST_PATH := $(CURDIR)/obj/$(ARCH)/tests
# path crypto
SRC_CRYPTO_PATH := $(CURDIR)/src/crypto_utils
OBJ_CRYPTO_PATH := $(CURDIR)/obj/$(ARCH)/crypto_utils

# compile macros
TARGET_NAME := itest

TARGET := $(BIN_PATH)/$(TARGET_NAME)
MAIN_SRC := main.c

# src files & obj files
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# src_tests files & obj tests files ****
SRC_TEST := $(foreach x, $(SRC_TEST_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ_TEST := $(addprefix $(OBJ_TEST_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC_TEST)))))

# src_crypto files & obj crypto files ****
SRC_CRYPTO := $(foreach x, $(SRC_CRYPTO_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ_CRYPTO := $(addprefix $(OBJ_CRYPTO_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC_CRYPTO)))))

# clean files list
CLEAN_LIST := $(TARGET)       \
			  $(OBJ)          \
			  $(OBJ_TEST)     \
			  $(OBJ_CRYPTO)   \

# create missing directory
MKDIR_P := mkdir -p

OUT_DIR := ${BIN_PATH} ${OBJ_PATH} $(OBJ_TEST_PATH) $(OBJ_CRYPTO_PATH)

${OUT_DIR}:
	@${MKDIR_P} ${OUT_DIR}

# non-phony targets
$(TARGET): $(OBJ) $(OBJ_TEST) $(OBJ_CRYPTO)
	$(CC) -o $@ $? $(LIBSTATIC) $(CCFLAG)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(CCOBJFLAG) -o $@ $<

# generate rules for tests files ****
$(OBJ_TEST_PATH)/%.o: $(SRC_TEST_PATH)/%.c*
	$(CC) $(CCOBJFLAG) -o $@ $<
# generate rules for crypto files ****
$(OBJ_CRYPTO_PATH)/%.o: $(SRC_CRYPTO_PATH)/%.c*
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

