
HSM_PATH= ../imx8dxla0/seco_libs
HSM_LIB= $(HSM_PATH)/*.a

LIBS= lib/$(ARCH)
HSM_INC= $(HSM_PATH)/include/hsm
NVM_INC= $(HSM_PATH)/include

IDIR = -I$(HSM_INC) -I$(NVM_INC) -Iinc

CCFLAG := -lpthread -ldl -lz -Wall -Wextra
LIBSTATIC := $(HSM_LIB) lib/$(ARCH)/libgomp.a
CCOBJFLAG := -c $(IDIR) -Wall -Wextra -fopenmp

# path macros
BIN_PATH := bin/$(ARCH)
OBJ_PATH := obj/$(ARCH)
SRC_PATH := src
# path tests ****
SRC_TEST_PATH := src/tests
OBJ_TEST_PATH := obj/$(ARCH)/tests

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
DISTCLEAN_LIST := $(OBJ) \
                  $(OBJ_TEST) \
                  $(OBJ_DEBUG)
CLEAN_LIST := $(TARGET) \
			  $(TARGET_DEBUG) \
			  $(DISTCLEAN_LIST)

# create missing directory
MKDIR_P = mkdir -p

OUT_DIR = ${BIN_PATH} ${OBJ_PATH} $(OBJ_TEST_PATH)

${OUT_DIR}:
	${MKDIR_P} ${OUT_DIR}

# default rule
default: all

.PHONY: directories
directories: ${OUT_DIR}

# non-phony targets
$(TARGET): $(OBJ) $(OBJ_TEST)
	$(CC) -o $@ $? $(LIBSTATIC) $(CCFLAG)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(CCOBJFLAG) -o $@ $<

# generate rules for tests files ****
$(OBJ_TEST_PATH)/%.o: $(SRC_TEST_PATH)/%.c*
	$(CC) $(CCOBJFLAG) -o $@ $<

# phony rules
.PHONY: all
all: directories $(TARGET)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)
	@rm -rf bin obj

.PHONY: distclean
distclean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(DISTCLEAN_LIST)
	@rm -rf bin obj
