

HSM_PATH= ../imx8dxla0/seco_libs
HSM_LIB= $(HSM_PATH)/*.a
HSM_INC= $(HSM_PATH)/include/hsm
NVM_INC= $(HSM_PATH)/include

IDIR = -I$(HSM_INC) -I$(NVM_INC) -Iinc
PREFIX =
CC := $(PREFIX)gcc
AR := $(PREFIX)ar
ARCH := x86_64
CCFLAG := -lpthread -ldl -lz -Wall -fopenmp
LIBSTATIC := $(HSM_LIB)
CCOBJFLAG := -c $(IDIR) -Wall -fopenmp

# path macros
BIN_PATH := bin/$(ARCH)
OBJ_PATH := obj/$(ARCH)
SRC_PATH := src

# compile macros
TARGET_NAME := v2x_fw_test

TARGET := $(BIN_PATH)/$(TARGET_NAME)
MAIN_SRC := main.c

# src files & obj files
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# clean files list
DISTCLEAN_LIST := $(OBJ) \
                  $(OBJ_DEBUG)
CLEAN_LIST := $(TARGET) \
			  $(TARGET_DEBUG) \
			  $(DISTCLEAN_LIST)
MKDIR_P = mkdir -p

OUT_DIR = ${BIN_PATH} ${OBJ_PATH}

${OUT_DIR}:
	${MKDIR_P} ${OUT_DIR}

# default rule
default: all

.PHONY: directories
directories: ${OUT_DIR}

# non-phony targets
$(TARGET): $(OBJ)
	$(CC) -o $@ $? $(LIBSTATIC) $(CCFLAG)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
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
