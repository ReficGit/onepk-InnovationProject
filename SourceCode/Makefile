#------------------------------------------------------------------
# Makefile - Make rules for ONE-P Sample applications
#
# Copyright (c) 2011-2012 by cisco Systems, Inc.
# All rights reserved.
#------------------------------------------------------------------
TUT_SRC ?= ../
include $(TUT_SRC)/Makefile.defs

# Objects file to build
OBJSNETAPP += \
	obj/InnovationProject.o \
	obj/datapath_util.o

LD_LIBS += -lonep${ONEP_LBITS}_datapath

# All Target
# To build DatapathTutorial: "make bin/DatapathTutorial"
all: makedirs bin/InnovationProject 

# Add inputs and outputs from these tool invocations to the build variables 

makedirs:
	@if [ ! -d obj ] ; then mkdir obj ; fi
	@if [ ! -d bin ] ; then mkdir bin ; fi

makeutil:
	${MAKE} -C $(TUT_SRC)/SessionElement all

# Tool invocations
bin/InnovationProject: makedirs makeutil $(OBJSNETAPP)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -pthread -o $@ $(OBJSNETAPP) \
			$(TUT_SRC)/SessionElement/obj/session_element_util.o \
			$(LD_FLAGS) $(LD_LIBDIRS) $(LD_LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) -rf obj bin 
	-@echo ' '

obj/%.o: %.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CC_INCDIRS) $(CC_BLDFLAGS) -MMD -MP -pthread \
		-MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

.PHONY: all clean dependents
.SECONDARY:

