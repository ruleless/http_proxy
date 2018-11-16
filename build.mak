CC:= clang
CXX:= clang++

CFLAGS+= -Wall -Werror
CXXFLAGS+= -Wall -Werror -std=c++11
LDFLAGS+=

SYSTEM_INC:=/usr/local/include

ifeq ($(SRCDIR),)
	SRCDIR:= ./
endif

CPP_SOURCES+= $(foreach d,$(SRCDIR),$(wildcard $(d)*.cpp))
CPP_OBJS+= $(patsubst %.cpp, $(OBJDIR)%.o, $(CPP_SOURCES))
CPP_DEPENDS:= $(CPP_OBJS:%.o=%.d)

C_SOURCES+= $(foreach d,$(SRCDIR),$(wildcard $(d)*.c))
C_OBJS+= $(patsubst %.c, $(OBJDIR)%.o, $(C_SOURCES))
C_DEPENDS:= $(C_OBJS:%.o=%.d)

SOURCES+= $(CPP_SOURCES) $(C_SOURCES)
OBJS+= $(CPP_OBJS) $(C_OBJS)
DEPENDS:= $(C_DEPENDS) $(CPP_DEPENDS)

.PHONY: clean all cpp _clean _all _install

.SUFFIXES: .c .cpp .o

all: $(OUTDIR)$(TARGET) $(_all)

$(OUTDIR)$(TARGET): $(OBJS)
ifeq ($(CPP_OBJS),)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)
else
	$(CXX) -o $@ $^ $(LIBS) $(LDFLAGS)
endif

$(C_OBJS):$(OBJDIR)%.o:%.c
	@mkdir -p $(dir $@)
	$(CC) -c $< -o $@ $(INCLUDE) $(CFLAGS)

$(CPP_OBJS):$(OBJDIR)%.o:%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $< -o $@ $(INCLUDE) $(CXXFLAGS)


-include $(C_DEPENDS)

$(C_DEPENDS):$(OBJDIR)%.d:%.c
	set -e; rm -f $@; \
	echo -n $(dir $<) > $@.$$$$; \
	$(CC) -MM $(INCLUDE) $(CFLAGS) $< >> $@.$$$$; \
	sed 's,\($*\)\.o[:]*,$(OBJDIR)\1.o $@:,g' < $@.$$$$ > $@; \
	rm $@.$$$$

-include $(CPP_DEPENDS)

$(CPP_DEPENDS):$(OBJDIR)%.d:%.cpp
	set -e; rm -f $@; \
	echo -n $(dir $<) > $@.$$$$; \
	$(CXX) -MM $(INCLUDE) $(CXXFLAGS) $< >> $@.$$$$; \
	sed 's,\($*\)\.o[:]*,$(OBJDIR)\1.o $@:,g' < $@.$$$$ > $@; \
	rm $@.$$$$


header:
ifneq ($(HEADERS),)
	install -d $(SYSTEM_INC)
	install --verbose --mode=0644 $(HEADERS) $(SYSTEM_INC)
endif


install: all header $(_install) $(HEADERS)
ifneq ($(debug), 1)
	strip $(OUTDIR)$(TARGET)
endif
	install -d $(INSTALL_DIR)
	install --verbose --mode=0755 $(OUTDIR)$(TARGET) $(INSTALL_DIR)


clean: $(_clean)
	$(shell find -name "*.d*" -exec rm -r {} \;)
	-rm -f $(OUTDIR)$(TARGET) $(OBJS)


fake:
	@echo "CPP_SOURCES: " $(CPP_SOURCES)
	@echo "C_SOURCES: " $(C_SOURCES)
	@echo "OBJS: " $(OBJS)
	@echo "DEPENDS: " $(DEPENDS)
