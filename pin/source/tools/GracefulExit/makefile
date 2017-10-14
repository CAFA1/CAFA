
## PIN tools
##

##############################################################
#
# Here are some things you might want to configure
#
##############################################################

TARGET_COMPILER?=gnu
ifdef OS
    ifeq (${OS},Windows_NT)
        TARGET_COMPILER=ms
    endif
endif

SUF = $(PINTOOLS_SUFFIX)


##############################################################
#
# include *.config files
#
##############################################################

ifeq ($(TARGET_COMPILER),gnu)
    include ../makefile.gnu.config
    STATIC=-static
endif

ifeq ($(TARGET_COMPILER),ms)
    include ../makefile.ms.config
    DBG?=
endif

ifeq ($(TARGET_OS),w)
    OS_API=windows
else
    OS_API=unix
endif


##############################################################
#
# Tests, tools and apps definitions
#
##############################################################

## Place all generic definitions here:

# This defines tests which run tools of the same name.  This is simply for convenience to avoid
# defining the test name twice (once in TOOL_ROOTS and again in TEST_ROOTS).
# Tests defined here should not be defined in TOOL_ROOTS and TEST_ROOTS.
TEST_TOOL_ROOTS = applicationexit

# This defines the tools which will be run during the the tests, and were not already defined in
# TEST_TOOL_ROOTS.
TOOL_ROOTS = 

# This defines the tests to be run that were not already defined in TEST_TOOL_ROOTS.
TEST_ROOTS =

# This defines all the applications that will be run during the tests.
APPS = 

# This defines any additional object files that need to be compiled.
OBJECT_FILES =

## Place OS specific definitions here:

ifeq ($(TARGET_OS),w)
    TOOL_ROOTS += threadFini_tool
    TEST_ROOTS += threadFini raceToEnterVm
    APPS += threadFini_app threadFini_exception_app raceToEnterVm_app
    OBJECT_FILES += threadUtils.o
endif

ifeq ($(TARGET_OS),l)
    TOOL_ROOTS += threadFini_tool
    TEST_ROOTS += threadFini threadFini_exception threadFini_sig raceToExit
    APPS += threadFini_app threadFini_exception_app threadFini_sig_app threadFini_sendsig raceToExit_app
    OBJECT_FILES += threadUtils.o
endif

## Finalize definitions - add prefixes and suffixes
TOOLS = $(TEST_TOOL_ROOTS:%=$(OBJDIR)%$(PINTOOL_SUFFIX)) $(TOOL_ROOTS:%=$(OBJDIR)%$(PINTOOL_SUFFIX))
APPS_BINARY_FILES = $(APPS:%=$(OBJDIR)%)
TESTS = $(TEST_TOOL_ROOTS:%=%.test) $(TEST_ROOTS:%=%.test)


##############################################################
#
# make targets
#
##############################################################

ifeq ($(TARGET_OS),w)
all: tools 
else
all: tools $(APPS_BINARY_FILES)
endif

tools: $(OBJDIR) $(TOOLS)

tests-sanity: $(OBJDIR) test

test: $(OBJDIR) $(TESTS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

## Cleanup
clean:
	-rm -rf $(OBJDIR) *.output  *.out *.tested *.failed *.xml *.makefile.copy
	-rm -rf pin.log pintool.log core.* *.core *.obj

##############################################################
#
# Test rules
#
##############################################################

# Test PIN_ExitApplication from both an analysis routine and a callback.
applicationexit.test: $(OBJDIR)applicationexit$(PINTOOL_SUFFIX) $(TESTAPP) applicationexit.tested applicationexit.failed
	$(PIN) -t $< -o $(OBJDIR)applicationexit.out -- $(TESTAPP) 
	diff --strip-trailing-cr $(OBJDIR)applicationexit.out applicationexit.master
	$(PIN) -t $< -o $(OBJDIR)applicationexit_c.out -c -- $(TESTAPP) 
	diff --strip-trailing-cr $(OBJDIR)applicationexit_c.out applicationexit.master
	rm applicationexit.failed $(OBJDIR)applicationexit.out $(OBJDIR)applicationexit_c.out 

threadFini.test: $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) $(OBJDIR)threadFini_app threadFini.tested threadFini.failed
	testFailed=0; \
	for trial in 0 1 2 3 4; do \
	  thisTest=0; \
	  $(PIN) -logfile $(OBJDIR)threadFini.log.$$trial \
	    -xyzzy -enable_vsm 1 -mesgon log_vsm -mesgon log_depot \
	    -t $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) \
	    -startsfile $(OBJDIR)threadStarts.out.$$trial \
	    -finisfile $(OBJDIR)threadFinis.out.$$trial -- \
	        $(OBJDIR)threadFini_app $$trial > $(OBJDIR)threadFini.out.$$trial 2>&1; \
	  if ! grep -q "fini function 0 6" $(OBJDIR)threadFini.out.$$trial; then thisTest=1; fi; \
	  sort $(OBJDIR)threadStarts.out.$$trial > $(OBJDIR)threadStarts.sorted.$$trial; \
	  sort $(OBJDIR)threadFinis.out.$$trial > $(OBJDIR)threadFinis.sorted.$$trial; \
	  if ! $(PIN_DIFF) $(OBJDIR)threadStarts.sorted.$$trial $(OBJDIR)threadFinis.sorted.$$trial; then thisTest=1; fi; \
	  if test $$thisTest -eq 1; then echo threadFini scenario $$trial failed; testFailed=1; \
          else echo threadFini scenario $$trial passed; fi; \
	done; \
	test $$testFailed -eq 0
	rm threadFini.failed $(OBJDIR)threadFini.out.* $(OBJDIR)threadFini.log.* $(OBJDIR)threadStarts.* $(OBJDIR)threadFinis.*

threadFini_exception.test: $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) $(OBJDIR)threadFini_exception_app threadFini_exception.tested threadFini_exception.failed
	-$(PIN) -logfile $(OBJDIR)threadFini_exception.log \
	  -xyzzy -mesgon log_vsm -mesgon log_depot \
	  -t $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) \
	  -startsfile $(OBJDIR)threadStarts_exception.out \
	  -finisfile $(OBJDIR)threadFinis_exception.out -- \
	      $(OBJDIR)threadFini_exception_app > $(OBJDIR)threadFini_exception.out 2>&1
	grep -q "fini function 0 2" $(OBJDIR)threadFini_exception.out
	sort $(OBJDIR)threadStarts_exception.out > $(OBJDIR)threadStarts_exception.sorted
	sort $(OBJDIR)threadFinis_exception.out > $(OBJDIR)threadFinis_exception.sorted
	$(PIN_DIFF) $(OBJDIR)threadStarts_exception.sorted $(OBJDIR)threadFinis_exception.sorted
	rm threadFini_exception.failed $(OBJDIR)threadFini_exception.out $(OBJDIR)threadFini_exception.log $(OBJDIR)threadFinis_exception.*

threadFini_sig.test: $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) $(OBJDIR)threadFini_sig_app $(OBJDIR)threadFini_sendsig threadFini_sig.tested threadFini_sig.failed
	-$(PIN) -logfile $(OBJDIR)threadFini_sig.log \
	  -xyzzy -mesgon log_vsm -mesgon log_depot \
	  -t $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) \
	  -startsfile $(OBJDIR)threadStarts_sig.out \
	  -finisfile $(OBJDIR)threadFinis_sig.out -- \
	      $(OBJDIR)threadFini_sig_app $(OBJDIR)threadFini_sendsig > $(OBJDIR)threadFini_sig.out 2>&1
	grep -q "fini function 0 2" $(OBJDIR)threadFini_sig.out
	sort $(OBJDIR)threadStarts_sig.out > $(OBJDIR)threadStarts_sig.sorted
	sort $(OBJDIR)threadFinis_sig.out > $(OBJDIR)threadFinis_sig.sorted
	$(PIN_DIFF) $(OBJDIR)threadStarts_sig.sorted $(OBJDIR)threadFinis_sig.sorted
	rm threadFini_sig.failed $(OBJDIR)threadFini_sig.out $(OBJDIR)threadFini_sig.log $(OBJDIR)threadStarts_sig.out $(OBJDIR)threadFinis_sig.out

raceToExit.test: $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) $(OBJDIR)raceToExit_app raceToExit.tested raceToExit.failed
	$(PIN) -logfile $(OBJDIR)raceToExit.log \
	  -xyzzy -mesgon log_vsm -mesgon log_depot \
	  -t $(OBJDIR)threadFini_tool$(PINTOOL_SUFFIX) \
	  -startsfile $(OBJDIR)threadStarts_raceToExit.out \
	  -finisfile $(OBJDIR)threadFinis_raceToExit.out -- \
	      $(OBJDIR)raceToExit_app > $(OBJDIR)raceToExit.out 2>&1
	grep -q "fini function 0 `cat $(OBJDIR)threadStarts_raceToExit.out | wc -l`" $(OBJDIR)raceToExit.out
	sort $(OBJDIR)threadStarts_raceToExit.out > $(OBJDIR)threadStarts_raceToExit.sorted
	sort $(OBJDIR)threadFinis_raceToExit.out > $(OBJDIR)threadFinis_raceToExit.sorted
	$(PIN_DIFF) $(OBJDIR)threadStarts_raceToExit.sorted $(OBJDIR)threadFinis_raceToExit.sorted
	rm raceToExit.failed $(OBJDIR)raceToExit.out $(OBJDIR)raceToExit.log $(OBJDIR)threadFinis_raceToExit.*

raceToEnterVm.test: $(OBJDIR)raceToEnterVm_app raceToEnterVm.tested raceToEnterVm.failed
	$(PIN) -logfile $(OBJDIR)raceToEnterVm.log \
	  -xyzzy -enable_vsm 1 -mesgon log_vsm -mesgon log_depot -- \
	      $(OBJDIR)raceToEnterVm_app > $(OBJDIR)raceToEnterVm.out 2>&1
	rm raceToEnterVm.failed $(OBJDIR)raceToEnterVm.out $(OBJDIR)raceToEnterVm.log


##############################################################
#
# Build rules
#
##############################################################

## defines

ifeq ($(TARGET_OS),l)
    THREADLIB = -lpthread
else
    THREADLIB =
endif

## Default build rules
$(OBJDIR)%.o: %.cpp
	$(CXX) ${COPT} $(CXXFLAGS) $(PIN_CXXFLAGS) ${OUTOPT}$@ $<

$(OBJDIR)%$(PINTOOL_SUFFIX): $(OBJDIR)%.o $(PIN_LIBNAMES)
	${PIN_LD} $(PIN_LDFLAGS) $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} $(PIN_LIBS) $(DBG)

## Special build rules
$(OBJDIR)threadFini_app: threadFini_app.cpp threadUtils.h $(OBJDIR)threadUtils.$(OBJEXT)
	${CXX} $(APP_CXXFLAGS) ${OUTEXE}$@ $< $(OBJDIR)threadUtils.$(OBJEXT) $(THREADLIB)

$(OBJDIR)threadFini_sig_app: threadFini_sig_app.cpp threadUtils.h $(OBJDIR)threadUtils.$(OBJEXT)
	${CXX} $(APP_CXXFLAGS) ${OUTOPT}$@ $< $(OBJDIR)threadUtils.$(OBJEXT) $(THREADLIB)

$(OBJDIR)threadFini_sendsig: threadFini_sendsig.cpp
	${CXX} $(APP_CXXFLAGS) ${OUTOPT}$@ $<

$(OBJDIR)threadFini_exception_app: threadFini_exception_app.cpp threadUtils.h $(OBJDIR)threadUtils.$(OBJEXT)
	${CXX} $(APP_CXXFLAGS) ${OUTEXE}$@ $< $(OBJDIR)threadUtils.$(OBJEXT) $(THREADLIB)

$(OBJDIR)raceToExit_app: raceToExit_app.cpp threadUtils.h $(OBJDIR)threadUtils.$(OBJEXT)
	${CXX} $(APP_CXXFLAGS) ${OUTEXE}$@ $< $(OBJDIR)threadUtils.$(OBJEXT) $(THREADLIB)

$(OBJDIR)raceToEnterVm_app: raceToEnterVm_app.cpp
	${CXX} $(APP_CXXFLAGS) ${OUTEXE}$@ $<

$(OBJDIR)threadUtils.$(OBJEXT): threadUtils_$(TARGET_OS).cpp threadUtils.h
	$(CXX) ${COPT} $(APP_CXXFLAGS) ${OUTOPT}$@ $<
