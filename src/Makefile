CC = gcc
BWGATED = bwgated
BWGATEDOBJS = mainsrv.o service.o session.o base.o util/trace.o util/DES.o tinyxml/tinyxmlparser.o tinyxml/tinyxmlerror.o tinyxml/tinyxml.o tinyxml/tinystr.o

ifdef CYGWIN
MDEF = CYGWIN
else
MDEF = _LINUX_OS_
endif

INCDIR = 
LDDIRS = -L.

LDLIST_SVR = -lstdc++ -lrt -lpthread

FLAGS = -O2 -fPIC -w

all: bwgd

bwgd: $(BWGATED)

$(BWGATED): $(BWGATEDOBJS)
	$(CC) -o $@ $(BWGATEDOBJS) $(LDDIRS) $(LDLIST_SVR) 
    
%.o : %.cpp
	$(CC) -D$(MDEF) $(INCDIR) $(FLAGS) -c $< -o $@

clean:
	-rm -f  $(BWGATED) *.elf *.gdb *.o *.a *.so
