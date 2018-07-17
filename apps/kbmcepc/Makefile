
TARGETS = pgw_K 
CC=g++ -fpermissive -std=c++11 -g -O3 -Wno-write-strings -Wall
CC1= g++ -std=c++11 -g
DPDK=0
PS=0
NETMAP=1
CFLAGS=-DMAX_CPUS=2

EPC_LIB = -I include-epc

# DPDK LIBRARY and HEADER
DPDK_INC=/include
DPDK_LIB=/lib/

# mtcp library and header 
#MTCP_FLD    =../../mtcp
#MTCP_INC    =-I${MTCP_FLD}/include
#MTCP_LIB    =-L${MTCP_FLD}/lib
#MTCP_TARGET = ${MTCP_LIB}/libmtcp.a
#MTCP_SCR = -I ${MTCP_FLD}/scr/include

UTIL_FLD = ../../util
UTIL_INC = -I${UTIL_FLD}/include
UTIL_OBJ = ${UTIL_FLD}/http_parsing.o ${UTIL_FLD}/tdate_parse.o ${UTIL_FLD}/netlib.o

#$(info VAR="$(MTCP_SCR)")

#PS_DIR = ../../io_engine/
#PS_INC = ${PS_DIR}/include
#INC = -I./include/ ${UTIL_INC} ${MTCP_INC} -I${UTIL_FLD}/include
#LIBS = ${MTCP_LIB}
#ifeq ($(PS),1)
#INC += -I{PS_INC}
#LIBS += -lmtcp -L${PS_DIR}/lib -lps -lpthread -lrt
#endif

ifeq ($(NETMAP),1)
LIBS += -lpthread -lrt
endif

# CFLAGS for DPDK-related compilation
INC += ${MTCP_INC}
ifeq ($(DPDK),1)
DPDK_MACHINE_FLAGS = $(shell cat /include/cflags.txt)
INC += ${DPDK_MACHINE_FLAGS} -I${DPDK_INC} -include $(DPDK_INC)/rte_config.h
endif

ifeq ($(shell uname -m),x86_64)
LIBS += -m64
endif

ifeq ($(DPDK),1)
DPDK_LIB_FLAGS = $(shell cat /lib/ldflags.txt)
#LIBS += -m64 -g -O3 -pthread -lrt -march=native -Wl,-export-dynamic -Wl,-lpthread -Wl,-lrt -Wl,-ldl
LIBS += -g -O3 -pthread -lrt -march=native -export-dynamic -lpthread -lrt -ldl
else
#LIBS += -m64 -g -O3 -pthread -lrt -march=native -Wl,-export-dynamic -Wl,-lpthread -Wl,-lrt -Wl,-ldl 
LIBS += -g -O3 -pthread -lrt -march=native -export-dynamic -lpthread -lrt -ldl 
endif

#LDFLAGS += -lboost_system

ifeq ($V,) # no echo
	export MSG=@echo
	export HIDE=@
else
	export MSG=@\#
	export HIDE=
endif

#EPC Files required
EPC_REQR = include-epc/packet.o include-epc/utils.o include-epc/s1ap.o include-epc/gtp.o include-epc/mysql.o include-epc/diameter.o include-epc/telecom.o  include-epc/security.o

all: pgw_K


############################################################################
#pgw_K compile
pgw_K.o: K_pgw.cpp
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< -pthread ${EPC_LIB} ${LIBS} ${CFLAGS} ${INC} -o pgw_K.o

pgw_K_C = pgw_K.o
pgw_K_L = ${CC} -o pgw_K $(EPC_REQR) $(pgw_K_C) ${LIBS}  ${UTIL_OBJ}  -lcrypto -pthread `mysql_config --cflags --libs`

pgw_K:	$(pgw_K_C)
	$(pgw_K_L)


################################################################################





clean:
	rm -f *~ *.o ${TARGETS} log_*

distclean: clean
	rm -rf Makefile
