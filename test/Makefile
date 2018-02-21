PROXYLIBWITHMIRACL = ../src/proxylibmiracl.a
AFGHPATH = /usr/local/include/afgh
MIRACLHPATH = /usr/local/include/miracl
CC = g++
CCFLAGS = -I${MIRACLHPATH} -I${AFGHPATH} -O0 -g -std=c++11
CCLIBS = -lstdc++
MAIN = main
MAINOBJ = main.o


main:

${MAIN}: ${MAINOBJ}
	${CC} ${CCFLAGS} ${CCLIBS} -o ${MAIN} ${MAINOBJ} ${PROXYLIBWITHMIRACL}

clean:
	rm -rf *.o a.out ${MIRACLPATH}/miracl.a proxylib.a

%.o: %.c
	${CC} ${CCFLAGS} -c $<

%.o: %.cpp
	${CC} ${CCFLAGS} -c $<

%.h:
