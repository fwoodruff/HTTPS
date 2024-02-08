
INC = . $(dir $(wildcard */.)) $(dir $(wildcard */*/.)) $(dir $(wildcard */*/*/.)) 
INCLUDES=$(INC:%=-I%) 

CXX = g++
CXXFLAGS = -pthread -O2 -std=gnu++2a -Wall -Wno-psabi $(INCLUDES)
LDFLAGS := -pthread
SOURCE := $(wildcard *.cpp) $(wildcard */*.cpp) $(wildcard */*/*.cpp) $(wildcard */*/*/*.cpp)
OBJECTS := ${SOURCE:.cpp=.o}
DEPENDS = ${OBJECTS:.o=.d}    # substitutes ".o" with ".d"
EXEC = codeymccodeface                # executable name


${EXEC} : ${OBJECTS} # link step
	${CXX} ${OBJECTS} ${LDFLAGS} -o ${EXEC}


-include ${DEPENDS}          # copies files x.d, y.d, z.d (if they exist)

clean:
	rm -f *.o
	rm -f */*.o
	rm -f */*/*.o
	rm -f */*/*/*.o
	rm ${EXEC}