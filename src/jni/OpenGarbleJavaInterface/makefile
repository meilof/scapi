# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-openssl

# compilation options
CXX=g++
CXXFLAGS=-fPIC -maes

# openssl dependency
OPENGARBLE_INCLUDES = -I$(prefix)/include
OPENGARBLE_LIB_DIR = -L$(prefix)/lib
OPENGARBLE_LIB = -lOpenGarble

SOURCES = ScNativeGarbledBooleanCircuit.cpp
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libOpenGarbleJavaInterface$(JNI_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES) $(JAVA_INCLUDES) $(OPENGARBLE_INCLUDES) \
	$(OPENGARBLE_LIB_DIR) $(INCLUDE_ARCHIVES_START) $(OPENGARBLE_LIB) $(INCLUDE_ARCHIVES_END)

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< $(OPENGARBLE_INCLUDES) $(JAVA_INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
	rm -f *.dylib
	rm -f *.jnilib

