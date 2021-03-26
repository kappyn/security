CXX       = g++
CXXFLAGS  = -Wall -pedantic -g
LIBS      = -lcrypto
TARGETS   = hash

all: $(TARGETS)

hash: hash.cpp
	$(CXX) -std=c++11 $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	\rm -f $(TARGETS) *~ core

