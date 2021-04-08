CXX       = g++
CXXFLAGS  = -Wall -pedantic -g
LIBS      = -lcrypto
TARGETS   = block

all: $(TARGETS)

block: block.cpp
	$(CXX) -std=c++11 $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGETS) *~ core
	rm -f examples/*_cbc_*
	rm -f examples/*_ecb_*
