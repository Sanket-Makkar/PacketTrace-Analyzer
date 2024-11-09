CC = gcc
CXX = g++
CFLAGS = -Wall -Werror -g
CXXFLAGS = $(CFLAGS)
LDFLAGS = $(CFLAGS)

TARGETS = proj4

all: $(TARGETS)

$(TARGETS): proj4.o ArgParser.o
	$(CXX) $(LDFLAGS) -o $@ $^

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $<

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o
	
distclean: clean
	rm -f $(TARGETS)

remake: distclean all