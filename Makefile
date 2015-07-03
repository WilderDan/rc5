CC=gcc
CFLAGS=-c -g

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

EXECUTABLE=rc5

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)  
	$(CC) $(OBJECTS) -o $(EXECUTABLE) 

obj/%.o: src/%.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean

clean:
	rm $(OBJECTS) $(EXECUTABLE)
