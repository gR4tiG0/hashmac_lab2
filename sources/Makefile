CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lb2

TARGET = hellman
SRC = hellman.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
