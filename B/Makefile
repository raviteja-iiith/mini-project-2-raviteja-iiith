CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap
TARGET = cshark

SRCS = main.c parser.c inspect.c
OBJS = $(SRCS:.c=.o)
HEADERS = cshark.h parser.h

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild