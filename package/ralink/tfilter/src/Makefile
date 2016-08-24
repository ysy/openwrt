CC ?= gcc

all: tfilter

tfilter:	main.c md5.c check.c
	@echo $(LDFLAGS)
	$(CC) -o $@  $(CFLAGS)  $^ $(LDFLAGS)
