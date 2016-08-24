CC ?= gcc

all: tbw

tbw:	main.c md5.c check.c
	@echo $(LDFLAGS)
	$(CC) -o $@  $(CFLAGS)  $^ $(LDFLAGS)
