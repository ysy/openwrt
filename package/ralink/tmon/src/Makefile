CC ?= gcc

#LDFLAGS += -lxt_ACCOUNT_cl
all: tmon pptp_mon

tmon:	main.c md5.c check.c
	@echo $(LDFLAGS)
	$(CC) -o $@  $(CFLAGS)  $^ $(LDFLAGS)


pptp_mon: pptp_mon.c
	$(CC) -o $@  $(CFLAGS)  $^ 
