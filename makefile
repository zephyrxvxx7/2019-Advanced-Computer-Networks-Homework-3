compiler = gcc
obj = main.o arp.o

all: $(obj)
	$(compiler) -o arp $(obj)

%.o: %.c
	$(compiler) -c $^ -o $@

.PHONY: clean
clean:
	rm *.o