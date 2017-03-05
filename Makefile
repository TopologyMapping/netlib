all: compile testlib.c
	gcc -Wall -g testsend.c *.o -lpcap -lnet -lpthread -lrt -o testsend
	gcc -Wall -g testlib.c *.o -lpcap -lnet -lpthread -lrt -o testlib

compile: *.c
	gcc -g -Wall -c dstructs/timespec.c
	gcc -g -Wall -c dstructs/dlist.c
	gcc -g -Wall -c dstructs/pavl.c
	gcc -g -Wall -c log/log.c
	gcc -g -Wall -c log/cyc.c
	gcc -g -Wall -c packet.c
	gcc -g -Wall -c sniffer.c
	gcc -g -Wall -c demux.c
	gcc -g -Wall -c sender4.c
	gcc -g -Wall -c sender6.c
	gcc -g -Wall -c confirm.c

clean:
	rm -rf *.o testsend testlib log.txt.0
