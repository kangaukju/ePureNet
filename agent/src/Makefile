agent: agent.c system.o hash.o
	cc agent.c system.o hash.o  -o ../agent -D_REENTRANT -L/usr/lib/mysql -I/usr/include/mysql -lmysqlclient -lpthread -lpcap

system.o : system.c
	cc system.c -c

hash.o : hash.c
	cc hash.c -c

clean:
	rm -fr *.o
	rm -fr ../agent
