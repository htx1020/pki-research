all:server client
.PHONY:all
 
server:server.c
	gcc $^ -o $@ -Wall -g -lssl -lcrypto
	
client:client.c
	gcc $^ -o $@ -Wall -g -lssl -lcrypto
 
.PHONY:clean
clean:
	rm -f server client
