all: clean aes256cbc

aes256cbc:
	cc -o AES256_CBC AES256_CBC.c -lssl -lcrypto -g -Wall

clean:
	-rm AES256_CBC *.o core
