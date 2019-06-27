all: clean aes256cbc sha256

aes256cbc:
	cc -o AES256_CBC AES256_CBC.c -lssl -lcrypto -g -Wall

sha256:
	cc -o SHA256 SHA256.c -lssl -lcrypto -g -Wall

clean:
	-rm AES256_CBC SHA256 *.o core
