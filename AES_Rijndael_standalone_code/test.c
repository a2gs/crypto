/*	$KAME: rijndaeltest.c,v 1.7 2001/05/27 01:56:45 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

#include "rijndael.h"
#include "rijndael-api-fst.h"

/* #include "dump.h" */

/* decrypt test */
struct {
	const char *key;
	const char *ct;
	const char *pt;
} dvector[] = {
    {
	"DE11FF0A429E1CD3DE016DAC294F771187463793E21C29525A3B282CDCAD6270",
	"E1268BA8A1473DEDE6CA64DDF2C8B805",
	"4DE0C6DF7CB1697284604D60271BC59A",
    },
};

/* encrypt test */
struct {
	const char *key;
	const char *pt;
	const char *ct;
} evector[] = {
    {
	/*
	"982D617A0F737342E99123A5A573D266F4961915B32DCA4118AD5CF1DCB6ED00",
	"6F8606BBA6CC03A5D0A64FE21E277B60",
	"1F6763DF807A7E70960D4CD3118E601A",
	*/
	"DE11FF0A429E1CD3DE016DAC294F771187463793E21C29525A3B282CDCAD6270",
	"4DE0C6DF7CB1697284604D60271BC59A",
	"E1268BA8A1473DEDE6CA64DDF2C8B805",
    },
};

static void hex2key(u_int8_t *, size_t, const char *);
int main(int, char **);

static void
hex2key(p, l, s)
	u_int8_t *p;
	size_t l;
	const char *s;
{
	size_t i;
	u_int v;

	for (i = 0; i < l && *s; i++) {
		sscanf(s, "%02x", &v);
		*p++ = v & 0xff;
		s += 2;
	}

	if (*s) {
		errx(1, "hex2key overrun");
		/*NOTREACHED*/
	}
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	int i, j;
	/*
	keyInstance k;
	cipherInstance c;
	*/
	/* unsigned char *hexbuff = NULL; */
	rijndaelKeyInstance k;
	rijndaelCipherInstance c;
	int error;
	const char *test;
	u_int8_t key[32], input[16], output[16], answer[16];

	error = 0;

	test = "decrypt test";
	i = 0;

printf("--- [%d %s] --------------------\n", i, test);

	memset(input, 0, sizeof(input));
	memset(output, 0, sizeof(output));
	memset(key, 0, sizeof(key));

	hex2key(key, sizeof(key), dvector[i].key);
	hex2key(input, sizeof(input), dvector[i].ct);
	hex2key(answer, sizeof(answer), dvector[i].pt);

/*
a2gs_ToolBox_DumpBuffer(key, sizeof(key), &hexbuff);
printf("key [%s] [%ld]:\n%s\n\n", dvector[i].key, sizeof(key), hexbuff);
free(hexbuff);

a2gs_ToolBox_DumpBuffer(input, sizeof(input), &hexbuff);
printf("input [%s] [%ld]:\n%s\n\n", dvector[i].ct, sizeof(input), hexbuff);
free(hexbuff);

a2gs_ToolBox_DumpBuffer(answer, sizeof(answer), &hexbuff);
printf("answer [%s] [%ld]:\n%s\n\n", dvector[i].pt, sizeof(answer), hexbuff);
free(hexbuff);
*/

	/* LINTED const cast */
	if (rijndael_makeKey(&k, DIR_DECRYPT, strlen(dvector[i].key) * 4, (char *)key) < 0) {
		printf("makeKey failed for %s %d\n", test, i);
		return(0);
	}

/*
a2gs_ToolBox_DumpBuffer(key, sizeof(key), &hexbuff);
printf("rijndael_makeKey() key [%s] [sizeof %ld/strlen %ld]:\n%s\n\n", dvector[i].key, sizeof(key), strlen(dvector[i].key) * 4, hexbuff);
free(hexbuff);
*/

	if (rijndael_cipherInit(&c, RIJNDAEL_MODE_ECB, NULL) < 0) {
		printf("cipherInit failed for %s %d\n", test, i);
		return(0);
	}

	for (j = 0; j < 10000; j++) {
		if (rijndael_blockDecrypt(&c, &k, input, sizeof(input) * 8, output) < 0) {
			printf("blockDecrypt failed for %s %d/%d\n", test, i, j);
			return(0);
		}

		memcpy(input, output, sizeof(input));
	}

/*
a2gs_ToolBox_DumpBuffer(output, sizeof(output), &hexbuff);
printf("output [%ld]:\n%s\n\n", sizeof(output), hexbuff);
free(hexbuff);
*/

	if (memcmp(output, answer, sizeof(output)) != 0) {
		printf("result mismatch for %s %d\n", test, i);
		return(0);
	}

	i = 0;

	test = "encrypt test";

printf("--- [%d %s] --------------------\n", i, test);
	memset(input, 0, sizeof(input));
	memset(output, 0, sizeof(output));
	memset(key, 0, sizeof(key));

	hex2key(key, sizeof(key), evector[i].key);
	hex2key(input, sizeof(input), evector[i].pt);
	hex2key(answer, sizeof(answer), evector[i].ct);

/*
a2gs_ToolBox_DumpBuffer(key, sizeof(key), &hexbuff);
printf("key [%s] [%ld]:\n%s\n\n", dvector[i].key, sizeof(key), hexbuff);
free(hexbuff);

a2gs_ToolBox_DumpBuffer(input, sizeof(input), &hexbuff);
printf("input [%s] [%ld]:\n%s\n\n", dvector[i].ct, sizeof(input), hexbuff);
free(hexbuff);

a2gs_ToolBox_DumpBuffer(answer, sizeof(answer), &hexbuff);
printf("answer [%s] [%ld]:\n%s\n\n", dvector[i].pt, sizeof(answer), hexbuff);
free(hexbuff);
*/

	/* LINTED const cast */
	if (rijndael_makeKey(&k, DIR_ENCRYPT, strlen(evector[i].key) * 4, (char *)key) < 0) {
		printf("makeKey failed for %s %d\n", test, i);
		return(0);
	}

/*
a2gs_ToolBox_DumpBuffer(key, sizeof(key), &hexbuff);
printf("rijndael_makeKey() key [%s] [sizeof %ld/strlen %ld]:\n%s\n\n", dvector[i].key, sizeof(key), strlen(dvector[i].key) * 4, hexbuff);
free(hexbuff);
*/

	if (rijndael_cipherInit(&c, RIJNDAEL_MODE_ECB, NULL) < 0) {
		printf("cipherInit failed for %s %d\n", test, i);
		return(0);
	}

	for (j = 0; j < 10000; j++) {
		if (rijndael_blockEncrypt(&c, &k, input, sizeof(input) * 8, output) < 0) {
			printf("blockEncrypt failed for %s %d/%d\n", test, i, j);
			return(0);
		}

		memcpy(input, output, sizeof(input));
	}

/*
a2gs_ToolBox_DumpBuffer(output, sizeof(output), &hexbuff);
printf("output [%ld]:\n%s\n\n", sizeof(output), hexbuff);
free(hexbuff);
*/

	if (memcmp(output, answer, sizeof(output)) != 0) {
		printf("result mismatch for %s %d\n", test, i);
		return(0);
	}

	exit(error);
}
