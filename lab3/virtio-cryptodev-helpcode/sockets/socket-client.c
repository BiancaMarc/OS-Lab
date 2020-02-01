/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */
#include <sys/poll.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket-common.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <crypto/cryptodev.h>
#define TIMEOUT 1
#define	KEY_SIZE	16

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port,po,cfd=-1;
	ssize_t n;
	unsigned char buf[BUF_SIZE];
	unsigned char crypbuf[BUF_SIZE];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	int ret;
	struct pollfd fds[2];

	

	if (argc != 4) {
		fprintf(stderr, "Usage: %s hostname port key\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	//strncpy(buf, HELLO_THERE, sizeof(buf));
	//buf[sizeof(buf) - 1] = '\0';

	/* Say something... */
	//if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) {
	//	perror("write");
	//	exit(1);
	//}
	//fprintf(stdout, "I said:\n%s\nRemote says:\n", buf);
	//fflush(stdout);

	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	/*
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	*/

	//CRYPTO
	cfd = open("/dev/crypto", O_RDWR,0);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}
	

	unsigned char key[KEY_SIZE] = "abdcabcdabcdabcd";
	unsigned char iv[BLOCK_SIZE]="abcdefghabcdefgh";

	//memcpy(key, argv[3], 16);

	struct session_op sess_op;
	memset(&sess_op,0,sizeof(sess_op));
	sess_op.key = key;
	sess_op.cipher = CRYPTO_AES_CBC;
	sess_op.keylen = KEY_SIZE;
	
		
	struct crypt_op cryp;
	memset(&cryp, 0, sizeof(cryp));
	cryp.iv = (void*)iv;
	

	if (ioctl(cfd, CIOCGSESSION, &sess_op)) {
			perror("ioctl");
			exit(1);
	}
	cryp.ses = sess_op.ses;
	cryp.len = BUF_SIZE;
	//CRYPTO

	fds[0].fd = 0;
	fds[0].events = POLLIN;

	fds[1].fd = sd;
	fds[1].events = POLLIN;

	/* Read answer and write it to standard output */
	for (;;) {
		ret = poll(fds, 2, 5000);
        if (ret){
        	if (fds[1].revents == POLLIN){
        		n = read(sd, buf, sizeof(buf));
        		if (n<=0){
					if (n < 0) {
						perror("read");
						exit(1);
					}
					else 
						fprintf(stderr,"Peer went away");
					break;
				}
				//insist_write(1,buf,n);
				//decrypt
				cryp.src = buf;
				cryp.ses = sess_op.ses;
				cryp.dst = crypbuf;
				cryp.len = sizeof(buf);
				cryp.iv = (void*)iv;
				cryp.op = COP_DECRYPT;
				if (ioctl(cfd, CIOCCRYPT ,&cryp)){
					perror("ioctl");
					exit(1);
				}
				fprintf(stderr, "He said: ");
				if (insist_write(1, crypbuf,sizeof(crypbuf)) != sizeof(crypbuf)) {
					perror("write");
					exit(1);
				}
				

        	}
        	if (fds[0].revents == POLLIN){
        		n = read(0,buf,sizeof(buf));
        		for(po=n;po<BUF_SIZE;po++)
        			buf[po]='\0';
        		//encrypt
        		//insist_write(sd,buf,n);
        		cryp.iv = (void*)iv;
        		cryp.ses = sess_op.ses;
        		cryp.src = buf;
				cryp.dst = crypbuf;
				cryp.len = sizeof(buf);
				cryp.op = COP_ENCRYPT;
				if (ioctl(cfd, CIOCCRYPT,&cryp)){
					perror("ioctl");
					exit(1);
				}
        		insist_write(sd,crypbuf,sizeof(crypbuf));
			}
        }	
		
	}

	fprintf(stderr, "\nDone.\n");
	return 0;
}
