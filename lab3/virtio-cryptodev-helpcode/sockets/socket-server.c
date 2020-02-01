/*
 * socket-server.c
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

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

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
	unsigned char buf[BUF_SIZE];
	//char newbuf[BUF_SIZE];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd,ret,cfd,po;
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;
	struct pollfd fds[2];
	unsigned char crypbuf[BUF_SIZE];
	
	if (argc != 2) {
		fprintf(stderr, "Usage: %s key\n", argv[0]);
		exit(1);
	}
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		//listen(sd,TCP_BACKLOG);
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		/* We break out of the loop when the remote peer goes away */

		//CRYPTO
		cfd = open("/dev/crypto", O_RDWR,0);
		if (cfd < 0) {
			perror("open(/dev/crypto)");
			return 1;
		}
		unsigned char iv[BLOCK_SIZE]="abcdefghabcdefgh";

		unsigned char key[KEY_SIZE] = "abdcabcdabcdabcd";
		//memcpy(key, argv[1], 16);
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
		
		//fds[1].revents = 0;
		for (;;) {
			fds[0].fd = 0;
			fds[0].events = POLLIN;
			//fds[0].revents = 0;
			fds[1].fd = newsd;
			fds[1].events = POLLIN;
			//continue;
        	ret = poll(fds,2,5000);
        	//printf("%d\n",ret);
        	if (ret){
        		if(fds[0].revents == POLLIN){ 		//input apo plik
					n = read(0,buf,sizeof(buf));
					//insist_write(newsd,buf,n);
					for(po=n;po<BUF_SIZE;po++)
        				buf[po]='\0';
					//encrypt
	        		cryp.ses = sess_op.ses;
	        		cryp.src = buf;
					cryp.dst = crypbuf;
					cryp.len = sizeof(buf);
					cryp.iv = (void*)iv;
					cryp.op = COP_ENCRYPT;
					if (ioctl(cfd, CIOCCRYPT,&cryp)){
						perror("ioctl");
						exit(1);
					}
					insist_write(newsd,crypbuf,sizeof(crypbuf));
				}
        		if (fds[1].revents == POLLIN){		//input apo socket
        			n = read(newsd, buf, sizeof(buf));
					if (n <= 0) {
						if (n < 0)
							perror("read from remote peer failed");
						break;
					}
					else {
						//insist_write(1,buf,n);
						//decrypt
						cryp.ses = sess_op.ses;
						cryp.src = buf;
						cryp.dst = crypbuf;
						cryp.iv = (void*)iv;
						cryp.len = sizeof(buf);
						cryp.op = COP_DECRYPT;
						if (ioctl(cfd, CIOCCRYPT ,&cryp)){
							perror("ioctl(decrypt)");
							exit(1);
						}
						if (crypbuf[0]=='\0')
							break;
						fprintf(stderr, "He said: ");
						if (insist_write(1, crypbuf, sizeof(crypbuf)) != sizeof(crypbuf)) {
							perror("write to remote peer failed");
							break;
						}
						
					}
				}
				
			}
		}	
	}		
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	

	/* This will never happen */
	return 1;
}

