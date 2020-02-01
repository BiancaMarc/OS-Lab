#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char ** argv){
	int fd, chars, i;

	fd = open(argv[1], O_RDONLY);
	if(fd<0){
		perror("Could not open file");
		exit(1);
	}

	chars = (int) *argv[2];

	char buffer[20];

	pid_t pid = fork();
	if(pid==0){
		while(1){
			ssize_t cnt = read(fd, buffer, chars);
			//pid_t pid1=getpid();
			printf("Child. pid = %ld\n", (long) pid);
			if(cnt < 0){
				perror("Could not read from file");
				exit(2);
			}
			for(i=0; i<cnt; i++)
				printf("%c", buffer[i]);
		}
	return 0;
	}

	while(1){
		ssize_t cnt = read(fd, buffer, chars);
		//pid_t pid1=getpid();
		printf("Parent. pid = %ld\n", (long) pid);
		if(cnt < 0){
			perror("Could not read from file");
			exit(2);
		}
		for(i=0; i<cnt; i++)
			printf("%c", buffer[i]);
	}

	return 0;
}

