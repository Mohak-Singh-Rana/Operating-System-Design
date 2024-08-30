#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char *argv[])
{
	long long int n ;
	n = atoi(argv[argc-1]);
	n = n*2;
	sprintf(argv[argc-1],"%lld",n);
	if(argc<2){
		printf("Unable to execute\n");
	}
	else if(argc==2){
		printf("%lld\n", n);
	}
	else {
		argv=argv+1;
	    if(execv(argv[0],argv)!=0){
			printf("Unable to execute\n");
		}
	}
	return 0;
}