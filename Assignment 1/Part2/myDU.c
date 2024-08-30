#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

long long int dir_space(char* basePath){
	struct stat fileStat;
	if(stat(basePath, &fileStat)==-1){	
		//stat unsuccessful
		printf("Unable to execute\n");
		exit(-1);
	}
	long long int size=fileStat.st_size;
	//Open the directory
    DIR *directory=opendir(basePath);
	if(directory==NULL){
		printf("Unable to execute\n");
		exit(-1);
	}
    struct dirent* ptr=readdir(directory);
	while(ptr){
		//Create the path to the subdirectory/subfiles/etc.
		char *subPath=(char *)malloc(sizeof(char)*4096);
		strcpy(subPath, basePath);
		strcat(subPath, "/");
		strcat(subPath, ptr->d_name);
		struct stat subFileStat;
		if(lstat(subPath, &subFileStat)==-1){	
			//lstat unsuccessful
			printf("Unable to execute\n");
			exit(-1);
		}
		if(S_ISDIR(subFileStat.st_mode)){	
			//handling sub-directories
			//If it's a directory, recursively calculate it's size
			if(strcmp(ptr->d_name, "..")==0 || strcmp(ptr->d_name, ".")==0){
				ptr=readdir(directory);
				continue;
		    }
            size+=dir_space(subPath);
		}
		else if(S_ISLNK(subFileStat.st_mode)){ 
			//handling symbolic-link
			//If it's symbolic link, recursively calculate the linked directory's size
			size+=dir_space(subPath);
		}
		else{	
			//handling files
			//If it's a file, add its size to the total
			size+=(long long int)subFileStat.st_size;
		}
		ptr=readdir(directory);
	}
    return size;
}

int main(int argc, char *argv[])
{
	if(argc<2){    
		//insufficient commands
		printf("Unable to execute\n");
		exit(-1);
	}
	int fd[2];
	if(pipe(fd)==-1){	
		//pipe unsuccessful
		printf("Unable to execute\n");
		exit(-1);
	}

	char* basePath=(char *)malloc(sizeof(char)*4096);
	strcat(basePath,argv[1]);
	struct stat baseStat;
	if(stat(basePath, &baseStat)==-1){	
		//stat unsuccessful
		printf("Unable to execute\n");
		exit(-1);
	}
	long long int size=baseStat.st_size;
	//Open the base directory
	DIR *directory=opendir(argv[1]);
	if(directory==NULL){
		printf("Unable to execute\n");
		exit(-1);
	}
	struct dirent* ptr=readdir(directory);
	while(ptr){
		//Create the path to the subdirectory/subfiles/etc.
		char *subPath=(char *)malloc(sizeof(char)*4096);
		strcpy(subPath, basePath);
		strcat(subPath, "/");
		strcat(subPath, ptr->d_name);
		struct stat subFileStat;
		if(lstat(subPath, &subFileStat)==-1){	
			//lstat unsuccessful
            printf("Unable to execute\n");
			exit(-1);
		}
		if(S_ISDIR(subFileStat.st_mode)){   
			//handling sub-directories
			//If it's a directory, fork to calculate size in the child process
			if(strcmp(ptr->d_name, "..")==0 || strcmp(ptr->d_name, ".")==0){
				ptr=readdir(directory);
				continue;
		    }
			int pid=fork();
			if(pid < 0){
				perror("fork");
				exit(-1);
			} 
			if(!pid){ 
				//Child process
				//Child process calculates size and writes to the pipe
				close(1);
				dup(fd[1]);
				size=dir_space(subPath);
                break;
			}
			else{ 
				// Parent process
				// Parent process waits for the child and adds its size to the total
				wait(NULL);
				char child_size[BUFSIZ];
				read(fd[0], child_size, sizeof(child_size));
				size+=atoi(child_size);
			}
		}
		else if(S_ISLNK(subFileStat.st_mode)){	 
			// handling symbolic-link
			//If it's symbolic link, recursively calculate the linked directory's size
			size+=dir_space(subPath);
		}
		else{	
			//handling files
			//If it's a file, add its size to the total 
			size+=(long long int)subFileStat.st_size;
		}
		ptr=readdir(directory);
	}
	printf("%lld\n", size);
	return 0;
}