//NOTE: This file compiles with no errors or warnings

#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <strings.h> 
size_t getFilesize(const char* filename) {
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}
//this is a full comment
/*this is even more comments */
/* multiline
comment
*/

int main(int argc, char** argv) {
	int j = 0;/*and another one-
	right here*/ int k;
	int a[j];
	void* l;
	int x;

	size_t filesize = getFilesize(argv[1]);
	//Open file
	int fd = open(argv[1], O_RDONLY, 0);
	assert(fd != -1);
	//Execute mmap
	char* mmappedData = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 11);
	assert(mmappedData != MAP_FAILED);
	//Write the mmapped data to stdout (= FD #1)
	write(1, mmappedData, filesize);
	//Cleanup
	int rc = munmap(mmappedData, filesize);
	assert(rc == 0);
	close(fd);
	void* c = mmap(NULL, 32, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
	strcpy(c, "hello world");
	bzero(l,x);
	setuid(1);
	char* buf;
	printf(buf, 128, argv[1]);
}
