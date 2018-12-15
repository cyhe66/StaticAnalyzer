#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
size_t getFilesize(const char* filename) {
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}
//this is a full comment strcpy();
// more comments
blah; // this is also a comment strcpy();
/*this is even more comments */
/* multiline
comment
*/

/* and we have another multiline comment here */
int j = 0;/*and another one-
right here*/ int k;
int a[j];
int x = a[j];
int l;
l = 12;
int x;

int main(int argc, char** argv) {
	size_t filesize = getFilesize(argv[1]);
	//Open file
	int fd = open(argv[1], O_RDONLY, 0);
	assert(fd != -1);
	//Execute mmap
	void* mmappedData = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
	assert(mmappedData != MAP_FAILED);
	//Write the mmapped data to stdout (= FD #1)
	write(1, mmappedData, filesize);
	//Cleanup
	int rc = munmap(mmappedData, filesize);
	assert(rc == 0);
	close(fd);
	strcpy();
	lstrcat();
	bzero();
	k = l;
	strcat();
	_tcsncpy();
	memcpy();
	setuid(1);
}
