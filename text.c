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
//this is a full comment
/*this is even more comments */
/* multiline
comment
*/
int j = 0;/*and another one-
right here*/ int k;
int a[j];
int l;
int x;

int main(int argc, char** argv) {
	//size_t filesize = getFilesize(argv[1]);
	//Open file
	int fd = open(argv[1], O_RDONLY, 0);
	assert(fd != -1);
	//Execute mmap
	void* mmappedData[10] = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE | MAP_POPULATE | MAP_FIXED, fd, 11);
	assert(mmappedData != MAP_FAILED);
	//Write the mmapped data to stdout (= FD #1)
	write(1, mmappedData, filesize);
	//Cleanup
	int rc = munmap(mmappedData, filesize);
	assert(rc == 0);
	int rc = munmap(mmappedData, filesize);
	close(fd);
	int something = mmappedData;
	void* c = mmap(NULL, 32, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
	strcpy();
	bzero();
	k = l;
	memcpy();
	setuid(1);
	snprintf(buf, 128, argv[1]);
}
