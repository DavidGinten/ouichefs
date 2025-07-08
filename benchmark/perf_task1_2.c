#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#define FILE_SIZE_MB 3
#define BUF_SIZE 4096
#define TEST_FILE "/mnt/testimg/testfile.txt"

double time_diff(struct timeval start, struct timeval end) {
	return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
}

int main() {
	int fd;
	char *buf = malloc(BUF_SIZE);
	memset(buf, 'A', BUF_SIZE);

	struct timeval start, end;

	// --- WRITE TEST ---
	fd = open(TEST_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open for write");
		return 1;
	}

	gettimeofday(&start, NULL);
	for (size_t i = 0; i < (FILE_SIZE_MB * 1024 * 1024) / BUF_SIZE; i++) {
		if (write(fd, buf, BUF_SIZE) != BUF_SIZE) {
			perror("write");
			close(fd);
			return 1;
		}
	}
	fsync(fd);  // Ensure everything is flushed to disk
	gettimeofday(&end, NULL);
	close(fd);

	printf("Write time: %.6f seconds\n", time_diff(start, end));
	//printf("%.6f", time_diff(start, end));

	// --- READ TEST ---
	fd = open(TEST_FILE, O_RDONLY);
	if (fd < 0) {
		perror("open for read");
		return 1;
	}

	gettimeofday(&start, NULL);
	ssize_t r;
	while ((r = read(fd, buf, BUF_SIZE)) > 0) {
		// simulate consuming the data
	}
	gettimeofday(&end, NULL);
	close(fd);

	printf("Read time: %.6f seconds\n", time_diff(start, end));
	//printf("%.6f", time_diff(start, end));

	free(buf);
	return 0;
}

