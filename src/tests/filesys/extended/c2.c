#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
char buffer[65536];
void test_main(void) {
  int fd = open("c2.txt");
  int size = filesize(fd);
  int bytes_written= 0;
  while (bytes_written < 65536) {
    bytes_written = write(fd, buffer, size);
  }
//   msg("bytes read = %d", bytes_written);
}