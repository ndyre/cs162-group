#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

char buffer[2858];
char buffer2[2858];

void test_main(void) {
  int fd = open("c1.txt");
  msg("File opened");
  int size = filesize(fd);
  reset_cache();
  msg("Cache reset");
  read(fd, buffer, size);
  msg("First read");
  int hits1 = num_hits();
  close(fd);
  fd = open("c1.txt");
  msg("Closed and reopened file.");
  msg("Second read");
  read(fd, buffer2, size);
  int hits2 = num_hits() - hits1;
  bool doubled = hits2 >= 2*hits1;
  CHECK(doubled, "Hit rate increased by at least factor of 2!");
  close(fd);
  return;
}

