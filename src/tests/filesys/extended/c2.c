#include <syscall.h>
#include <random.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FILE_SIZE 64000
#define MAX_WRITES 1000
char buffer1[FILE_SIZE];
char buffer2[FILE_SIZE];
int one_byte = 1;

void test_main(void) {
  int fd_a;
  int bytes_written;
  int bytes_read;
  int writes;
  random_init(0);
  random_bytes(buffer1, sizeof buffer1);

  CHECK(create("a", 0), "create \"a\"");

  CHECK((fd_a = open("a")) > 1, "open \"a\"");

  /* Write bytes to a file one at a time */
  for (int i = 0; i < FILE_SIZE; i++) {
    bytes_written = write(fd_a, buffer1, one_byte);
    if (bytes_written != one_byte) {
      fail("Not enough bytes written");
    }
  }
  /* Reset offset */
  seek(fd_a, 0);
  
  /* Read bytes one at a time */
  for (int i = 0; i < FILE_SIZE; i++) {
    bytes_read = read(fd_a, buffer2, one_byte);
    if (bytes_read != one_byte) {
      fail("Not enough bytes read");
    }
  }

  /* Get device writes */
  writes = device_writes();
  CHECK(writes < MAX_WRITES, "Too many device writes!");
}