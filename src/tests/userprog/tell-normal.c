/*This test case opens the file sample.txt and calls the tell system
 call to retrieve the current position of the file. Then, it calls
 the seek system call to move the file position to 10 and calls
 tell again to verify the position change.*/
 #include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int fd;
  CHECK((fd = open("sample.txt")) > 1, "open \"sample.txt\"");

  int position = tell(fd);
  if (position != 0)
    fail("tell returned %d instead of %zu", position, 0);

  seek(fd, 10);
  position = tell(fd);

  if (position != 10)
    fail("tell returned %d instead of %zu", position, 10);
}