/* Tries to call tell with an invalid fd,
   which must either fail silently or terminate the process with
   exit code -1. */

#include <limits.h>
#include <syscall.h>
#include "tests/main.h"

void test_main(void) {
  tell(0x01012342);
  tell(7);
  tell(2546);
  tell(-5);
  tell(-8192);
  tell(INT_MIN + 1);
  tell(INT_MAX - 1);
}