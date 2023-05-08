# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(c1) begin
(c1) File opened
(c1) Cache reset
(c1) First read
(c1) Closed and reopened file.
(c1) Second read
(c1) Hit rate increased by at least factor of 2!
(c1) end
EOF
pass;