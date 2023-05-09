# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(c2) begin
(c2) create "a"
(c2) open "a"
(c2) Too many device writes!
(c2) end
EOF
pass;
