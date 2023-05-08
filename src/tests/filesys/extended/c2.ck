# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-2) begin
(cache-2) Hit rate increased!
(cache-2) end
EOF
pass;