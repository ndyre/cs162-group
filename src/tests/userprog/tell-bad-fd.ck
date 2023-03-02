# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(tell-bad-fd) begin
(tell-bad-fd) end
tell-bad-fd: exit(0)
EOF
(tell-bad-fd) begin
tell-bad-fd: exit(-1)
EOF
pass;
