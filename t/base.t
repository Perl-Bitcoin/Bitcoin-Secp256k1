use Test2::V0;
use Bitcoin::Secp256k1;

################################################################################
# This tests whether blah blah blah
################################################################################

my $secp = Bitcoin::Secp256k1->new();
isa_ok $secp, 'Bitcoin::Secp256k1';

done_testing;

