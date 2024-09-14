use Test2::V0;
use Bitcoin::Secp256k1;

use constant HAS_TEST_MEMORYGROWTH => eval { require Test::MemoryGrowth; 1 };
plan skip_all => 'This test requires Test::MemoryGrowth module'
	unless HAS_TEST_MEMORYGROWTH;

################################################################################
# This tests whether Bitcoin::Secp256k1 leaks memory (constructor / destructor)
################################################################################

Test::MemoryGrowth::no_growth {
	my $secp = Bitcoin::Secp256k1->new;
} 'construction/destruction of Bitcoin::Secp256k1 does not leak';

done_testing;

