use Test2::V0;
use Bitcoin::Secp256k1;

################################################################################
# This tests whether the base methods defined in XS are working correctly
################################################################################

my $secp;

subtest 'constructor works' => sub {
	$secp = Bitcoin::Secp256k1->new();
	isa_ok $secp, 'Bitcoin::Secp256k1';
};

subtest 'can import and export pubkey' => sub {
	my $sample_pubkey = '0389261a9b1f32cfeaae8f29ad18c6e6a1f1ef3667ad6f9d55ce16d15e11995b78';
	my $sample_pubkey_unc =
		'0489261a9b1f32cfeaae8f29ad18c6e6a1f1ef3667ad6f9d55ce16d15e11995b78819dddb2afbff8248ea486eb9c2b9cf67c3ec0a6fb6ddf033a1b926f3937977b';
	my $pubkey_bytes = pack 'H*', $sample_pubkey;
	my $pubkey_unc_bytes = pack 'H*', $sample_pubkey_unc;

	is $secp->_pubkey, undef, 'starting pubkey ok';
	is $secp->_pubkey($pubkey_bytes), $pubkey_bytes, 'setter ok';
	is $secp->_pubkey, $pubkey_bytes, 'getter ok';
	is $secp->_pubkey(undef, 1), $pubkey_bytes, 'getter with explicit compression ok';
	is $secp->_pubkey(undef, 0), $pubkey_unc_bytes, 'getter with explicit (un)compression ok';
};

done_testing;

