use Test2::V0;
use Bitcoin::Secp256k1;
use Digest::SHA qw(sha256);

################################################################################
# This tests whether the base methods defined in XS are working correctly. Data
# from:
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
################################################################################

my $secp;

my $sample_privkey = pack 'H*',
	'619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9';
my $sample_pubkey = pack 'H*', '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357';
my $sample_pubkey_unc = pack 'H*',
	'045476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357fd57dee6b46a6b010a3e4a70961ecf44a40e18b279ec9e9fba9c1dbc64896198';
my $sample_preimage = pack 'H*',
	'0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000';
my $sample_sig = pack 'H*',
	'304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee';

subtest 'should create and destroy' => sub {
	$secp = Bitcoin::Secp256k1->new();
	isa_ok $secp, 'Bitcoin::Secp256k1';
};

subtest 'should import and export pubkey' => sub {
	is $secp->_pubkey, undef, 'starting pubkey ok';
	is $secp->_pubkey($sample_pubkey), $sample_pubkey, 'setter ok';
	is $secp->_pubkey, $sample_pubkey, 'getter ok';
	is $secp->_pubkey(undef, 1), $sample_pubkey, 'getter with explicit compression ok';
	is $secp->_pubkey(undef, 0), $sample_pubkey_unc, 'getter with explicit (un)compression ok';
	is $secp->_pubkey($sample_pubkey_unc), $sample_pubkey, 'setter with uncompressed input, compressed output ok';
};

subtest 'should import and export signature' => sub {
	is $secp->_signature, undef, 'starting sig ok';
	is $secp->_signature($sample_sig), $sample_sig, 'setter ok';
	is $secp->_signature, $sample_sig, 'getter ok';
};

subtest 'should verify a signature' => sub {
	my $sample_partial_digest = sha256($sample_preimage);
	my $sample_digest = sha256($sample_partial_digest);

	ok $secp->_verify($sample_digest), 'digest verification ok';
	ok !$secp->_verify($sample_partial_digest), 'incorrect digest verification failed ok';
};

subtest 'should generate a signature' => sub {
	my $sample_partial_digest = sha256($sample_preimage);
	my $sample_digest = sha256($sample_partial_digest);

	$secp->_sign($sample_privkey, $sample_partial_digest);
	isnt $secp->_signature, $sample_sig, 'incorrect digest signing failed ok';

	$secp->_sign($sample_privkey, $sample_digest);
	is $secp->_signature, $sample_sig, 'signing ok';
};

done_testing;

