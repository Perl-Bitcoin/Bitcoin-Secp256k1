use Test2::V0;
use Bitcoin::Secp256k1;
use Digest::SHA qw(sha256);

################################################################################
# This tests whether the base methods defined in XS are working correctly. Data
# from:
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
################################################################################

my $secp;

subtest 'constructor works' => sub {
	$secp = Bitcoin::Secp256k1->new();
	isa_ok $secp, 'Bitcoin::Secp256k1';
};

subtest 'can import and export pubkey' => sub {
	my $sample_pubkey = '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357';
	my $sample_pubkey_unc =
		'045476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357fd57dee6b46a6b010a3e4a70961ecf44a40e18b279ec9e9fba9c1dbc64896198';
	my $pubkey_bytes = pack 'H*', $sample_pubkey;
	my $pubkey_unc_bytes = pack 'H*', $sample_pubkey_unc;

	is $secp->_pubkey, undef, 'starting pubkey ok';
	is $secp->_pubkey($pubkey_bytes), $pubkey_bytes, 'setter ok';
	is $secp->_pubkey, $pubkey_bytes, 'getter ok';
	is $secp->_pubkey(undef, 1), $pubkey_bytes, 'getter with explicit compression ok';
	is $secp->_pubkey(undef, 0), $pubkey_unc_bytes, 'getter with explicit (un)compression ok';
	is $secp->_pubkey($pubkey_unc_bytes), $pubkey_bytes, 'setter with uncompressed input, compressed output ok';
};

subtest 'can import and export signature' => sub {
	my $sample_sig =
		'304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee';
	my $sig_bytes = pack 'H*', $sample_sig;

	is $secp->_signature, undef, 'starting sig ok';
	is $secp->_signature($sig_bytes), $sig_bytes, 'setter ok';
	is $secp->_signature, $sig_bytes, 'getter ok';
};

subtest 'can verify a signature' => sub {
	my $sample_preimage =
		'0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000';
	my $sample_partial_digest = sha256(pack 'H*', $sample_preimage);
	my $sample_digest = sha256($sample_partial_digest);

	ok $secp->_verify($sample_digest), 'digest verification ok';
	ok !$secp->_verify($sample_partial_digest), 'incorrect digest verification failed ok';
};

done_testing;

