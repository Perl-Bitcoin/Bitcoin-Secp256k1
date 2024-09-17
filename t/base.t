use Test2::V0;
use Bitcoin::Secp256k1;
use Digest::SHA qw(sha256);

use lib 't/lib';
use Secp256k1Test;

################################################################################
# This tests whether the base methods defined in XS are working correctly.
################################################################################

my $secp;
my %t = Secp256k1Test->test_data;

my $partial_digest = sha256($t{preimage});
my $digest = sha256($partial_digest);

subtest 'should create and destroy' => sub {
	$secp = Bitcoin::Secp256k1->new();
	isa_ok $secp, 'Bitcoin::Secp256k1';
};

subtest 'should import and export pubkey' => sub {
	is $secp->_pubkey, undef, 'starting pubkey ok';
	is $secp->_pubkey($t{pubkey}), $t{pubkey}, 'setter ok';
	is $secp->_pubkey, $t{pubkey}, 'getter ok';
	is $secp->_pubkey(undef, 1), $t{pubkey}, 'getter with explicit compression ok';
	is $secp->_pubkey(undef, 0), $t{pubkey_unc}, 'getter with explicit (un)compression ok';
	is $secp->_pubkey($t{pubkey_unc}), $t{pubkey}, 'setter with uncompressed input, compressed output ok';
};

subtest 'should import and export signature' => sub {
	is $secp->_signature, undef, 'starting sig ok';
	is $secp->_signature($t{sig}), $t{sig}, 'setter ok';
	is $secp->_signature, $t{sig}, 'getter ok';
};

subtest 'should generate a public key' => sub {
	$secp->_clear;
	is $secp->_pubkey, undef, 'cleared pubkey ok';

	$secp->_create_pubkey($t{privkey});
	is $secp->_pubkey, $t{pubkey}, 'pubkey ok';
};

subtest 'should verify a signature' => sub {
	$secp->_pubkey($t{pubkey});
	$secp->_signature($t{sig});

	ok $secp->_verify($digest), 'digest verification ok';
	ok !$secp->_verify($partial_digest), 'incorrect digest verification failed ok';
};

subtest 'should generate a signature' => sub {
	$secp->_sign($t{privkey}, $partial_digest);
	isnt $secp->_signature, $t{sig}, 'incorrect digest signing failed ok';

	$secp->_sign($t{privkey}, $digest);
	is $secp->_signature, $t{sig}, 'signing ok';
};

subtest 'should normalize a signature' => sub {
	$secp->_signature($t{sig_unn});

	ok $secp->_normalize, 'signature normalized ok';
	is $secp->_signature, $t{sig}, 'signature ok';
	ok !$secp->_normalize, 'already normalized ok';
};

done_testing;

