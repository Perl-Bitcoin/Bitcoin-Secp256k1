use Test2::V0;
use Bitcoin::Secp256k1;
use Digest::SHA qw(sha256);

use lib 't/lib';
use Secp256k1Test;

################################################################################
# This tests whether high level Perl API is working correctly.
################################################################################

my $secp = Bitcoin::Secp256k1->new;
my %t = Secp256k1Test->test_data;

subtest 'should verify a private key' => sub {
	ok $secp->verify_private_key("\x12" x 32), 'verification ok';
	ok !$secp->verify_private_key("\xff" x 32), 'larger than curve order ok';
	ok !$secp->verify_private_key("\xff" x 31), 'not 32 bytes ok';
};

subtest 'should derive a public key' => sub {
	is $secp->create_public_key($t{privkey}), $t{pubkey}, 'pubkey derived ok';
};

subtest 'should compress a public key' => sub {
	is $secp->compress_public_key($t{pubkey_unc}), $t{pubkey}, 'pubkey compressed ok';
	is $secp->compress_public_key($t{pubkey}), $t{pubkey}, 'compressed pubkey intact ok';

	is $secp->compress_public_key($t{pubkey}, 0), $t{pubkey_unc}, 'pubkey uncompressed ok';
	is $secp->compress_public_key($t{pubkey_unc}, 0), $t{pubkey_unc}, 'uncompressed pubkey intact ok';
};

subtest 'should normalize a signature' => sub {
	is $secp->normalize_signature($t{sig_unn}), $t{sig}, 'signature normalized ok';
	is $secp->normalize_signature($t{sig}), $t{sig}, 'normalized signature intact ok';
};

subtest 'should sign and verify a message' => sub {
	is $secp->sign_message($t{privkey}, $t{preimage}), $t{sig}, 'message signed ok';
	ok $secp->verify_message($t{pubkey}, $t{sig}, $t{preimage}), 'message verified ok';

	is warns {
		ok $secp->verify_message($t{pubkey}, $t{sig_unn}, $t{preimage}), 'unnormalized signature verified ok';
	}, 1, 'unnormalized signature warning ok';
};

subtest 'should sign and verify a digest' => sub {
	is $secp->sign_digest($t{privkey}, sha256(sha256($t{preimage}))), $t{sig}, 'digest signed ok';
	ok $secp->verify_digest($t{pubkey}, $t{sig}, sha256(sha256($t{preimage}))), 'digest verified ok';

	is warns {
		ok $secp->verify_digest($t{pubkey}, $t{sig_unn}, sha256(sha256($t{preimage}))),
			'unnormalized signature verified ok';
	}, 1, 'unnormalized signature warning ok';
};

done_testing;

