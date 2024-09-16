#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <secp256k1.h>

#define CURVE_SIZE 32

typedef struct {
	secp256k1_context* ctx;
	secp256k1_pubkey* pubkey;
	secp256k1_ecdsa_signature* signature;
} secp256k1_perl;

void secp256k1_perl_replace_pubkey(secp256k1_perl *perl_ctx, secp256k1_pubkey *new_pubkey);
void secp256k1_perl_replace_signature(secp256k1_perl *perl_ctx, secp256k1_ecdsa_signature *new_signature);

secp256k1_perl* secp256k1_perl_create(unsigned char *randomize, size_t len)
{
	secp256k1_context *secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (len != CURVE_SIZE || !secp256k1_context_randomize(secp_ctx, randomize)) {
		secp256k1_context_destroy(secp_ctx);
		croak("Failed to randomize secp256k1 context");
	}

	secp256k1_perl *perl_ctx = malloc(sizeof *perl_ctx);
	perl_ctx->ctx = secp_ctx;
	perl_ctx->pubkey = NULL;
	perl_ctx->signature = NULL;
	return perl_ctx;
}

void secp256k1_perl_destroy(secp256k1_perl *perl_ctx)
{
	secp256k1_perl_replace_pubkey(perl_ctx, NULL);
	secp256k1_perl_replace_signature(perl_ctx, NULL);
	secp256k1_context_destroy(perl_ctx->ctx);
	free(perl_ctx);
}

void secp256k1_perl_replace_pubkey(secp256k1_perl *perl_ctx, secp256k1_pubkey *new_pubkey)
{
	if (perl_ctx->pubkey != NULL) {
		free(perl_ctx->pubkey);
	}

	perl_ctx->pubkey = new_pubkey;
}

void secp256k1_perl_replace_signature(secp256k1_perl *perl_ctx, secp256k1_ecdsa_signature *new_signature)
{
	if (perl_ctx->signature != NULL) {
		free(perl_ctx->signature);
	}

	perl_ctx->signature = new_signature;
}

secp256k1_perl* ctx_from_sv(SV* self)
{
	return (secp256k1_perl*) SvIV(SvRV(self));
}

/* XS code below */

MODULE = Bitcoin::Secp256k1				PACKAGE = Bitcoin::Secp256k1

PROTOTYPES: DISABLED

SV*
new(classname)
		SV *classname
	CODE:
		/* Calling Bytes::Random::Secure to randomize context */
		dSP;
		PUSHMARK(SP);

		SV *tmp = newSViv(CURVE_SIZE);

		EXTEND(SP, 1);
		PUSHs(tmp);
		PUTBACK;

		size_t count = call_pv("Bytes::Random::Secure::random_bytes", G_SCALAR);
		SvREFCNT_dec(tmp);

		SPAGAIN;

		if (count != 1) {
			croak("Calling Bytes::Random::Secure::random_bytes went wrong in Bitcoin::Secp256k1::new");
		}

		tmp = POPs;
		PUTBACK;

		STRLEN len;
		unsigned char *randomize = (unsigned char*) SvPVbyte(tmp, len);

		/* Randomness dump */
		/* for (int i = 0; i < len; ++i) { warn("%d: %d", i, randomize[i]); } */

		secp256k1_perl* ctx = secp256k1_perl_create(randomize, len);

		/* Blessing the object */
		SV *secp_sv = newSViv(0);
		RETVAL = sv_setref_iv(secp_sv, SvPVbyte_nolen(classname), (unsigned long) ctx);
		SvREADONLY_on(secp_sv);
	OUTPUT:
		RETVAL

# Clears public key and signature from the object
void
_clear(self)
		SV *self
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);
		secp256k1_perl_replace_pubkey(ctx, NULL);
		secp256k1_perl_replace_signature(ctx, NULL);

# Getter / setter for the public key
SV*
_pubkey(self, ...)
		SV *self
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);
		if (items > 1 && SvOK(ST(1))) {
			SV *new_pubkey = ST(1);
			if (SvROK(new_pubkey)) {
				croak("public key must not be a reference");
			}

			size_t key_size;
			unsigned char *key = (unsigned char*) SvPVbyte(new_pubkey, key_size);

			secp256k1_pubkey *result_pubkey = malloc(sizeof *result_pubkey);
			int result = secp256k1_ec_pubkey_parse(
				ctx->ctx,
				result_pubkey,
				key,
				key_size
			);

			if (!result) {
				free(result_pubkey);
				croak("the input does not appear to be a valid public key");
			}

			secp256k1_perl_replace_pubkey(ctx, result_pubkey);
		}

		unsigned int compression = SECP256K1_EC_COMPRESSED;

		if (items > 2 && !SvTRUE(ST(2))) {
			compression = SECP256K1_EC_UNCOMPRESSED;
		}

		if (ctx->pubkey != NULL) {
			unsigned char key_output[65];
			size_t key_size = 65;
			secp256k1_ec_pubkey_serialize(
				ctx->ctx,
				key_output,
				&key_size,
				ctx->pubkey,
				compression
			);

			RETVAL = newSVpv((char*) key_output, key_size);
		}
		else {
			RETVAL = &PL_sv_undef;
		}
	OUTPUT:
		RETVAL

# Getter / setter for the signature
SV*
_signature(self, ...)
		SV *self
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);
		if (items > 1 && SvOK(ST(1))) {
			SV *new_signature = ST(1);
			if (SvROK(new_signature)) {
				croak("signature must not be a reference");
			}

			size_t signature_size;
			unsigned char *signature = (unsigned char*) SvPVbyte(new_signature, signature_size);

			secp256k1_ecdsa_signature *result_signature = malloc(sizeof *result_signature);
			int result = secp256k1_ecdsa_signature_parse_der(
				ctx->ctx,
				result_signature,
				signature,
				signature_size
			);

			if (!result) {
				free(result_signature);
				croak("the input does not appear to be a valid signature");
			}

			secp256k1_perl_replace_signature(ctx, result_signature);
		}

		if (ctx->signature != NULL) {
			unsigned char signature_output[72];
			size_t signature_size = 72;
			secp256k1_ecdsa_signature_serialize_der(
				ctx->ctx,
				signature_output,
				&signature_size,
				ctx->signature
			);

			RETVAL = newSVpv((char*) signature_output, signature_size);
		}
		else {
			RETVAL = &PL_sv_undef;
		}
	OUTPUT:
		RETVAL

# Creates a public key from a private key
void
_create_pubkey(self, privkey)
		SV *self
		SV *privkey
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);

		size_t seckey_size;
		unsigned char *seckey_str = (unsigned char*) SvPVbyte(privkey, seckey_size);
		if (seckey_size != CURVE_SIZE) {
			croak("creating a pubkey requires a 32-byte secret key");
		}

		secp256k1_pubkey *result_pubkey = malloc(sizeof *result_pubkey);
		int result = secp256k1_ec_pubkey_create(
			ctx->ctx,
			result_pubkey,
			seckey_str
		);

		if (!result) {
			free(result_pubkey);
			croak("creating pubkey failed (invalid private key?)");
		}

		secp256k1_perl_replace_pubkey(ctx, result_pubkey);

# Normalizes a signature. Returns false value if signature was already normalized
SV*
_normalize(self)
		SV *self
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);
		if (ctx->signature == NULL) {
			croak("normalization requires a signature");
		}

		secp256k1_ecdsa_signature *result_signature = malloc(sizeof *result_signature);
		int result = secp256k1_ecdsa_signature_normalize(
			ctx->ctx,
			result_signature,
			ctx->signature
		);

		secp256k1_perl_replace_signature(ctx, result_signature);
		RETVAL = result ? &PL_sv_yes : &PL_sv_no;
	OUTPUT:
		RETVAL

# Verifies a signature
SV*
_verify(self, message)
		SV *self
		SV *message
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);
		if (ctx->pubkey == NULL || ctx->signature == NULL) {
			croak("verification requires both pubkey and signature");
		}

		size_t message_size;
		unsigned char *message_str = (unsigned char*) SvPVbyte(message, message_size);

		if (message_size != CURVE_SIZE) {
			croak("verification requires a 32-byte message hash");
		}

		int result = secp256k1_ecdsa_verify(
			ctx->ctx,
			ctx->signature,
			message_str,
			ctx->pubkey
		);

		RETVAL = result ? &PL_sv_yes : &PL_sv_no;
	OUTPUT:
		RETVAL

# Signs a digest
void
_sign(self, privkey, message)
		SV* self
		SV* privkey
		SV* message
	CODE:
		secp256k1_perl *ctx = ctx_from_sv(self);

		size_t message_size;
		unsigned char *message_str = (unsigned char*) SvPVbyte(message, message_size);
		if (message_size != CURVE_SIZE) {
			croak("signing requires a 32-byte message hash");
		}

		size_t seckey_size;
		unsigned char *seckey_str = (unsigned char*) SvPVbyte(privkey, seckey_size);
		if (seckey_size != CURVE_SIZE) {
			croak("signing requires a 32-byte secret key");
		}

		secp256k1_ecdsa_signature *result_signature = malloc(sizeof *result_signature);
		int result = secp256k1_ecdsa_sign(
			ctx->ctx,
			result_signature,
			message_str,
			seckey_str,
			NULL,
			NULL
		);

		if (!result) {
			free(result_signature);
			croak("signing failed (nonce generation problem?)");
		}

		secp256k1_perl_replace_signature(ctx, result_signature);

void
DESTROY(self)
		SV *self
	CODE:
		secp256k1_perl_destroy(ctx_from_sv(self));

BOOT:
	secp256k1_selftest();

