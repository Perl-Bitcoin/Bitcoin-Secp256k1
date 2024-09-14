#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <secp256k1.h>

#define CURVE_SIZE 32

secp256k1_context* ctx_from_perl(SV* self)
{
	return (secp256k1_context*) SvIV(SvRV(self));
}

/* XS code below */

MODULE = Bitcoin::Secp256k1				PACKAGE = Bitcoin::Secp256k1

PROTOTYPES: DISABLED

SV*
new(classname)
		SV *classname
	CODE:
		secp256k1_context *secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

		/* Calling Bytes::Random::Secure to randomize context */
		dSP;
		PUSHMARK(SP);

		SV *tmp = newSViv(CURVE_SIZE);

		EXTEND(SP, 1);
		PUSHs(tmp);
		PUTBACK;

		int count = call_pv("Bytes::Random::Secure::random_bytes", G_SCALAR);
		SvREFCNT_dec(tmp);

		SPAGAIN;

		if (count != 1) {
			croak("Calling Bytes::Random::Secure::random_bytes went wrong in Bitcoin::Secp256k1::new");
		}

		tmp = POPs;
		STRLEN len;
		unsigned char *randomize = SvPVbyte(tmp, len);
		if (len != CURVE_SIZE || !secp256k1_context_randomize(secp_ctx, randomize)) {
			croak("Failed to randomize secp256k1 context");
		}

		/* Randomness dump */
		/* for (int i = 0; i < len; ++i) { warn("%d: %d", i, randomize[i]); } */

		PUTBACK;

		/* Blessing the object */
		SV *secp_sv = newSViv(0);
		RETVAL = sv_setref_iv(secp_sv, SvPVbyte_nolen(classname), (unsigned long) secp_ctx);
		SvREADONLY_on(secp_sv);
	OUTPUT:
		RETVAL

void
DESTROY(self)
		SV *self
	CODE:
		secp256k1_context_destroy(ctx_from_perl(self));

BOOT:
	secp256k1_selftest();

