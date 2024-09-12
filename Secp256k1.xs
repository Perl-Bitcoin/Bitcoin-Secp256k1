#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <secp256k1.h>

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
		/* TODO: fill_random is not a part of secp256k1, need to call Perl CSPRNG */
		/* unsigned char randomize[32];
		if (!fill_random(randomize, sizeof(randomize)) || !secp256k1_context_randomize(secp_ctx, randomize)) {
			croak("Failed to randomize secp256k1 context");
		} */

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

