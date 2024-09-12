#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <secp256k1.h>

MODULE = Bitcoin::libsecp256k1				PACKAGE = Bitcoin::libsecp256k1

PROTOTYPES: DISABLED

BOOT:
	secp256k1_selftest();

