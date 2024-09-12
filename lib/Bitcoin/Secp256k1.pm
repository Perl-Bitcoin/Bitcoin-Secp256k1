package Bitcoin::Secp256k1;

use v5.10;
use warnings;

require XSLoader;
XSLoader::load('Bitcoin::Secp256k1', $Bitcoin::Secp256k1::VERSION);

1;

__END__

=head1 NAME

Bitcoin::Secp256k1 - New module

=head1 SYNOPSIS

	use Bitcoin::Secp256k1;

	# do something

=head1 DESCRIPTION

This module lets you blah blah blah.

=head1 SEE ALSO

L<Some::Module>

=head1 AUTHOR

Bartosz Jarzyna E<lt>bbrtj.pro@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2024 by Bartosz Jarzyna

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

