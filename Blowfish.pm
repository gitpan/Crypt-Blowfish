package Crypt::Blowfish;

require Exporter;
require DynaLoader;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

@ISA = qw(Exporter DynaLoader);
# @ISA = qw(Exporter DynaLoader Crypt::BlockCipher);

# Items to export into callers namespace by default
@EXPORT =	qw();

# Other items we are prepared to export if requested
@EXPORT_OK =	qw();

$VERSION = '2.06';
bootstrap Crypt::Blowfish $VERSION;

use strict;
use Carp;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}


sub blocksize { 8; }
sub keysize { 0; } 

sub new
{
	usage("new Blowfish key") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'ks'} = Crypt::Blowfish::init(shift);

	$self;
}

sub encrypt
{
	usage("encrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::Blowfish::crypt($data, $data, $self->{'ks'}, 0);

	$data;
}

sub decrypt
{
	usage("decrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::Blowfish::crypt($data, $data, $self->{'ks'}, 1);

	$data;
}

1;

__END__
#
# Parts Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# New Parts Copyright (C) 2000 W3Works, LLC (http://www.w3works.com/)
# All rights reserved.
#

=head1 NAME

Crypt::Blowfish - Perl Blowfish encryption module

=head1 SYNOPSIS

    use Crypt::Blowfish;
    
Blowfish is capable of strong encryption and can use key sizes up 
to 56 bytes (a 448 bit key).  You're encouraged to take advantage 
of the full key size to ensure the strongest encryption possible 
from this module.


=head1 DESCRIPTION

The module implements the Crypt::CBC interface.  You're encouraged
to read the perldoc for Crypt::CBC if you intend to use this module
for Cipher Block Chaining.

Crypt::CBC has the following methods:

=over 4

=item blocksize
=item keysize
=item encrypt
=item decrypt

=back

=head1 FUNCTIONS

=over 4

=item blocksize

Returns the size (in bytes) of the block cipher.

=item keysize

Returns the size (in bytes) of the key.

=item new

	my $cipher = new Crypt::Blowfish $key;

This creates a new Crypt::Blowfish BlockCipher object, using $key,
where $key is a key of C<keysize()> bytes.

=item encrypt

	my $cipher = new Crypt::Blowfish $key;
	my $ciphertext = $cipher->encrypt($plaintext);

This function encrypts $plaintext and returns the $ciphertext
where $plaintext and $ciphertext should be of C<blocksize()> bytes.

=item decrypt

	my $cipher = new Crypt::Blowfish $key;
	my $plaintext = $cipher->decrypt($ciphertext);

This function decrypts $ciphertext and returns the $plaintext
where $plaintext and $ciphertext should be of C<blocksize()> bytes.

=back

=head1 EXAMPLE

	my $key = pack("H16", "0123456789ABCDEF");
	my $cipher = new Crypt::Blowfish $key;
	my $ciphertext = $cipher->encrypt("plaintex");	# NB - 8 bytes
	print unpack("H16", $ciphertext), "\n";

=head1 PLATFORMS

Crypt::Blowfish has been tested B<successfully> against the following:

	Linux 2.2.X (RH6.X, Mandrake 6.5)
	Solaris 2.7 SPARC
	FreeBSD 3.4
	FreeBSD 3.3
	HP-UX B.10.20 (using HP's cc)

Crypt::Blowfish has been tested and B<failed> against the following:

	FreeBSD 3.2
	Win32

=head1 NOTES

To use the CBC mode, you B<must> use Crypt::CBC version 1.22 or higher.

=head1 SEE ALSO

Crypt::CBC,
Crypt::DES,
Crypt::IDEA

Bruce Schneier, I<Applied Cryptography>, 1995, Second Edition,
published by John Wiley & Sons, Inc.

=head1 COPYRIGHT

The implementation of the Blowfish algorithm was developed by,
and is copyright of, A.M. Kuchling.
Other parts of the perl extension and module are
copyright of Systemics Ltd ( http://www.systemics.com/ ). Code
revisions, updates, and standalone release is the copyright
of W3Works, LLC.

=head1 AUTHOR

Original algorithm, Bruce Shneier.  Original implimentation, A.M.
Kuchling.  Original Perl impilmentation, Systemics Ltd.

Current revision and maintainer:  Dave Paris <amused@pobox.com>

=head1 THANKS

To my wonderful wife for her patience & love.  To EFNet #perl, to 
infobot #perl, to the folks that helped test this module.  A special 
thanks to my friends for guidance and support.  Perl couldn't have 
had this module without ya'll.








