require 5.004;
use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'		=>	'Crypt::Blowfish',
	'VERSION_FROM'	=>	'Blowfish.pm',
	dist		=>	{ COMPRESS => 'gzip -9f', SUFFIX => 'gz'}
	);
