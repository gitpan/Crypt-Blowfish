print "1..3\n";

use Crypt::Blowfish;

my $blowfish=new Crypt::Blowfish(pack("H32","0123456789abcdef0123456789abcdef"));
print "not " if(!defined($blowfish));
print "ok 1\n";

my $data="TestData";
my $out=$blowfish->encrypt($data);
print "not " if(unpack("H16",$out) ne "8d62e5b9f6c9376d");
print "ok 2\n";

$data=$blowfish->decrypt($out);
print "not " if($data ne "TestData");
print "ok 3\n";
