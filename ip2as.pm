package ip2as;

use strict;
use warnings;

our $VERSION = '1';
our @EXPORT_OK = qw(getas4ip);

use Data::Dumper;
use JSON::XS qw(decode_json);
use Net::Patricia;
use Socket;
use File::Basename;
use Cwd 'abs_path';

sub get_json{
	my $filename = dirname(abs_path($0)) . '/tools/ip2asn.json';

	open my $fh, '<', $filename;
	read $fh, my $string, -s $fh;
	close $fh;

	return decode_json($string);
}

sub is_v4{
	my $ip = shift;
	if(defined(Socket::inet_pton(AF_INET, $ip))){
		return 1;
	}else{
		return 0;
	}
}

sub get_lookup{
	my $data = shift;
	my $v4 = new Net::Patricia;
	my $v6 = new Net::Patricia AF_INET6;

	foreach my $key(keys %$data){
		my $value = %$data{$key};
		my @split = split('/', $key);
		if(is_v4(shift(@split))){
			$v4->add_string($key, $value);
		}else{
			$v6->add_string($key, $value);
		}
	}
	return ($v4, $v6);
}

my $data = get_json();
my ($v4, $v6) = get_lookup($data);

sub getas4ip{
	my $ip = shift;

	my $result;

	if(is_v4($ip)){
		$result = $v4->match_string($ip);
	}else{
		$result = $v6->match_string($ip);
	}

	return $result;
}
1;
