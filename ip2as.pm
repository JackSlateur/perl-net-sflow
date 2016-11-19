package ip2as;

use strict;
use warnings;

our $VERSION = '1';
our @EXPORT_OK = qw(getas4ip);

use Net::IP;
use NetAddr::IP;
use Socket;
use Net::DNS::Async;

my $res = new Net::DNS::Async(QueueSize => 200, Retries => 1);
my %IPcache;
my %IPv6cache;

sub parse{
	my $ip = shift;

	my $family = undef;
	my $shortip = undef;

	if(defined(Socket::inet_pton(AF_INET, $ip))){
		$family = 4;
		$shortip = NetAddr::IP->new($ip, 24);
		$shortip = $shortip->network()->addr();
	}

	if(defined(Socket::inet_pton(AF_INET6, $ip))){
		$family = 6;
		$shortip = NetAddr::IP->new6($ip, 64);
		$shortip = $shortip->network()->addr();
	}

	return $family, $shortip;
}

sub getcache{
	my $ip = shift;

	my ($family, $shortip) = parse($ip);

	if($family == 4){
		if(defined($IPcache{$shortip})){
			return $IPcache{$shortip};
		}
	}else{
		if(defined($IPv6cache{$shortip})){
			return $IPv6cache{$shortip};
		}
	}
	return;
}

sub setcache{
	my $ip = shift;
	my $asn = shift;

	my ($family, $shortip) = parse($ip);
	if($family == 4){
		$IPcache{$shortip} = $asn;
	}else{
		$IPv6cache{$shortip} = $asn;
	}
}

sub ptr2ip{
	my $ptr = shift;

	my $family = 4;

	if($ptr =~ /origin6.asn.cymru.com/){
		$family = 6;
	}

	$ptr =~ s/origin.asn.cymru.com//g;
	$ptr =~ s/origin6.asn.cymru.com//g;
	chop $ptr;

	my @part = split /\./, $ptr;
	@part = reverse(@part);
	if($family == 4){
		push @part, 0;
		return join '.', @part;
	}else{
		for(my $i = 0; $i < 16; $i++){
			push @part, 0;
		}

		my $ip = '';
		for(my $i = 1; $i < $#part + 2; $i++){
			$ip .= $part[$i - 1];
			if($i % 4 == 0){
				$ip .= ':';
			}
		}
		chop $ip;
		return $ip;
	}
}

sub callback{
	my $response = shift;

	if(!defined($response)){
		return;
	}

	my @question = $response->question;
	my $real_ip = ptr2ip($question[0]->name);

	foreach my $rr ($response->answer){
		next unless $rr->type eq 'TXT';
		my @result = split(/ /, $rr->txtdata);
		setcache($real_ip, $result[0]);
		return;
	}
	
}

sub resolve{
	my $ip = shift;
	my $truncate = 1;

	my ($family, undef) = parse($ip);

	if($family == 6){
		$truncate = 16;
	}

	my $revIP = Net::IP->new($ip)->reverse_ip;

	if($family == 4){
		$revIP =~ s/in-addr.arpa./origin.asn.cymru.com./g;
	}else{
		$revIP =~ s/ip6.arpa./origin6.asn.cymru.com./g;
	}

	my @part = split /\./, $revIP;
	$revIP = join '.', @part[$truncate..$#part];

	my $query = new Net::DNS::Packet($revIP, 'TXT');
	$res->add(\&callback, $query);
}

sub getas4ip{
	my $ip = shift;
#	print "Debug getas4ip: " . scalar %IPcache . " v4 entries, " . scalar %IPv6cache . " v6 entries, looking for $ip\n";

	my $asn = getcache($ip);
	if(!defined($asn)){
		resolve($ip);
	}
	return $asn;
}
1;
