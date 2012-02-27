#! /usr/bin/perl -w
use strict;

sub process_packet {
	my($user_data, $header, $packet) = @_;
	my @packet_by_str = split /\R/, $packet;
	my $key;
	my $val;
	#print "PACKET:\n $packet\n";
	#print "PACKET_BY_STR:\n@packet_by_str\n";
	print "my %http_header = (";
	foreach (@packet_by_str){
		
		if(/(.*):(.*)/){				
			#($key, $val) = &str_editing($_);
			print "\t$1 => $2\n";
		}
	} 
		# ...
	print ")\nNEXT\n\n";
}

sub str_editing {	# get inf from str
	my $str = @_;

	my $key;
	my $value;
	
	($key, $value) = split /:/, $str;
	return ($key, $value);
	
}

print "arg1:", $ARGV[0], "\n";
my %output_base;

if ($ARGV[0] ne "-i"){	#not interface then file need mods
	if (defined($_=<>)){
		print ("$1 \n") if (m/(\d{2}:\d{2}:\d{2}\.\d{6}).*/); # take ti,e like 17:26:42.643526
		while (<>){
			chomp;
			if(/(.*):(.*)/){				
				$output_base{$1} = $2;	# memory
			}
			#($key, $value) split /:/ $_;
		}	
		my $key;
		my $value;
		while ( ($key, $value) = each %output_base){
			print "$key = > $value\n"
		}
	}	
}else{
#main part of programm
use Net::Pcap;
	my $err = '';
	my $dev = $ARGV[1];
	
	my $filter_str = "tcp and port 80";
	my $net;
	my $mask;
	my $filter;
	
	
	#$dev = Net::Pcap::pcap_lookupdev(\$err);  # find a device
	print "$dev \n";
	my $pcap = Net::Pcap::pcap_open_live($dev, 1024, 1, 0, \$err)
		or die "Can't open devvice $dev: $err\n";
	Net::Pcap::pcap_lookupnet($dev, \$net, \$mask, \$err);
	
	Net::Pcap::pcap_compile($pcap, \$filter, $filter_str, 1, $mask);
	Net::Pcap::pcap_setfilter($pcap, $filter);

	Net::Pcap::pcap_loop($pcap, 10, \&process_packet, "user data");


	Net::Pcap::pcap_close($pcap);
			
}


