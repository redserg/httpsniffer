#! /usr/bin/perl -w
use strict;
#хеш ссылок на массив значений заголовков, по названиям
my %header_base; 

print "arg1:", $ARGV[0], "\n";

if ($ARGV[0] ne "-i"){	#not interface then file, bad bad, need mods!!
	printf "file\n";
	return 0;
	if (defined($_=<>)){
		print ("$1 \n") if (m/(\d{2}:\d{2}:\d{2}\.\d{6}).*/); # take ti,e like 17:26:42.643526
		while (<>){
			chomp;
			if(/(.*):(.*)/){				
				$header_base{$1} = $2;	# memory
			}
			#($key, $value) split /:/ $_;
		}	
		my $key;
		my $value;
		while ( ($key, $value) = each %header_base){
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
#	print "my %http_header = (";
#	print ")\nEND\n\n";

	print_base();
	Net::Pcap::pcap_close($pcap);
			
}


sub process_packet {	#need to slie tcp/ip part!!
	my($user_data, $header, $packet) = @_;
	my ($firststr, @packet_by_str) = split /\R/, $packet;

	push_http_pack (@packet_by_str);
#	tcp_pack_editing_print(@packet_by_str);

#	my $key;
#	my $val;
	#print "PACKET:\n $packet\n";
	#print "PACKET_BY_STR:\n@packet_by_str\n";

}
sub print_base{

	my $key;
	my $value;
	print "my %header_base = (";

	while (($key, $value) = each %header_base){
		foreach (@{$value}){
			print "\t\'$key\' = > \'$_\'\n";
		}
		print "\n";
	}
	print ")\nEND\n\n";


}
sub push_http_pack {	# get inf from packet and push it in base
	my (@packet_by_str) = @_;	#изучаем перл глубже стр70
	foreach (@packet_by_str){
		if(/(\w.*?)\:\s*(\w[^\f\r\n].*[^\f\r\n])\s*/){						
			
			##$header_base{$1} = [] unless exist header_base{$1};
			push @{ $header_base{$1}}, $2; #автовификация

		}
		elsif(/\R/){
			last;
		}
	} 
}

sub tcp_pack_editing_print {	# get inf from packet and print it

	my ($firststr,@packet_by_str) = @_;

#	my $key;
#	my $value;
	
	foreach (@packet_by_str){
		
		if(/(\w.*?)\:\s*(\w[^\f\r\n].*[^\f\r\n])\s*/){				
			print "\t\'$1 => $2\'\n";
		}
		elsif(/\R/){
			last;
		}
		print "\n";
	} 
		# ...

#	($key, $value) = split /:/, $str;
#	return ($key, $value);
	
}
sub extract_http_pack{

}