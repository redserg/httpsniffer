#! /usr/bin/perl -w
use strict;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP qw(:strip);
  use NetPacket::TCP;

#хеш ссылок на массив значений заголовков, по названиям
my %header_base; 
if (is_field("Date")  ){
				print "1\n";
			}
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
	#my $dev;
	my ($_, $dev, @filter_list) = @ARGV;
	my $filter_str = join " ", @filter_list;#"tcp and port 80";
	$filter_str =  "tcp and port 80 and " .  $filter_str;
	my $net;
	my $mask;
	my $filter;
	
	print "$dev \n";
	print "$filter_str\n";
	my $pcap = Net::Pcap::pcap_open_live($dev, 1024, 1, 0, \$err)
		or die "Can't open device $dev: $err\n";

	Net::Pcap::pcap_lookupnet($dev, \$net, \$mask, \$err);
	Net::Pcap::pcap_compile($pcap, \$filter, $filter_str, 1, $mask);
	Net::Pcap::pcap_setfilter($pcap, $filter);
	

	Net::Pcap::pcap_loop($pcap, 100, \&process_packet, "user data");

	print_base();
	Net::Pcap::pcap_close($pcap);
			
}

sub process_packet {
	my($user_data, $header, $packet) = @_;
	push_http_pack (extract_http_pack($packet));
}
sub extract_http_pack{
	my ($packet) = @_;	#need easyfication
	my $tcp_obj = NetPacket::TCP->decode(
		NetPacket::IP::ip_strip(
			NetPacket::Ethernet::eth_strip(
				$packet
			)
		)
	);
	my (@full_packet_by_str) = split /\R/, $packet;
	my (@packet_by_str) = @full_packet_by_str;
	return @packet_by_str;
}
sub push_http_pack {	# get inf from packet and push it in base
	my (@packet_by_str) = @_;	#изучаем перл глубже стр70
	foreach (@packet_by_str){
		
		if(/\R+/){	# тело отделено от заголовка строкой
			last;
		}
		elsif(m/([\w]+?):\h*(.+)\h*/s){#/([\w-]+?):\h*([\w][^\f\r\n]*)\h*/(/([\w-]+):\s*([\w][^\f\r\n]*)\s*/){	#/(\w.*?)\:\s*(\w.*[^\f\r\n])\s*/){		#bad bad!!!				
			
			##$header_base{$1} = [] unless exist header_base{$1};
			if (is_field($1) && (!attend_str_in_array( $2, @{ $header_base{$1}}))  ){
				push @{ $header_base{$1}}, $2; #автовификация
			}
			#print "$_\n";
		}
		if(/\R+/){	# тело отделено от заголовка строкой
			last;
		}
	} 
}
sub print_base{

	my $key;
	my $value;
	print "my %header_base = (\n";

	while (($key, $value) = each %header_base){
		foreach (@{$value}){
			print "\t\'$key\' => \'$_\',\n";
		}
		print "\n";
	}
	print ")\nEND\n\n";


}
sub attend_str_in_array{
	my ($element, @array) = @_;
	for (@array){
		if ($element eq $_){
			return 1;
		}
	}
	return 0;
}
sub is_field{
	my ($arg) = @_;
	if ("$arg" =~ m/[\w]{2,}./ && !("$arg" =~ m/cookie/i) ){
		return 1;
	}
	return 0;
}

