#! /usr/bin/perl -w
use strict;
use Net::Pcap;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP qw(:strip);
  use NetPacket::TCP;
#хеш ссылок на массив значений заголовков, по названиям
my %header_base; 
my $default_filter = "tcp and port 80 and ";

for (@ARGV){	#need modif
	if ($_ eq "-f"){
		my $err = '';
		my ($_, $dump, @filter_list) = @ARGV;
		my $filter_str = join " ", @filter_list;#"tcp and port 80";
		$filter_str =  $default_filter .  $filter_str;
		my $net;
		my $mask;
		my $filter;

		my $pcap = Net::Pcap::pcap_open_offline($dump, \$err)
      		  or die "Can't read '$dump': $err\n";

		#Net::Pcap::pcap_lookupnet($dump, \$net, \$mask, \$err)
		#	and die "Can't lookupnet device $dump: $err\n";	#0 is OK
		Net::Pcap::pcap_compile($pcap, \$filter, $filter_str, 1, 0)	#is it right withou mask??
			and die "Can't compile filter:\t$filter_str\n";	#0 is OK

		process_pcap($pcap, $filter);

		last;
	}
	elsif($_ eq "-i"){
		my $err = '';
		my ($_, $dev, @filter_list) = @ARGV;
		my $filter_str = join " ", @filter_list;#"tcp and port 80";
		$filter_str =  $default_filter .  $filter_str;
		my $net;
		my $mask;
		my $filter;
		
		print "$dev \n";
		print "$filter_str\n";
		my $pcap = Net::Pcap::pcap_open_live($dev, 1024, 1, 0, \$err)
			or die "Can't open device $dev: $err\n";

		Net::Pcap::pcap_lookupnet($dev, \$net, \$mask, \$err)
			and die "Can't lookupnet device $dev: $err\n";	#0 is OK
		Net::Pcap::pcap_compile($pcap, \$filter, $filter_str, 1, $mask)
			and die "Can't compile filter:\t$filter_str\n";
		
#		my $dump_file = 'network.dmp';
#		my $dumper = Net::Pcap::pcap_dump_open($pcap, $dump_file);
#		Net::Pcap::pcap_loop($pcap, 10, \&process_packet, $dumper);
		
		process_pcap($pcap, $filter);

		last;
	}
	else{
		die "bad sintax:$_\n\t -f FILESNAME BPF \nor\n\t -i INTERFACE BPF\n"
	}
}

sub process_pcap{
	my ($pcap, $filter) = @_;
	Net::Pcap::pcap_setfilter($pcap, $filter);
	Net::Pcap::pcap_loop($pcap, 10, \&process_packet, "user data");
	print_base();
	Net::Pcap::pcap_close($pcap);
}
sub process_packet {
	my($user_data, $header, $packet) = @_;
#	Net::Pcap::pcap_dump($user_data, $header, $packet);
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
	#print "\tSTART\n$tcp_obj->{data} \n\tEND\n";
	my (@packet_by_str) = split /\R/, $tcp_obj->{data};
	return @packet_by_str;
}
sub push_http_pack {	# get inf from packet and push it in base
	my (@packet_by_str) = @_;	#изучаем перл глубже стр70
	foreach (@packet_by_str){
		if(m/^([\w]+?):\h*(.+)\h*/s){#/([\w-]+?):\h*([\w][^\f\r\n]*)\h*/(/([\w-]+):\s*([\w][^\f\r\n]*)\s*/){	#/(\w.*?)\:\s*(\w.*[^\f\r\n])\s*/){		#bad bad!!!				
			
			##$header_base{$1} = [] unless exist header_base{$1};
			if (is_field($1) && (!attend_str_in_array( $2, @{ $header_base{$1}}))  ){
				push @{ $header_base{$1}}, $2; #автовификация
			}
			#print "PASSed:\t\t$_\n";
		}		
		elsif($_ eq ""){	# тело отделено от заголовка строкой
			#print "EMPTY:\t\t$_\n";
			last;
		}
		else{
			#print "ABORTED:\t\t$_\n";
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
	print ")\n\n";
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
	return "$arg" =~ m/[\w]{2,}./ && !("$arg" =~ m/cookie/i);
}

