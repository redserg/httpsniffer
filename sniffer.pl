#! /usr/bin/perl -w
use strict;
use Net::Pcap;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP qw(:strip);
  use NetPacket::TCP;
#хеш ссылок на массив значений заголовков, по названиям
my %header_base; 

my $default_filter = "tcp and port 80 ";
my @headers = ("Age", "TE", "URI", "Via");
my $count = 10;
my @args;

while (defined ($_ = shift @ARGV)){
	if ($_ eq "-c"){
		$count = shift @ARGV;
	}
	elsif($_ eq "-h"){
		print "sniffer.pl [ -c count ] \n[ - i interface ]  [ BPF ]\nOR\n[ -f file] [ BPF ]\n";

	}
	else{
		push (@args,$_);
	}
}
@ARGV = @args;

if(defined($_ = $ARGV[0])){
	print "getting $count packets\n";

	if ($_ eq "-f"){
		my $err = '';
		my $net;
		my $mask;
		my $filter;

		my ($_, $dump, @filter_list) = @ARGV;

		my $filter_str = &build_filter(@filter_list);
		print "from file:\t$dump\nwith BPF:\t$filter_str\n";

		my $pcap = Net::Pcap::pcap_open_offline($dump, \$err)
      		  or die "Can't read '$dump': $err\n";

		#Net::Pcap::pcap_lookupnet($dump, \$net, \$mask, \$err)
		#	and die "Can't lookupnet device $dump: $err\n";	#0 is OK
		Net::Pcap::pcap_compile($pcap, \$filter, $filter_str, 1, 0)	#is it right withou mask??
			and die "Can't compile filter:\t$filter_str\n";	#0 is OK

		&process_pcap($pcap, $filter);

	}
	elsif($_ eq "-i"){
		my $err = '';
		my $net;
		my $mask;
		my $filter;

		my ($_, $dev, @filter_list) = @ARGV;
		my $filter_str = &build_filter(@filter_list);
		print "from interface:\t$dev\nwith BPF:\t$filter_str\n";

		my $pcap = Net::Pcap::pcap_open_live($dev, 1024, 1, 0, \$err)
			or die "Can't open device $dev: $err\n";

		Net::Pcap::pcap_lookupnet($dev, \$net, \$mask, \$err)
			and die "Can't lookupnet device $dev: $err\n";	#0 is OK
		Net::Pcap::pcap_compile($pcap, \$filter, $filter_str, 1, $mask)
			and die "Can't compile filter:\t$filter_str\n";

#		my $dump_file = 'network.dmp';
#		my $dumper = Net::Pcap::pcap_dump_open($pcap, $dump_file);
#		Net::Pcap::pcap_loop($pcap, 10, \&process_packet, $dumper);

		&process_pcap($pcap, $filter);

	}
	else{
		die "bad sintax:$_\nsniffer.pl [ -c count ] \n[ - i interface ]  [ BPF ]\nOR\n[ -f file] [ BPF ]\n";
	}

	&print_base();

	exit (0);
}

sub build_filter{
	my (@filter_list) = @_;
	my $filter_str = join " ", @filter_list;
	if ($filter_str ne ""){
		$filter_str =  $default_filter . " and " . $filter_str ;
	}
	else{
		$filter_str =  $default_filter;
	}
	return $filter_str;
}

sub process_pcap{
	my ($pcap, $filter) = @_;
	Net::Pcap::pcap_setfilter($pcap, $filter);
	Net::Pcap::pcap_loop($pcap, $count, \&process_packet, "user data");
	Net::Pcap::pcap_close($pcap);
}
sub process_packet {
	my($user_data, $header, $packet) = @_;
#	Net::Pcap::pcap_dump($user_data, $header, $packet);
	&push_http_pack (extract_http_pack($packet));
}
sub extract_http_pack{
	my ($packet) = @_;
	my $tcp_obj = NetPacket::TCP->decode(
		NetPacket::IP::ip_strip(
			NetPacket::Ethernet::eth_strip(
				$packet
			)
		)
	);
#	warn "\tSTART\n$tcp_obj->{data} \n\tEND\n";
	my (@packet_by_str) = split /\R/, $tcp_obj->{data};
	return @packet_by_str;
}
sub push_http_pack {	# get inf from packet and push it in base
	my (@packet_by_str) = @_;
	foreach (@packet_by_str){
		if(m/^\h*([!-~]*?):\h*(.+)\h*$/s){#m/\h*([A-Z]\w{2,}):\h*(\w{2,}.+)\h*/s

			##$header_base{$1} = [] unless exist header_base{$1};
			if (&is_field($1) && (!&attend_str_in_array( $2, @{ $header_base{$1}}))  ){
				push @{ $header_base{$1}}, $2; #автовификация
			}
			else{
				#warn "NOTHEADER(or is ib base):\t$1\nIN:$_\n";
			}
#			warn "PASSed:\t\t$_\n";
		}		
		elsif($_ eq ""){	# тело отделено от заголовка строкой
#			warn "EMPTY:\t\t$_\n";
			last;
		}
		else{
#			warn "ABORTED:\t\t$_\n";
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
	return (
		 (	("$arg" =~ m/^[A-Z]\w{3,}$/) ||
		 	(&attend_str_in_array($arg, @headers))
		 )&&
		 !("$arg" =~ m/^cookie/i)
	);
}
