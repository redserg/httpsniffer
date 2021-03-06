#! /usr/bin/perl -w
# "," в конце вывода Perl структуры
use strict;
# use Net::Pcap;
use Net::Pcap::Reassemble;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP qw(:strip);
  use NetPacket::TCP;
#use XML::Simple;
#use YAML;

# $Net::Pcap::Reassemble::debug = 1;

#хеш ссылок на массив значений заголовков, по названиям
my @user_base; 
# hash by ack of hash by seq of data
my %sessions_by_ack;	
my $structure_type = "p";
# my $warnings_enable_flag = 0;
my $default_filter = "tcp and port 80 ";

my $packet_num=0;

my @important_headers = (
	"User-Agent",
	"Accept", 
	"Accept-Language", 
	"Accept-Encoding",
	"Accept-Charset",
#	"Refer",
	 
	);

my $help_str = "sniffer.pl [ -c count ] [ -pxy structure type]\n[ - i interface ]  [ BPF ]\nOR\n[ -f file] [ BPF ]\n";

my $count = 0x7fffffff;
my @args;

while (defined ($_ = shift @ARGV)){	# Flags
	if ($_ eq "-c"){
		$count = shift @ARGV;
	}
	elsif($_ eq "-h"){
		warn $help_str;
		exit (0);
	}
	elsif($_ eq "-p"){
		$structure_type = "p";
	}
	elsif($_ eq "-x"){
		$structure_type = "x";
	}
	elsif($_ eq "-y"){
		$structure_type = "y";
	}
	else{
		push (@args,$_);
	}
}
@ARGV = @args;

if(defined($_ = $ARGV[0])){
	

	if ($_ eq "-f"){
		my $err = '';
		my $net;
		my $mask;
		my $filter;
		my ($_, $dump, @filter_list) = @ARGV;
		my $filter_str = &build_filter(@filter_list);

		&greeting($count,"f",$dump,$filter_str);

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

		&greeting($count,"i",$dev,$filter_str);


		my $pcap = Net::Pcap::pcap_open_live($dev, 65535, 1, 0, \$err)
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
		die "bad syntax:$_\nsniffer.pl" . $help_str;
	}

&print_base();

	exit (0);
}
warn $help_str;
exit (-1);

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
	Net::Pcap::Reassemble::loop($pcap, $count, \&process_packet, "user data");
	# Net::Pcap::pcap_loop($pcap, $count, \&process_packet, "user data");
	Net::Pcap::pcap_close($pcap);
}
sub process_packet {
	my($user_data, $header, $packet) = @_;
	++$packet_num;
	# warn "$packet_num\n" if $warnings_enable_flag;

	my $tcp_obj = &extract_http_pack($packet);

	# Fragmentation!!!

	${ $sessions_by_ack{$tcp_obj->{acknum}} }{$tcp_obj->{seqnum}} = $tcp_obj->{data};

	if ($tcp_obj->{flags} & PSH){
		# warn "p\n" if $warnings_enable_flag;

		my $data;
		my @seqnums_by_increase = sort (keys (%{ $sessions_by_ack{$tcp_obj->{acknum}} }));

		foreach (@seqnums_by_increase){
			$data .= ${ $sessions_by_ack{$tcp_obj->{acknum}} }{$_};
		}

		&push_http_pack($data);

		# warn "$tcp_obj->{acknum}\n" if $warnings_enable_flag;
		# warn "$data\n" if $warnings_enable_flag;

		delete $sessions_by_ack{$tcp_obj->{acknum}};
	}

	 #(&extract_http_pack($packet));
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
	return $tcp_obj;
}
sub push_http_pack {	# get inf from packet and push it in base
	my ($packet) = @_;
	my (@packet_by_str) = split /\R/, $packet;
	my $newref;
	my $oldref;
	my $Request_Header_flag = 0;
	foreach (@packet_by_str){
		if(m/^([\w-]+?):\h*(.+)/){
			#make a new hash from important headers by this packet
			if (&is_important($1) ){
				${$newref}{$1} = $2;
				$Request_Header_flag = 1; 
			}
		}	
	} 
	#if this packet is from new user, add it to array of bases
	if($Request_Header_flag){
		foreach (@important_headers){
			${$newref}{$_} = "" unless(defined(${$newref}{$_}));		
		}
		foreach $oldref (@user_base){
			if (&user_eq($newref, $oldref)){ #is it old user?
				return 1;
			}
		}
		push @user_base, $newref; #if it new
		return 2;
	}
}
sub print_base{
	if($structure_type eq "p"){
		my $i = 0;
		my $temp;
		foreach (@user_base){
			print "my \$user_$i = (\n";
				foreach $temp (@important_headers){
					print "\t\'$temp\' => \'$$_{$temp}\',\n"; #warning if it unitialized
				}
			print ");\n\n";
			++$i;
		}
	}
	elsif($structure_type eq "x"){
		use XML::Simple;
		my %output_hash;	
		my $username;
		my $i = 0;
		foreach (@user_base){
			$username = "user_$i";
			$i++;
			$output_hash{$username} = $_;
		}

		my $simple = XML::Simple->new();
		my $out = $simple->XMLout(\%output_hash);
		print "$out\n";
	}
	elsif($structure_type eq "y"){
		use YAML;

		my %output_hash;
		my $username;
		my $i = 0;
		foreach (@user_base){
			$username = "user_$i";
			$i++;
			$output_hash{$username} = $_;
		}
		my $out = YAML::Dump(%output_hash);
		print "$out";
	}
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
sub is_important{
	my ($arg) = @_;
	return &attend_str_in_array($arg, @important_headers);
}
sub user_eq{
	my ($r1, $r2) = @_; 
	foreach (@important_headers){
		if ($$r1{$_} ne $$r2{$_}){
			return 0;
		}
	}
	return 1;
}
sub greeting(){
	my ($count,$flag, $dev, $filter_str) = @_;
	warn "getting $count packets\n";
	if($flag eq "f"){
		warn "from file:\t$dev\n"
	}
	elsif($flag eq "i"){
		warn "from interface:\t$dev\n"
	}
	warn "with BPF:\t$filter_str\n";
	if($structure_type eq "p"){
		warn "print as Perl structure.\n";
	}
	elsif($structure_type eq "x"){
		warn "print as XML structure.\n";
	}
	elsif($structure_type eq "y"){
		warn "print as YAML structure.\n";
	}
}
