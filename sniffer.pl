#! /usr/bin/perl -w
use Net::Pcap;
use strict;

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

}