# SYN Flood Attack

A SYN flood occurs when a host becomes so overwhelmed by SYN segments initiating incomplete connection requests that it can no longer process legitimate connection requests.

Two hosts establish a TCP connection with a triple exchange of packets known as a three-way handshake: A sends a SYN segment to B; B responds with a SYN/ACK segment; and A responds with an ACK segment. A SYN flood attack inundates a site with SYN segments containing forged (spoofed) IP source addresses with nonexistent or unreachable addresses. B responds with SYN/ACK segments to these addresses and then waits for responding ACK segments. Because the SYN/ACK segments are sent to nonexistent or unreachable IP addresses, they never elicit responses and eventually time out.

## How to run
In order to run this file from the terminal we have to give the following order

```
perl syn_flood_attack.pl
```
As we are using a raw socket, the user must have root access! The user will then be prompted to enter the destination ip address and the destination port he wishes to attack. A random spoof address and its port will be used for the creation of the tcp and ip headers and the SYN flood attack.
