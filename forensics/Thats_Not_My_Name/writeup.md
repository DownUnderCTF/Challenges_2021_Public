# Solution
1. We've been provided with a PCAP file, and based off the challenge has been led to believe some data exfiltration is at play. First thing that comes to mind for that topic is DNS exfiltration and tunneling. To check this, we can search for unusally long dns queries in wireshark
```
dns && dns.qry.name.len > 35
```
2. After running that search there's plenty of traffic that seems ordinary. However, by scrolling down further we can start to see a large amount of traffic to a suspicious domain and a different IP than the rest of the DNS traffic
```
qawesrdtfgyhuj.xyz | 3.24.188.205
```
3. By having a look at the UDP stream, we're able to see a large amount of back and forth traffic with the same stream, which is unsual for ordinary DNS traffic. To investigate further, we can use the commandline equivalent of wireshark - tshark, to extract all queries going to this domain and save them to a file called queries.txt .
```
tshark -r notmyname.pcapng -T fields -e dns.qry.name -Y "dns.qry.name contains qawesrdtfgyhuj.xyz" > queries.txt
```
4. Based on the outputs of the file, the subdomains appear to be hexed, so next step is to remove the domain and dots from the queries and unhex the remaining contents. To remove the extras from the file, we can use the following commands in vim
```
:%s/qawesrdtfgyhuj.xyz//g
:%s/\.//g
```

5. To unhex the file, you can write your own python script with hexlify or your personal preference, or run the file through an online tool called 'CyberChef' to change the data to ascii.

6. By running the resulting data through binwalk, we can see there's a number of png files that were delivered through to the server throughout the tunnels lifetime. However, first let's check the data we have available to us by searching for the flag one of the following ways:
```
From command line: egrep -a DUCTF{ unhexed.txt
From vim: /DUCTF{
```
7. Here we actually found the flag within the data stream itself.
```
DUCTF{c4t_g07_y0ur_n4m3}
```
