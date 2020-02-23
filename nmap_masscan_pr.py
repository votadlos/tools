#!/usr/bin/python3

import sys,re

if len(sys.argv) < 3:
    print("\nCompare nmap and masscan results and prepare cmd line for nmap rescan\n")
    print("Usage: "+sys.argv[0]+" nmap_scan_results.gnmap " + "masscan_output.txt")
    print("\tExample nmap cmd: nmap -sV -oA nmap_scan_results 10.10.10.10")
    print("\tExample masscan cmd: masscan -e tun0 -pT:1-65535,U:1-65535 10.10.10.10 >masscan_output.txt\n\n")
    sys.exit(1)

gnmap = sys.argv[1]
masscan = sys.argv[2]
if len(sys.argv) > 3:
    ip = sys.argv[3]
else:
    ip = 'will take first from masscan' #will be the first from masscan

print("[+] Input: gnmap:"+gnmap+", masscan:"+masscan+", IP:" + ip)

res = dict()
res['nmap'] = dict()
res['masscan'] = dict()

# nmap output
f = open(gnmap, 'r')
for l in f:
    p = re.search('Ports: (.+)$',l)
    
    if p is not None:
        pr = p.group(1) 
        pp = re.split(', ', pr)

        for p2 in pp:
            r = re.search("^(\d+)/(\w+)/(\w+)/", p2)

            if r is not None:
                port = r.group(1)
                state = r.group(2)
                protocol = r.group(3)

                if res['nmap'].get(protocol,'ihatepython') == 'ihatepython' :
                    res['nmap'][protocol] = dict()
                res['nmap'][protocol][port] = state
f.close()

# masscan output
f = open(masscan, 'r')
for l in f:
    p = re.search('Discovered open port (\d+)/(\w+) on (\S+)',l)
    port = p.group(1)
    protocol = p.group(2)
    if ip == 'will take first from masscan': #first IP, memorize and then process lines for this IP only
        ip = p.group(3)
    elif (ip == p.group(3)):
        if res['masscan'].get(protocol,'ihatepython') == 'ihatepython' :
            res['masscan'][protocol] = dict()
        res['masscan'][protocol][port] = 'open'
f.close()

#print(res) #DEBUG

# construct line for nmap rescan
to_scan = dict()
to_scan['udp'] = list()
to_scan['tcp'] = list()

for prot in res['masscan'].keys():
    for p in res['masscan'][prot].keys():
        print("[+] Checking "+p+"/"+prot+"...")
        if res['nmap'].get(prot,'perliscool') != 'perliscool':
            if res['nmap'][prot].get(p,'perliscool2') == 'perliscool2':
                print("\tNo port "+p+" in nmap res")
                print("\t\tAppend "+p+"/"+prot+" to secondary nmap scan")
                to_scan[prot].append(p)
        elif(len(to_scan[prot]) == 0):
            to_scan[prot] = [*res['masscan'][prot].keys()]


print("[+] TCP: ",to_scan['tcp']) #DEBUG
print("[+] UDP: ",to_scan['udp']) #DEBUG

u = False
t = False
if len(to_scan['tcp']) > 0:
    print("\n\n[+] Scan TCP only: ")
    print("nmap -sV -sC -oA nmap/secondary-tcp -p T:"+','.join(to_scan['tcp']) + " " + ip +"\n")
    t = True

if len(to_scan['udp']) > 0:
    print("\n\n[+] Scan UDP only: ")
    print("nmap -sV -sC -sU -oA nmap/secondary-udp -p "+','.join(to_scan['udp']) + " " + ip +"\n")
    u = True

if u and t:
    print("\n\n[+] Scan all ports: ")
    print("nmap -sV -sC -sU -oA nmap/secondary-udp-tcp -p U:"+','.join(to_scan['udp'])+",T:"+','.join(to_scan['tcp']) + " " + ip +"\n")


