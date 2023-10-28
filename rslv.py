#!/usr/bin/env python
# -*- coding: latin-1 -*-
import requests, sys, json, socket, os
if len(sys.argv) < 2:
    print("Please use: python3 rslv.py domain.com")
    exit()
url = "https://www.virustotal.com/vtapi/v2/domain/report"
params = {"apikey":"0a1f92cc877fb00875cf0fa6e856db8009fb322fce4b507a9ef40e22d63b7fa4","domain":sys.argv[1]}
os.system("clear")
print("""         _nnnn_                      
        dGGGGMMb     ,..............,
       @p~qp~~qMb    | Scanning...  |
       M|@||@) M|   _;..............'
       @,----.JM| -'
      JS^\__/  qKL
     dZP        qKRb
    dZP          qKKb
   fZP            SMMb
   HZM            MMMM
   FqM            MMMM
 __| ".        |\dS"qML
 |    `.       | `' \Zq
_)      \.___.,|     .'
\____   )MMMMMM|   .'
     `-'       `--' """)
nl = "\n"
listdomains = []
listresolv = []
response = requests.get(url, params=params)
try:
    jsonread = response.json()
    subdomains = sorted(jsonread['subdomains'])
except(KeyError):
    print(nl + "(!) No domains found :(" +  nl)
    exit(0)
except(ValueError):
    print(nl + "(!) Decoding JSON has failed, maybe to many requests?, please wait some." +  nl)
    exit(0)
response2 = requests.get("https://api.hackertarget.com/hostsearch/?q=" + sys.argv[1])
for line in response2.iter_lines():
    linestr = str(line)
    linesplit = linestr.split(",")
    if not linesplit[0].replace("""b'""", "") == """API count exceeded - Increase Quota with Membership'""":
        listdomains.append(linesplit[0].replace("""b'""", ""))
for subdomain in subdomains:
    if not subdomain in listdomains:
        listdomains.append(subdomain)
for socketresolv in listdomains:
    try:
        resolved = socket.gethostbyname(socketresolv)
        if not resolved in listresolv:
            listresolv.append(resolved)
    except:
        pass
print(nl + "» Found domains:")
for subdomain in listdomains:
    print(subdomain)
print(nl + "» Found ips:")
ipsfound = 0
for iplist in listresolv:
    list = ["23.145.", "23.156.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.", "1.1.1.1", "172.64.", "172.65.", "172.67.", "172.68."]
    if not any(iplist.startswith(s) for s in list):
        ipsfound += 1
        print(iplist)
if ipsfound == 0:
    print("(!) No ips found :(" +  nl)
    exit(1)
save = input("Save? y/n: ")
if save == "y":
    try:
        os.mkdir("domains/")
    except FileExistsError:
        if os.path.isfile("domains/" + sys.argv[1] + ".txt"):
            os.system("rm domains/" + sys.argv[1] + ".txt")
        pass
    for iplist in listresolv:
        list2 = ["23.145.", "23.156.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.", "1.1.1.1", "172.64.", "172.65.", "172.67.", "172.68."]
        if not any(iplist.startswith(s) for s in list):
            with open("domains/" + sys.argv[1] + '.txt', 'a') as xX:
                xX.write(iplist + '\n')
    print("For scanning: masscan -iL domains/" + sys.argv[1] +".txt -p 1-65535 --retries 1 -nmap --open-only -Pn -oL domains/" + sys.argv[1] + ".txt --rate=10000")