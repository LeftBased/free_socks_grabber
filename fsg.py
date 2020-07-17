import sys
import time
import random
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENTS=[]

TEST_SOCKS=[]
GOOD_SOCKS=[]

THREADS=[]
NUM_OF_THREADS=15

# ------------------------------------------------------------------------------

def ll_proxyscan_io():

    global USER_AGENTS
    ua=random.choice(USER_AGENTS)
    rnd_header={'User-Agent':ua}    
    socks_list=[]
    
    r = requests.get('https://www.proxyscan.io/download?type=socks5',headers=rnd_header)
    if(r.status_code!=200):
        print('[-] Can\'t get data from proxyscan.io')
    else:
        rdata=r.text
        print('[*] Start parsing data from proxyscan.io')
        socks_list=rdata.split('\n')
        print('[+] Got',len(socks_list),'SOCKS5 from proxyscan.io')
    
    return socks_list

# ------------------------------------------------------------------------------

def ll_speedx():

    global USER_AGENTS
    ua=random.choice(USER_AGENTS)
    rnd_header={'User-Agent':ua}    
    socks_list=[]
        
    r = requests.get('https://github.com/TheSpeedX/PROXY-List/blob/master/socks5.txt',headers=rnd_header)
    if(r.status_code!=200):
        print('[-] Can\'t get data from speedx')
    else:
        rdata=r.text
        print('[*] Start parsing data from speedx')
        ps=re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}',rdata)
        if(len(ps)==0):
            print('[-] Can\'t parse data from speedx')
        else:
            for xsocks in ps:
                socks_list.append(xsocks)
            #print(socks_list)
            print('[+] Got',len(socks_list),'SOCKS5 from speedx')
    
    return socks_list

# ------------------------------------------------------------------------------

def ll_socks5():

    global USER_AGENTS
    ua=random.choice(USER_AGENTS)
    rnd_header={'User-Agent':ua}    
    socks_list=[]
        
    r = requests.get('https://github.com/hookzof/socks5_list/blob/master/proxy.txt',headers=rnd_header)
    if(r.status_code!=200):
        print('[-] Can\'t get data from socks5')
    else:
        rdata=r.text
        print('[*] Start parsing data from socks5')
        ps=re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}',rdata)
        if(len(ps)==0):
            print('[-] Can\'t parse data from socks5')
        else:
            for xsocks in ps:
                socks_list.append(xsocks)
            #print(socks_list)
            print('[+] Got',len(socks_list),'SOCKS5 from socks5')
    
    return socks_list

# ------------------------------------------------------------------------------

def chk_one_sock(xsock):

    global USER_AGENTS
    ua=random.choice(USER_AGENTS)
    rnd_header={'User-Agent':ua}       

    result=""
    
    xtmp=xsock.split(':')
    if(len(xsock)<=2):
        return result
    ip=xtmp[0]
    port=xtmp[1]

    r = requests.get('https://api.ipify.org',headers=rnd_header)
    if(r.status_code!=200):
        print('[-] Can\'t get old IP')
    else:
        old_ip=r.text
        
        try:

            proxies = {'http': "socks5://"+xsock, 'https': "socks5://"+xsock}        
            rx = requests.get('https://api.ipify.org',headers=rnd_header,proxies=proxies,timeout=3)
            if(rx.status_code!=200):
                print("[-] Sock",xsock,"didn\'t work")
            else:
                new_ip=rx.text
                if(old_ip!=new_ip):
                    print("[+] Sock",xsock,"is good, old_ip ==",old_ip,"new_ip ==",new_ip)
                    return xsock
        except:
            pass
        
    return result
# ------------------------------------------------------------------------------

print("-=[ Free Socks5 Grabber and checker v.0.1 ]=-\n")

USER_AGENTS=open("user_agents.txt").read().splitlines()

TEST_SOCKS=TEST_SOCKS+open("old_socks.txt").read().splitlines()

print('[+] Got',len(TEST_SOCKS),'SOCKS5 from file')

TEST_SOCKS=TEST_SOCKS+ll_proxyscan_io()
TEST_SOCKS=TEST_SOCKS+ll_speedx()
TEST_SOCKS=TEST_SOCKS+ll_socks5()
TEST_SOCKS=list(dict.fromkeys(TEST_SOCKS))

print('[+] Total grabbed SOCKS5 from web:',len(TEST_SOCKS))

processes = []
with ThreadPoolExecutor(max_workers=NUM_OF_THREADS) as executor:
    for zsock in TEST_SOCKS:
        processes.append(executor.submit(chk_one_sock, zsock))

for task in as_completed(processes):
    if(len(task.result())>1):
        GOOD_SOCKS.append(task.result())

with open("good_socks.txt", "w") as outfile:
    outfile.write("\n".join(GOOD_SOCKS))

old_=open("old_socks.txt").read().splitlines()
old_=old_+GOOD_SOCKS
old_=list(dict.fromkeys(old_))

with open("old_socks.txt", "w") as outfile:
    outfile.write("\n".join(old_))
        
print("[+] We have",len(GOOD_SOCKS),"checked socks5")