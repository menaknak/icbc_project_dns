import os
import re
import ipaddress
import random
import re
import time
from collections import defaultdict
import socket

def checkip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def mkdir(path):
    path = path.strip().rstrip('/')
    exist = os.path.exists(path)
    if not exist:
        os.makedirs(path)
    else:
        pass


def get_ipv4_a(domain):
    p = os.popen('dig A '+domain+' +short')
    x=p.read()
    return x.strip()   

def get_ipv6_aaaa(domain):
    p = os.popen('dig AAAA '+domain+' +short')
    x=p.read()
    # print(x)
    return x.strip()

def get_ipv4_gluerecord(domain):
    ip = None
    ccTLD=[
        'g.dns.cn',
        'f.dns.cn',
        'e.dns.cn',
        'd.dns.cn',
        'c.dns.cn',
        'b.dns.cn',
        'a.dns.cn',
        'ns.cernet.net',
    ]
    while not ip:
        chose_ccTLD = random.choice(ccTLD)
        p = os.popen('dig '+domain+' @'+chose_ccTLD+' +noall +additional')
        x = p.read()
        ip = extract_domain_type_ip(x,domain,qtype='A')
    return ip

def get_ipv6_gluerecord(domain):
    ip = None
    ccTLD=[
        'g.dns.cn',
        'f.dns.cn',
        'e.dns.cn',
        'd.dns.cn',
        'c.dns.cn',
        'b.dns.cn',
        'a.dns.cn',
        'ns.cernet.net',
    ]
    while not ip:
        chose_ccTLD = random.choice(ccTLD)
        p = os.popen('dig '+domain+' @'+chose_ccTLD+' +noall +additional')
        x = p.read()
        ip = extract_domain_type_ip(x,domain,qtype='AAAA')
    return ip

# def get_ns_nsip(nslist):
#     ns_nsip=[]
#     for ns in nslist:
#         ns_nsip.append((ns,)+(get_ip(ns),))
#     return ns_nsip

def get_ns_nsipv4_tuple(ns):
    return (ns,)+(get_ipv4_gluerecord(ns),)

def get_ns_nsipv6_tuple(ns):
    return (ns,)+(get_ipv6_gluerecord(ns),)

def extract_domain_type_ip(response,domain,qtype='A'):
    lines = response.strip().split('\n')
    # print(lines)
    for l in lines:
        # print(l)
        if l.startswith(';'):
            continue
        else:
            rdatas = l.strip().split('\t')
            if rdatas[0].split('.')[0]==domain.split('.')[0] and rdatas[3]==qtype:
                ip = rdatas[4]
                if checkip(ip):
                    return ip
                else:
                    return None

def extract_edns0bufsize(string):
    try:
        # result=re.search(r'EDNS: (.*)',string).group(1)
        result=re.search(r'udp: ([0-9]*)',string).group(1)
    except:
        result=None
    return result

def extract_msgsize(string):
    try:
        result=re.search(r'MSG SIZE  rcvd: ([0-9]*)',string).group(1)
    except:
        result=None
    return result

def extract_RCODE(string):
    try:
        result=re.search(r'status: (.*),',string).group(1)
    except:
        result=None
    return result

def extract_answer_num(string):
    try:
        result=re.search(r'ANSWER: ([0-9]*),',string).group(1)
    except:
        result=None
    return result

def extract_time(string):
    try:
        result=re.search(r'Query time: (.*?) msec',string).group(1)
    except:
        result=None
    return result

def extract_pdns(string):
    result=re.search(r'SERVER: (.*?)#',string).group(1)
    return result

def extract_resultip(response):
    lines = response.strip().split('\n')
    # print(lines)
    for l in lines[::-1]:
        # print(l)
        if l.startswith(';'):
            continue
        else:
            ip = l.strip().split('\t')[-1].split(' ')[-1]
            if checkip(ip):
                return ip
            else:
                return None


def extract_rr(response):
    lines = response.strip().split('\n')
    rr=[]
    for l in lines:
        l = l.strip()
        if l.startswith(';') or l=='':
            continue
        else:
            rr.append(l)
    if not rr: return None
    return rr

def get_LDNS():
    p = os.popen('dig '+'com')
    x=p.read()
    LDNS=extract_pdns(x)
    return LDNS

def get_time_avg(time_list):
    new = [int(i) for i in time_list if i]
    if new:
        return sum(new)/len(new)
    else: return None

def phase_1_NXD(repeat=1):
    latency=[]
    flag=False
    PDNS=''
    for i in range(repeat):
        RANDOM=str(int(random.random()*1000000))
        global domain_ip_dict
        p = os.popen('dig '+'.')
        x=p.read()
        time=extract_time(x)
        latency.append(time)
        # print(x,file=F)
    return latency


def phase_2_ADNS(domain_ns_nsip_tuple,repeat=1,qtype='A'):
    latency=[]
    t=domain_ns_nsip_tuple
    for i in range(repeat):
        RANDOM=str(int(random.random()*1000000))
        domain=RANDOM+'.'+t[0]
        p = os.popen('dig '+qtype+' '+domain+' @'+t[2]+' +noauthority +noadditional')
        x=p.read()
        # print(x)
        time=extract_time(x)
        RCODE = extract_RCODE(x)
        latency.append(time)
        # print(x,file=F)
    return latency, RCODE

def phase_3_CDNDNS(domain_ns_nsip_tuple,repeat=1,qtype='A'):
    repeat=1 
    latency=[]
    t=domain_ns_nsip_tuple
    for i in range(repeat):
        RANDOM=str(int(random.random()*1000000))
        domain=RANDOM+'.'+t[0]
        p = os.popen('dig '+qtype+' '+t[0]+' +noauthority +noadditional')
        # p = os.popen('dig '+qtype+' '+t[0]+' +noall +stats +answer')
        x=p.read()
        RCODE = extract_RCODE(x)
        latency.append(extract_time(x))
    return latency, extract_resultip(x),extract_rr(x), RCODE


def get_RR(ns_nsip_tuple, qtype):
    adns = ns_nsip_tuple[0]
    adnsip = ns_nsip_tuple[1]
    ts=time.time()
    RR = defaultdict(dict)
    domain = 'icbc.com.cn'
    p = os.popen('dig '+qtype+' '+domain+' @'+adnsip+' +noauthority +noadditional')
    x = p.read()
    adns_ednsbufsize = extract_edns0bufsize(x)
    RR[ts]['LDNS'] = get_LDNS()
    RR[ts]['TargetADNS'] = adns
    RR[ts]['TargetADNS_IP'] = adnsip #这里是直接从ADNS得到返回RR
    RR[ts]['Qtype'] = qtype
    if qtype=='MX':        
        if adns_ednsbufsize:
            RR[ts]['EDNS_enabled'] = True
        else:
            RR[ts]['EDNS_enabled'] = False
        RR[ts]['TargetADNS_UDPbufsize'] = adns_ednsbufsize


    RR[ts]['RR'] = extract_rr(x) 
    RR[ts]['Query time'] = extract_time(x)
    RR[ts]['MSG SIZE rcvd'] = extract_msgsize(x)
    return RR

def get_TCP(ns_nsip_tuple):
    adns = ns_nsip_tuple[0]
    adnsip = ns_nsip_tuple[1]
    ts=time.time()
    RR = defaultdict(dict)
    domain = 'icbc.com.cn'
    p = os.popen('dig MX'+' '+domain+' @'+adnsip+' +bufsize=512 +noauthority +noadditional')
    x = p.read()
    adns_ednsbufsize = extract_edns0bufsize(x)
    RR[ts]['LDNS'] = get_LDNS()
    RR[ts]['TargetADNS'] = adns
    RR[ts]['TargetADNS_IP'] = adnsip #这里是直接从ADNS得到返回RR
    qtype = 'MX'
    RR[ts]['Qtype'] = qtype
    # if qtype=='MX':        
    #     if adns_ednsbufsize:
    #         RR[ts]['EDNS_enabled'] = True
    #     else:
    #         RR[ts]['EDNS_enabled'] = False
    #     RR[ts]['TargetADNS_UDPbufsize'] = adns_ednsbufsize


    RR[ts]['RR'] = extract_rr(x) 
    RR[ts]['Query time'] = extract_time(x)
    RR[ts]['MSG SIZE rcvd'] = extract_msgsize(x)
    RR[ts]['Answer_num'] = extract_answer_num(x)
    return RR
    
def get_metrics(domain_ns_nsip_tuple,repeat=1,verbose=True,LOG_RR=True,qtype='A'):
    ts=time.time()
    result = defaultdict(dict)
    TIME=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    # time.strptime('2022-04-09 13:07:53', "%Y-%m-%d %H:%M:%S") # time.struct
    # time.mktime(time.strptime("2018-08-07", "%Y-%m-%d")) # 1533571200.0
    t=domain_ns_nsip_tuple
    domain=t[0]
    CL=get_time_avg(phase_1_NXD(repeat))
    CTlist,CTRCODE = phase_2_ADNS(t,repeat,qtype)
    CT=get_time_avg(CTlist)
    CLTCDN,ip,rr,CDNRCODE=phase_3_CDNDNS(t,repeat,qtype)
    CLTCDN = [int(i) for i in CLTCDN if i]
    CLTCDN=sum(CLTCDN)
    CLT=CL+CT
    CDN=CLTCDN-CLT
    if CDN<0:CDN=0.0
    
    if verbose:
        print('['+'-'*30+']')    
        # print()
        print('Time:\t\t',TIME)
        print('Domain:\t\t',domain)
        print('TargetADNS:\t',t[1])
        print('TargetADNS_IP:\t',t[2])
        print('Qtype:\t',qtype)
        print('Resolved IP:\t',ip)
        print('RR:\t',rr)

        print('LDNS:\t\t',get_LDNS())
        print()
        
        print('Latencies of resolution paths')
        print('C-L:\t\t %.2f' % CL)
        print('C-T:\t\t %.2f' %CT)
        print('C-L-T-CDN:\t %.2f' %CLTCDN)
        
        # print('C-CDN:\t\t %.2f' %CLTCDN)
        # print('时延 = 0ms，通常是因为\n(1) DNS 缓存, (2) 距离近')
        print()
        print()

    # 字典记录数值，转存 json   
    result[ts]['Time']=TIME
    result[ts]['Domain']=domain
    result[ts]['TargetADNS']=t[1]
    result[ts]['TargetADNS_IP']=t[2]
    result[ts]['LDNS']=get_LDNS()
    result[ts]['Resolved IP']=ip
    result[ts]['Qtype']=qtype
    if LOG_RR:result[ts]['RR']=rr
    result[ts]['C-L']= CL
    result[ts]['C-T']=CT
    result[ts]['C-L-T-CDN']=CLTCDN

    result[ts]['CT_RCODE']=CTRCODE
    result[ts]['C-L-T-CDN_RCODE']=CDNRCODE

    return result


def get_v6_address():
    ip_list = os.popen("ip addr show | sed -e 's/^.*inet6 \([^ ]*\)\/.*$/\\1/;t;d'").readlines()
    ip = ip_list[1].strip()
    return ip

def get_v4_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def send_dns_query(clientip,qtype):
    hardcode = 'mapsystm'
    clientip = clientip.replace('.','-')
    RANDOM = str(int(random.random()*10000))
    aim_url = clientip+'x'+RANDOM+'x'+hardcode+'.icbc.com.cn'
    # print('dig '+qtype+' '+aim_url+' +noall')
    p = os.popen('dig '+qtype+' '+aim_url+' +noall')
    # x=p.read()
    # print(x)



if __name__ == "__main__":
    t='xx.icbc-am.icbc.com.cn'
    print(get_v4_address())
    send_dns_query(get_v6_address(),'AAAA')
    # print()