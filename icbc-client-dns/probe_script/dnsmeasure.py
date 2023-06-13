'''
精简版linux系统会发现没有dig命令，这时候就需要安装一下。
debian系
apt-get install dnsutils

centos系
yum install bind-utils
pip3 install xlrd
'''

import time
import random
import re
import json
from collections import defaultdict
from datetime import date as dt
from optparse import OptionParser
from util import * 
from measurement_target import *

usage = 'Usage: %prog [options]\n '
parser = OptionParser(usage=usage)
parser.add_option("-4", "--ipv4", action="store_true" , dest="v4", default=False,
    help="以IPv4线路向目标ADNS查询A/MX/SOA记录，不查A")
parser.add_option("-6", "--ipv6", action="store_true" , dest="v6", default=False,
    help="以IPv6线路向目标ADNS查询AAAA/MX/SOA记录，不查AAAA")
parser.add_option("-s", "--sleep", type="float", dest="msec", default=300,
    help="how much to sleep between requests, in msec")
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, 
    help="print log")
parser.add_option("-n", "--number", type="int", dest="n", default=None,
    help="exit after N tasks (default: unlimited)")
# parser.add_option("-t", "--qtype", type="str", dest="qtype", default='MX,SOA',help="e.g. MX,SOA")

(options, args) = parser.parse_args()



LOG_RR=True #是否在log里记录RR
VERBOSE = options.verbose # 是否打印每一次扫描信息
SLEEPTIME = options.msec
# 默认查 V4 A 记录
V4 = True
V6 = False
if options.v6:
    V6 = True
    V4 = False

if V4: 
    qtype='A'
    vlogpath = 'v4'
    clientip = get_v4_address()
if V6: 
    qtype='AAAA'
    vlogpath = 'v6'
    clientip = get_v6_address()

    

REPEAT=10

# from pprint import pprint as pp

def main(adns,repeat=1,verbose=False,LOG_RR=True,qtype='A'):
    domain_ns_nsip=[]
    if V4:
        ns_nsip_tuple=get_ns_nsipv4_tuple(adns)
    if V6:
        ns_nsip_tuple=get_ns_nsipv6_tuple(adns)
    
    
    # ADNS循环查一次 MX SOA EDNS
    MX = get_RR(ns_nsip_tuple,'MX')
    SOA = get_RR(ns_nsip_tuple,'SOA')
    TXT = get_RR(ns_nsip_tuple,'TXT')
    TCP = get_TCP(ns_nsip_tuple)
    

    for d in measurelist:
        domain_ns_nsip.append((d,)+ns_nsip_tuple)
    # pp(domain_ns_nsip)
    # print(domain_ns_nsip)
    
    result = dict()
    for t in domain_ns_nsip:
        result.update(get_metrics(t,repeat,verbose,LOG_RR,qtype=qtype))

    return TCP,MX, SOA, TXT, result
    



i = 0
while True:
    i+=1
    if options.n and i > options.n:
        break

    DATE = dt.today().strftime("%Y-%m-%d")
    logpath='../log/'+DATE+'/'+vlogpath+'/'
    mkdir(logpath)

    for adns in ns:
        # client - LDNS - ADNS 映射 发包

        send_dns_query(clientip,qtype)

        TCP,MX,SOA,TXT,AAAAA = main(adns,5,verbose=VERBOSE,LOG_RR=LOG_RR,qtype=qtype)
        # TIME=time.strftime("%Y-%m-%d_%H=%M=%S", time.localtime())
        # fw =open(logpath+qtype+'+'+TIME+'.json','w',encoding='utf-8')   
        # json.dump(result,fw,ensure_ascii=False,indent=4)#

        result = AAAAA
        fw =open(logpath+qtype+'.json','a',encoding='utf-8')   #
        json.dump(result,fw,ensure_ascii=False)#
        fw.write('\n')
        result = TCP
        fw =open(logpath+'TCP'+'.json','a',encoding='utf-8')   #
        json.dump(result,fw,ensure_ascii=False)#
        fw.write('\n')
        result = MX
        fw =open(logpath+'MX'+'.json','a',encoding='utf-8')   #
        json.dump(result,fw,ensure_ascii=False)#
        fw.write('\n')
        result = SOA
        fw =open(logpath+'SOA'+'.json','a',encoding='utf-8')   #
        json.dump(result,fw,ensure_ascii=False)#
        fw.write('\n')
        result = TXT
        fw =open(logpath+'TXT'+'.json','a',encoding='utf-8')   #
        json.dump(result,fw,ensure_ascii=False)#
        fw.write('\n')
        time.sleep(SLEEPTIME)



