
from dnstroubleshoot import atroubleshoot

from dataagg import dnsaggregation


file = '/home/nly/thu_ftp/dns_icbc/2022-12-31/A.json'
agg = dnsaggregation.dnsaggregation(file,False,1672416193,1672502337) # datauri, alldata=False, starttime=-1, endtime=-1
agg.loadData()

test = agg.regionAgg('浙江')

dect = atroubleshoot.atroubleshoot()
dect.detect(test)

'''
输出示例：
[(1672421622.0, 72.8), (1672425521.0, 66.2), (1672426118.0, 65.8)]
C-T网络拥塞: (1672421622, 72.8)
C-T网络拥塞: (1672425521, 66.2)
C-T网络拥塞: (1672426118, 65.8)
DNS查询链路网络拥塞，请检查CDN智能DNS配置:  (1672427927, 124)
DNS查询链路网络拥塞，请检查CDN智能DNS配置:  (1672452525, 857) 
DNS查询链路网络拥塞，请检查CDN智能DNS配置:  (1672473227, 792)
'''