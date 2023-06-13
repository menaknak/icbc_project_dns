import os
import json
import time
import base64
import numpy as np
from cachedipinfo import dnsfastwhois as fastwhois
# from cachedipinfo import fastwhois

import pandas as pd
from dnsdatabase import dnsdatabase





class dnsaggregation:
    def __init__(self, datauri, alldata=True, starttime=-1, endtime=-1, interval=300, targethosts=[], targetips=[]):


        '''
        Parameters:
            datauri: 数据json文件位置
            alldata: 是否直接提取所有数据
            metric: ["all_time","query_time","nxd_1","adns_2_latency"] 中的类型
            starttime, endtime: 单位是sec 用time.time()可以获取现在的时间
            interval: 取数间隔，单位是sec
            targethosts: 重点观察的主机名
            targetips: 重点观察的ip

        '''
        # self.whois = fastwhois.fastwhois()
        self.regions = ["黑龙江","吉林","辽宁","河北","甘肃","青海","陕西","河南","山东","山西","安徽","湖北","湖南","江苏","四川","贵州","云南",\
        "浙江","江西","广东","福建","海南","新疆","内蒙古","宁夏","广西","西藏","北京","上海","天津","重庆",'Unknown']
        self.metrics = [["all_time","query_time","nxd_1","adns_2_latency"]]
        self.starttime = starttime
        self.endtime = endtime
        self.curtime = int(time.time())
        if self.endtime == -1:
            self.endtime = self.curtime
        if self.starttime == -1:
            self.starttime = self.endtime - 24*60*60 #24h ago
        self.alldata = alldata
        self.datauri = datauri
        self.interval = interval
        self.isload = False
        self.targethosts = targethosts
        self.targetips = targetips
        self.data = []
        
    def loadData(self):
        '''
        如果是"all_data" 直接读json文件，返回
        如果是其他，会根据starttime endtime 筛选出一段数据
        '''
        self.isload = True
        if self.starttime > self.endtime:
            print("Warning: start time is greater than end time.")
            return []
        client = dnsdatabase.dnsdatabase(self.datauri)
        
        if self.alldata:
            tmp = client.dnsfiledata()
        else:
            tmp = client.dnsfiledata()
            #print(tmp)
            if self.targetips:
                tmp = tmp[tmp['monitor'].isin(self.targetips)]
            tmp = tmp.loc[self.starttime:self.endtime]
        whois = fastwhois.fastwhois()
        tmp['region'] = tmp['monitor'].map(lambda ip: whois.query(ip)["geo"] if isinstance(whois.query(ip), dict) else "Unknown")
        self.data = tmp[:]
        #return self.data
    
    def regionAgg(self, region="北京"):
        if region not in self.regions:
            raise Exception("unsupported region: " + region + "\nThe currently supported regions are: " + str(self.regions))
            
        whois = fastwhois.fastwhois()
        def timereg(ts, interval):
            return ts - ts%interval + interval//2
        if not self.isload:
            self.loadData()
        tmp = self.data.fillna({'region': 'Unknown'})
        tmp = tmp[tmp['region'].str.contains(region)]
        whois.update()
        return tmp
    
    def dns3tupleAgg(self, clientip, adns, domain):
        def timereg(ts, interval):
            return ts - ts%interval + interval//2
        
        if not self.isload:
            self.loadData()
        
        df = self.data.copy(deep=True)
        df = df[(df["monitor"==clientip]) & (df["adns"]==adns) & (df["domain"]==domain)]
        return df


    





 