import pandas as pd
import numpy as np
from collections import Counter,defaultdict
import os
from cachedipinfo import dnsfastwhois
FastWhois = dnsfastwhois.fastwhois()

class dnsresolutioninfo:
    def __init__(self):
        self.adnsdf = pd.DataFrame()
        self.clientdf = pd.DataFrame()
        self.df = pd.DataFrame()

    def getIPandProvince(self,ip_loc_list):
        table = []
        # 处理成 address province ISP 表
        for (ip, loc) in ip_loc_list:
            s = loc.split()
            province = ' '.join(s[:-1])
            table.append([ip,province]) 
        return table
    
    def getIPandLoction(self,ipset):
        ip_loc_list = []
        for ip in ipset:
            ip_loc_list.append((ip,FastWhois.query_loction(ip)))           
        add_pro_isp_df = pd.DataFrame(ip_loc_list)
        add_pro_isp_df.columns = ['ip','location']
        FastWhois.update()
        return add_pro_isp_df
        

    def ADNSInfoExtract(self,df):
        df.rename(inplace=True,columns={'开始时间':'time', '客户端地理位置':'egress_location', '请求接收端':'authoritative', 'cName':'domain', '请求发起端':'egress'})
        df = df.drop_duplicates(['egress','domain'])
        # 处理cName列，解析出C的IP
        def extract_ip(row):
            clientip = row['domain'].split('x')[0].replace('-','.')
            return clientip
        df['client_ip'] = df.apply(extract_ip,axis=1)
        df = df.drop_duplicates(['egress','client_ip'])
        # 改列排序 去domain
        df = df[['client_ip','egress', 'egress_location', 'authoritative', 'time']]
        self.adnsdf = df
        return self.adnsdf
        
        


    def clientInfoExtract(self,df):
        C_INGRESS = df[['monitor','ldns']]
        C_INGRESS.drop_duplicates(inplace=True)
        C_INGRESS.columns=['client_ip','ingress']
        self.clientdf = C_INGRESS
        return self.clientdf


    def infoMerge(self, adnsrawdf, clientrawdf):
        self.ADNSInfoExtract(adnsrawdf)
        self.clientInfoExtract(clientrawdf)

        # 收集所有需要解析地理位置的IP
        ips = set()
        ips.update(self.adnsdf['client_ip'])
        ips.update(self.adnsdf['egress'])
        ips.update(self.adnsdf['authoritative'])
        ips.update(self.clientdf['client_ip'])
        ips.update(self.clientdf['ingress'])        
        add_pro_isp_df = self.getIPandLoction(ips)

        self.adnsdf = pd.merge(self.adnsdf,add_pro_isp_df,left_on='client_ip',right_on='ip',how='left')
        self.adnsdf = pd.merge(self.adnsdf,add_pro_isp_df,left_on='egress',right_on='ip',how='left')
        self.adnsdf = pd.merge(self.adnsdf,add_pro_isp_df,left_on='authoritative',right_on='ip',how='left')
        self.adnsdf.columns = ['client_ip', 'egress', 'egress_location', 'authoritative', 'time',
                    'C_IP','C_LOCATION','E_IP','E_LOCATION', 'A_IP', 'A_LOCATION']
        # 融合adns和client两端的数据
        self.df = pd.merge(self.adnsdf,self.clientdf,left_on='client_ip',right_on = 'client_ip',how = 'left')
        self.df = pd.merge(self.df,add_pro_isp_df,left_on='ingress',right_on='ip',how='left')
        self.df.columns = ['client_ip', 'egress', 'egress_location', 'authoritative', 'time',
                    'C_IP','C_LOCATION','E_IP','E_LOCATION', 'A_IP', 'A_LOCATION','IN_IP','IN_IP2','IN_LOCATION']
        self.df = self.df[['time','C_IP','C_LOCATION','IN_IP','IN_LOCATION','E_IP','E_LOCATION', 'A_IP', 'A_LOCATION']]
        return self.df

