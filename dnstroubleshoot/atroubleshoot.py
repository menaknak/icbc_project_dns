import numpy as np
import pandas as pd
import time
from dataagg import dnsaggregation
import base64
from anomalydetection import detection

class atroubleshoot:
    '''
    实例化一次这个排障类，就可以对无数条曲线用
    '''
    def __init__(self) -> None:
        self.detector = detection.timingdetection()
        self.metrics = ["all_time","query_time","nxd_1","adns_2_latency"]
    
    def anomaly_detect(self, datas, metric):
        if metric not in self.metrics:
            raise Exception("unsupported metric: " + metric + "\nThe currently supported metrics are: " + str(self.metrics))
        df = datas[["collect_time",metric]]
        tuples = [tuple(x) for x in df.values]
        self.detector.statslabel = False # 因为每次喂的是不一样的指标，所以stats每次都要更新一下，置statslabel为False即可更新
        tooBig, tooSmall = self.detector.gaussDetect(tuples)
        return (tooBig, tooSmall)
    
    # def check_resolved_ip(data):  
    #     ans = str(base64.b64decode(data['answers']))
    #     if 'CNAME' in ans: return True # 如果解析出来CNAME链，则是CDN分配的边缘服务器，属于正常情况
    #     ips = data['ips'].split(';')
    #     ips.pop()
    #     for ip in ips:
    #         if ip not in ipdic[data['domain']]: #ipdic是所有域名下的白名单IP
    #             return False #DNS劫持
    #     return True

    def detect(self, datas):
        '''
        Param:
            datas: DataFrame或字典 类，一段时间窗口内的数据库记录，窗口大小为datas的长度
        Return:
            alarm: Bools类，True 报警
            
        故障诊断逻辑：传入一整段数据（pandas.DataFrame类型），可以是多天的连续数据（按地区聚合），对这段datas进行异常检测，然后x坐标存在一个list里面，每检查一个指标就遍历x坐标在不在异常list里面
        这里传进来的是完整的数据表，所有字段都有，可以做完整的故障树
        本函数会调用以上4个函数
        厂商 nxd_1 超时会有什么反馈？ 脚本工具是写 -1
        '''
        CL_tooBig, CL_tooSmall = self.anomaly_detect(datas,"nxd_1")
        CT_tooBig, CT_tooSmall = self.anomaly_detect(datas,"adns_2_latency")
        CLTCDN_tooBig, CLTCDN_tooSmall = self.anomaly_detect(datas,"query_time")

        #for data in datas: # 这个不能直接这么遍历，对于DataFrame对象，要 iterrows
        for idx, data in datas.iterrows():

            # if not self.check_resolved_ip(data): # 目前没有白名单，无法做对照
            #     print('DNS劫持') 

            t = data['collect_time']
            cl = data['nxd_1']
            if cl<0: 
                print('LDNS故障')
            elif cl>100 and (t,cl) in CL_tooBig:
                print('C-L网络拥塞: ',(t,cl))
            else:
                # phase2 adns_2_latency
                ct = data['adns_2_latency']
                if ct<0:
                    print(data['adns'],'ADNS宕机')
                elif (t,ct) in CT_tooBig:
                    print('C-T网络拥塞:',(t,ct))
                else:
                    # phase 3 CLTCDN
                    cltcdn = data['query_time']
                    if (t,cltcdn) in CLTCDN_tooBig:
                        print('DNS查询链路网络拥塞，请检查CDN智能DNS配置: ',(t,cltcdn))