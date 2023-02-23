import json
import pandas as pd

def avg(nums):
            if not nums: return -1
            nums = [int(i) for i in nums]
            return sum(nums)/len(nums)

class dnsdatabase:
    def __init__(self, uri):
        self.uri = uri
    def dnsfiledata(self):
        '''
        直接读厂商上传到清华FTP服务器的 json 文件，并转化为pandas.DataFrame用于进一步数据分析
        '''
        with open(self.uri) as f:
            j = json.load(f)
        dfall = pd.DataFrame(j)
        # dfall = dfall.drop(['answers'],axis=1)
        dfall['collect_time'] = dfall['collect_time'].astype(int)
        dfall['collect_time'] = dfall['collect_time']//1000
        dfall = dfall.set_index(['collect_time'],drop=False)
        dfall = dfall.sort_index(axis=0) # 按 index 排序，默认升序
        dfall['query_time'] = dfall['query_time'].astype(int)
        dfall['nxd_1'] = dfall['nxd_1'].map(lambda cell: avg(cell.split(';')[1:]))
        dfall['adns_2_latency'] = dfall['adns_2_latency'].map(lambda cell: avg(cell.split(';')[1:]))
        return dfall