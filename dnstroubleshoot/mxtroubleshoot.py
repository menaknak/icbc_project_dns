import numpy as np
import time
from dataagg import dnsaggregation
import base64

class mxtroubleshoot:
    '''
    检测是否发生了CNAME抢占MX记录
    '''
    def __init__(self) -> None:
        pass 

    def detect(self, data):
        '''
        Param:
            data: DataFrame或者字典 类，一段时间窗口内的数据库记录，记录默认时间窗口为1（即每次默认只检查一条记录）
        Return:
            alarm: Bools类，True 报警
        '''
        ans = self.display_answer(data)
        if 'CNAME' in ans:
            print('发生了CNAME抢占')


    def display_answer(self, data):
        '''
        单条数据，读取并解码DNS answer字段
        '''
        ans = str(base64.b64decode(data['answers']))
        return ans

 