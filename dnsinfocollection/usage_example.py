# 本模块的用法示例
# 模块的作用：将client端的拨测数据和ADNS端的数据整合成一个表，
# 输入是pandas.DataFrame类型的两端数据，输出是pandas.DataFrame类型的整合表

import pandas as pd
from dnsinfocollection import dnsresolutioninfo

info = dnsresolutioninfo.dnsresolutioninfo()

adnsdataframe = pd.DataFrame(一段时间的ADNS端表数据)
clientdataframe = pd.DataFrame(同一段时间的client端表数据)

merged = info.infoMerge(adnsdataframe,clientdataframe)