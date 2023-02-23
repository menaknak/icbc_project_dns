'''
本脚本为anomalydetection模块的用法示例
'''

from anomalydetection import detection

# 模拟数据,坐标 x=5，x=9 异常
x = [i for i in range(20)]
y = [1,]*20
y[5]=10
y[9]=-100

# 实例化检测器 detector
detector = detection.timingdetection()

# 将数据整合成投喂需要的格式 [(x1,y1),(x2,y2),...]
xy = list(zip(x,y))

# 给检测器投喂数据，记录过大值，和过小值
tooBig, tooSmall = detector.gaussDetect(xy)

