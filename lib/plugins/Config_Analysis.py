#!/usr/bin/env python
# coding=utf-8 
import os

class Config_Analysis:
    def __init__(self):
        pass 

    def check_preload(self): 
        preload_env  = os.getenv('LD_PRELOAD') 
        preload_file = os.path.exists('/etc/ld.so.preload')
        if preload_env:
            print('  [1]PRELOAD环境变量检测    [ 存在风险 ]')
            print("  存在环境变量LD_PRELOAD: {}，请确认是否存在动态链接库劫持".format(preload_env)) 
        else:
            print('  [1]PRELOAD环境变量检测    [ OK ]') 

        if preload_file:
            print('  [2]PRELOAD配置文件检测    [ 存在风险 ]')
            print("  存在文件 /etc/ld.so.preload,请确认是否存在动态链接库劫持") 
        else:
            print('  [2]PRELOAD配置文件检测    [ OK ]')

    def run(self):
        print('\n安全相关配置检测开始')
        self.check_preload() 
