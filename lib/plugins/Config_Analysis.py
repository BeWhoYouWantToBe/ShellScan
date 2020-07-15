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
            print("存在环境变量LD_PRELOAD: {}，请确认是否存在动态链接库劫持".format(preload_env)) 
        if preload_file:
            print("存在文件 /etc/ld.so.preload,请确认是否存在动态链接库劫持") 

    def run(self):
        self.check_preload() 
