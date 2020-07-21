#!/usr/bin/env python
# coding=utf-8 
import pdb
import subprocess as sb  
from lib.common import is_inner_ip

class Network_Analysis:

    def __init__(self):
        ss = sb.Popen('ss -anptu | egrep "ESTAB|UNCONN"',shell=True,stdout=sb.PIPE).communicate()[0].split('\n')[1:-1]
        self.ss_info = [i.split() for i in ss] 

    def check_reverse_shell(self):
        result = []
        for i in self.ss_info:
            try:
                inner = is_inner_ip(i[5].split(':')[0])
                if not inner:
                    result.append(i)
            except:
                continue 
        
        if result:
            print('  [1]反弹SHELL检测    [ 存在风险 ]')
            for i in result:
                print(i) 
        else:
            print('  [1]反弹SHELL检测    [ OK ]')

    def run(self):
        print('网络链接类检测开始')
        self.check_reverse_shell()
