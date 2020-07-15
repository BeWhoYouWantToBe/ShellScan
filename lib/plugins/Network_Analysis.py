#!/usr/bin/env python
# coding=utf-8 
import pdb
import subprocess as sb  
from lib.common import is_inner_ip

class Network_Analysis:

    def __init__(self):
        ss = sb.Popen('ss -anptu',shell=True,stdout=sb.PIPE).communicate()[0].split('\n')[1:-1]
        self.ss_info = [i.split() for i in ss] 

    def check_reverse_shell(self):
        for i in self.ss_info:
            try:
                inner = is_inner_ip(i[5].split(':')[0])
                if not inner:
                    print('网络链接中存在公网IP，请排查是否为反弹SHELL，详情：')
                    print(i) 
            except:
                continue

    def run(self):
        self.check_reverse_shell()
