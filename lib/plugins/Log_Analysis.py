#!/usr/bin/env python
# coding=utf-8
import os
import subprocess as sb 
from lib.common import *

class Log_Analysis:
    def __init__(self): 
        self.ssh_log = sb.Popen('grep "Accepted password" /var/log/secure',shell=True,stdout=sb.PIPE).communicate()[0].strip().split('\n')

    def check_ip(self):
        for log in self.ssh_log:
            ip = log.split()[8]
            intranet = is_inner_ip(ip)
            if not intranet:
                print("存在外网IP成功登录SSH，请进一步排查，详情：")
                print(log)

    def run(self):
        print("日志安全检测开始")
        self.check_ip()
        print
