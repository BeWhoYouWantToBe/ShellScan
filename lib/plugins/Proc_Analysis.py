#!/usr/bin/env python
# coding=utf-8 
from __future__ import print_function  
from __future__ import unicode_literals 
import pdb 
import subprocess as sb 
import os

class Proc_Analysis:
    def __init__(self):
        self.name = "进程安全检测" 

    def check_hide_proc(self): 
        ps_pid_list = sb.Popen("ps -ef | awk '{print $2}'",stdout=sb.PIPE,shell=True).communicate()[0].splitlines()[1:]  
        proc_pid_list = [i for i in os.listdir('/proc') if i.isdigit()] 
        hide_pid = list(set(proc_pid_list).difference(set(ps_pid_list)))
        hide_pid = ['1550']
        if hide_pid:
            for i in hide_pid:
                print("PID为{}的进程为隐藏进程，可能为恶意进程，请进一步排查".format(i))
                cmdline = sb.Popen("cat /proc/{}/cmdline".format(i),shell=True,stdout=sb.PIPE).communicate()[0].replace('\x00',' ')
                cwd = sb.Popen("ls -l /proc/{}/cwd".format(i),shell=True,stdout=sb.PIPE).communicate()[0].split(' ')[-1] 
                print("详情：\n 进程启动命令：{}\n 进程当前工作目录: {}\n".format(cmdline,cwd)) 

    def run(self):
        print('进程安全检测开始') 
        self.check_hide_proc()

if __name__ == '__main__':
    PA = Proc_Analysis()
    PA.run()
