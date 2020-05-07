#!/usr/bin/env python
# coding=utf-8 
from __future__ import print_function  
from __future__ import unicode_literals  
from lib.common import analysis_file
import pdb  
import subprocess as sb 
import os

class Proc_Analysis:
    def __init__(self):
        self.name = "进程安全检测" 
        self.hide_pid = 0  
        process = sb.Popen("ps aux",stdout=sb.PIPE,shell=True).communicate()[0].split('\n')[1:-1]
        self.proc_info = [i.split() for i in process]
        for i in range(len(self.proc_info)):
            self.proc_info[i][10] = (' ').join(self.proc_info[i][10:])
            self.proc_info[i] = self.proc_info[i][:11]

#    def check_reverse_shell(self): 
        

    def check_hide_proc(self): 
        ps_pid_list = [i[1] for i in self.proc_info]
        proc_pid_list = [i for i in os.listdir('/proc') if i.isdigit()] 
        self.hide_pid = list(set(proc_pid_list).difference(set(ps_pid_list)))
        if self.hide_pid:
            for i in self.hide_pid:
                print("PID为{}的进程为隐藏进程，可能为恶意进程，请进一步排查".format(i))
                cmdline = sb.Popen("cat /proc/{}/cmdline".format(i),shell=True,stdout=sb.PIPE).communicate()[0].replace('\x00',' ')
                cwd = sb.Popen("ls -l /proc/{}/cwd".format(i),shell=True,stdout=sb.PIPE).communicate()[0].split(' ')[-1] 
                malicious = analysis_file('/proc/{}/exe'.format(i))
                print("详情：\n 进程启动命令：{}\n 进程当前工作目录: {}\n 命中恶意特征: {}".format(cmdline,cwd,malicious)) 

    def run(self):
        print('进程安全检测开始') 
        self.check_hide_proc()
        print(self.proc_info)

if __name__ == '__main__':
    PA = Proc_Analysis()
    PA.run()
