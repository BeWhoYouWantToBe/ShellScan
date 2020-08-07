#!/usr/bin/env python
# coding=utf-8 
from __future__ import print_function  
from __future__ import unicode_literals  
from lib.common import analysis_file,get_proc_info
import pdb  
import subprocess as sb 
import os 
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

class Proc_Analysis:
    def __init__(self):
        self.hide_pid = 0   
        self.cpu_level = 70
        self.mem_level = 70
        process = sb.Popen("ps aux",stdout=sb.PIPE,shell=True).communicate()[0].split('\n')[1:-1]
        self.ps_info = [i.split() for i in process]
        for i in range(len(self.ps_info)):
            self.ps_info[i][10] = (' ').join(self.ps_info[i][10:])
            self.ps_info[i] = self.ps_info[i][:11]    
        self.ps_info = { i[1]:i for i in self.ps_info } 

    def check_load(self):
        result = []
        for pid in self.ps_info.keys():
            if float(self.ps_info[pid][2]) > self.cpu_level:
                result.append(pid)
            elif float(self.ps_info[pid][3]) > self.mem_level:
                result.append(pid)
            else:
                pass  

        if result:
            print('  [1]挖矿病毒检测    [ 存在风险 ]') 
            for pid in result:
                get_proc_info(pid,self.ps_info[pid]) 
        else:
            print('  [1]挖矿病毒检测    [ OK ]')


    def check_reverse_shell(self):
        result = []
        for pid in self.ps_info.keys():
            if 'bash' in self.ps_info[pid][10]:
                fd = sb.Popen('ls -l /proc/{}/fd'.format(pid),shell=True,stdout=sb.PIPE).communicate()[0].split('\n')[1:3]
                have_socket = [True if 'socket' in j else False for j in fd]
                have_pipe = [True if 'pipe' in j else False for j in fd] 
                if have_socket[0] and have_socket[1]:
                    result.append(pid)
                elif have_pipe[0] and have_pipe[1]:
                    result.append(pid)
                else:
                    pass 
        if result:
            print('  [2]反弹SHELL检测    [ 存在风险 ]') 
            for pid in result:
                get_proc_info(pid,self.ps_info[pid]) 
        else:
            print('  [2]反弹SHELL检测   [ OK ]')

    def check_hide_proc(self): 
        ps_pid_list = self.ps_info.keys()
        proc_pid_list = [i for i in os.listdir('/proc') if i.isdigit()] 
        self.hide_pid = list(set(proc_pid_list).difference(set(ps_pid_list)))
        if self.hide_pid:
            print('  [3]隐藏进程检测    [ 存在风险 ]')
            for pid in self.hide_pid:
                print("PID为{}的进程为隐藏进程，可能为恶意进程，请进一步排查".format(pid))
                get_proc_info(pid,self.ps_info[pid],malicious=True)  
        else:
            print('  [3]隐藏进程检测    [ OK ]')

    def check_fileless(self):
        result = [] 
        fileless = sb.Popen('ls -alR /proc/*/exe 2> /dev/null | grep deleted',shell=True,stdout=sb.PIPE).communicate()[0]
        if fileless:
            print('  [4]无文件恶意软件检测    [ 存在风险 ]') 
            print('  ' + fileless) 
        else:
            print('  [4]无文件恶意软件检测    [ OK ]')





    def run(self):
        print('\n进程类检测开始') 
        self.check_load()
        self.check_hide_proc()
        self.check_reverse_shell() 
        self.check_fileless()

if __name__ == '__main__':
    PA = Proc_Analysis()
    PA.run()
