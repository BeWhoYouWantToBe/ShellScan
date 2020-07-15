#!/usr/bin/env python
# coding=utf-8 
from __future__ import print_function  
from __future__ import unicode_literals  
from lib.common import analysis_file,get_proc_info
import pdb  
import subprocess as sb 
import os

class Proc_Analysis:
    def __init__(self):
        self.name = "进程安全检测" 
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
        for pid in self.ps_info.keys():
            if float(self.ps_info[pid][2]) > self.cpu_level:
                print("PID为{}的进程CPU负载过高，可能为挖矿进程，请进一步排查".format(self.ps_info[pid][1])) 
                get_proc_info(pid,self.ps_info[pid])
            elif float(self.ps_info[pid][3]) > self.mem_level:
                print("PID为{}的进程内存负载过高，可能为挖矿进程，请进一步排查".format(self.ps_info[pid][1])) 
                get_proc_info(pid,self.ps_info[pid])
            else:
                pass


    def check_reverse_shell(self):
        for pid in self.ps_info.keys():
            if 'bash' in self.ps_info[pid][10]:
                fd = sb.Popen('ls -l /proc/{}/fd'.format(pid),shell=True,stdout=sb.PIPE).communicate()[0].split('\n')[1:3]
                have_socket = [True if 'socket' in j else False for j in fd]
                have_pipe = [True if 'pipe' in j else False for j in fd] 
                if have_socket[0] and have_socket[1]:
                    print("PID为{}的进程可能为反弹SHELL进程，请进一步排查".format(pid))
                    get_proc_info(pid,self.ps_info[pid])
                elif have_pipe[0] and have_pipe[1]:
                    print("PID为{}的进程可能为反弹SHELL进程，请进一步排查".format(pid))
                    get_proc_info(pid,self.ps_info[pid])
                else:
                    pass

    def check_hide_proc(self): 
        ps_pid_list = self.ps_info.keys()
        proc_pid_list = [i for i in os.listdir('/proc') if i.isdigit()] 
        self.hide_pid = list(set(proc_pid_list).difference(set(ps_pid_list)))
        if self.hide_pid:
            for pid in self.hide_pid:
                print("PID为{}的进程为隐藏进程，可能为恶意进程，请进一步排查".format(pid))
                get_proc_info(pid,self.ps_info[pid],malicious=True)

    def run(self):
        print('进程安全检测开始') 
        self.check_load()
        self.check_hide_proc()
        self.check_reverse_shell()

if __name__ == '__main__':
    PA = Proc_Analysis()
    PA.run()
