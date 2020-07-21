#!/usr/bin/env python
# coding=utf-8 
import os  
import pdb 
from lib.common import check_shell

class Backdoor_Analysis:
    def __init__(self):
        pass 

    def check_cron(self): 
        command = ['wget','curl','base64']
        risk = 0
        try:
            cron_dir_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/','/etc/cron.hourly/', '/etc/cron.monthly/']
            for cron_dir in cron_dir_list:
                for file in os.listdir(cron_dir):
                    path = cron_dir + file 
                    f = open(path)
                    for line in f.readlines():
                        result = check_shell(line)
                        if result:
                            risk = 1
                            print('  [1]定时任务检测    [ 存在风险 ]')
                            print('  检测到定时任务文件: {} 中存在反弹SHELL: {}，请进一步确认'.format(path,result.strip()))
                        else:
                            for i in command:
                                if i in line:
                                    risk = 1
                                    print('  [1]定时任务检测    [ 存在风险 ]')
                                    print '  检测到定时任务文件: {} 中存在敏感命令: {}, 请进一步确认'.format(path,i)
                                    break  
            if not risk:
                print('  [1]定时任务检测   [ OK ] ')



        except Exception,e:
            print e  

    def check_SSHwrapper(self):
        sshd = ['/sbin/sshd','/usr/sbin/sshd']
        try:
            for i in sshd:
                infos = os.popen("file {} 2>/dev/null".format(i)).read().splitlines()
                if ('ELF' not in infos[0]) and ('executable' not in infos[0]):
                    print('  [2]SSH Wrapper后门检测    [ 存在风险 ]')
                    print('  {} 被篡改,文件非可执行文件'.format(i)) 
                else:
                    print('  [2]SSH Wrapper后门检测    [ OK ]')
        except Exception,e:
            print(e) 

    def check_setuid(self):
        try:
            file_infos = os.popen("find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null | grep -vE 'pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps'").read().splitlines()
            if file_infos:
                print('  [3]suid权限检测    [ 存在风险 ]')
                for info in file_infos:
                    print('文件{}设置了suid属性，请确认是否为后门文件'.format(info))
            else:
                print('  [3]suid权限检测    [ OK ]')
        except Excpetion,e:
            print(e)

    def run(self):
        print('\n常见后门检测开始')
        self.check_cron()
        self.check_SSHwrapper()
        self.check_setuid()
