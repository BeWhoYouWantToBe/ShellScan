#!/usr/bin/env python
# coding=utf-8 
import os  
import pdb 
from lib.common import check_shell

class Backdoor_Analysis:
    def __init__(self):
        pass 

    def check_cron(self): 
        try:
            cron_dir_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/','/etc/cron.hourly/', '/etc/cron.monthly/']
            for cron_dir in cron_dir_list:
                for file in os.listdir(cron_dir):
                    path = cron_dir + file 
                    f = open(path)
                    for line in f.readlines():
                        result = check_shell(line)
                        if result:
                            print '检测到定时任务文件: {} 中存在反弹SHELL: {}，请进一步确认'.format(path,result.strip()) 
        except Exception,e:
            print e  

    def check_SSHwrapper(self):
        sshd = ['/sbin/sshd','/usr/sbin/sshd']
        try:
            for i in sshd:
                infos = os.popen("file {} 2>/dev/null".format(i)).read().splitlines()
                if ('ELF' not in infos[0]) and ('executable' not in infos[0]):
                    print('{} 被篡改,文件非可执行文件'.format(i))
        except Exception,e:
            print(e)

    def run(self):
        print('常见后门检测开始')
        self.check_cron()
        self.check_SSHwrapper()
