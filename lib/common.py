#!/usr/bin/env python
# coding=utf-8 
import re
import os   
import pdb
import subprocess as sb    
from socket import inet_aton
from struct import unpack

def ip2long(ip_addr):
    return unpack("!L", inet_aton(ip_addr))[0]
    
def is_inner_ip(ip):
    if ip.startswith('169.254'):
        return True 
    else:
        ip = ip2long(ip)    
        return ip2long('127.0.0.0') >> 24 == ip >> 24 or ip2long('10.0.0.0') >> 24 == ip >> 24 or ip2long('172.16.0.0') >> 20 == ip >> 20 or ip2long('192.168.0.0') >> 16 == ip >> 16


def get_proc_info(pid,ps_info,malicious=False):
    try: 
        user = ps_info[0] 
        start_time = ps_info[8]
        ps_cmd = ps_info[10]
        cmdline = sb.Popen("cat /proc/{}/cmdline".format(pid),shell=True,stdout=sb.PIPE).communicate()[0].replace('\x00',' ')
        cwd = sb.Popen("ls -l /proc/{}/cwd".format(pid),shell=True,stdout=sb.PIPE).communicate()[0].split(' ')[-1]  
        if malicious:
            is_malicious = analysis_file('/proc/{}/exe'.format(pid))
            print("详情：\n 进程启动命令1：{}\n 进程启动命令2: {}\n 进程当前工作目录: {} 进程启动用户: {}\n 进程启动时间: {}\n 命中恶意特征: {}\n".format(ps_cmd,cmdline,cwd,user,start_time,is_malicious))  
        else:
            print("详情：\n 进程启动命令1：{}\n 进程启动命令2: {}\n 进程当前工作目录: {} 进程启动用户: {}\n 进程启动时间: {}\n".format(ps_cmd,cmdline,cwd,user,start_time)) 
    except:
        pass

def get_malicious_info():
    malicious_info = set()
    try:
         malware_path = './lib/mallcious/'
         for file in os.listdir(malware_path):
             with open(malware_path + file) as f:
                 for line in f:
                     malware = line.strip().replace('\n', '')
                     if len(malware) > 5:
                         if malware[0] != '#' and malware[0] != '.' and ('.' in malware):
                             malicious_info.add(malware) 
         return malicious_info
    except:
         return 


def analysis_file(file): 
    if not os.path.exists(file):
        return 
    elif os.path.isdir(file):
        return  
    elif (os.path.getsize(file) == 0) or round(os.path.getsize(file) / float(1024 * 1024)) > 10:
        return 
    else:
        strings = sb.Popen('strings {}'.format(file),shell=True,stdout=sb.PIPE).communicate()[0]
        malicious_info = get_malicious_info() 
        for malicious in malicious_info:
            if malicious in strings:
                print("文件: {} 匹配到恶意特征: {}".format(file,malicious))
                return malicious
        return  

def check_shell(content):                                                                                                                                                   
    try:
        if (('bash' in content) and (('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (('exec ' in content) and ('socket' in content)) or ('curl ' in content) or ('wget ' in content) or ('lynx ' in content) or ('bash -i' in content))) or (".decode('base64')" in content) or ("exec(base64.b64decode" in content):
            return content
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return content
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return content 
        elif (('wget ' in content) or ('curl ' in content)) and ((' -O ' in content) or (' -s ' in content)) and (' http' in content) and (('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or ('bash ' in content)):
            return content
        else:
            return False
    except:
        return False

if __name__ == '__main__': 
    is_intranet('100.10.10.10')
