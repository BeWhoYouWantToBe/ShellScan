#!/usr/bin/env python
# coding=utf-8
import os  
import subprocess as sb 

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
    with open('/tmp/shell.txt') as f:
        for line in f:
            content = check_shell(line.strip())
            print(content)
#    analysis_file('/tmp/install_agent/install_agent.sh') 
