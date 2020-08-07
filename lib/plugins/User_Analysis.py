#!/usr/bin/env python
# coding=utf-8 
import os 
import subprocess as sb

class User_Analysis:
    def __init__(self):
        pass 

    def check_newuser(self): 
        process = sb.Popen("diff /etc/passwd /etc/passwd-",stdout=sb.PIPE,shell=True).communicate()[0]
        if process:
            print('  [1]新增用户检测    [ 存在风险 ]')
            print('  请确认以下用户是否合法')
            print('  {}'.format(process))
        else:
            print('  [1]新增用户检测    [ OK ]')

    def run(self):
        print('\n用户检测开始')
        self.check_newuser()
