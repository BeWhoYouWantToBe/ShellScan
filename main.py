#!/usr/bin/env python
# coding=utf-8
from __future__ import print_function 
from __future__ import unicode_literals  
from lib.plugins.Proc_Analysis import *
import os,time,optparse   

def main():
    parser = optparse.OptionParser()  

    print('Security Scan Start')  

    Proc_Analysis().run()

if __name__ == '__main__':
    main()
