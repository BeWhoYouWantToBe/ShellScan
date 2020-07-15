#!/usr/bin/env python
# coding=utf-8
from __future__ import print_function 
from __future__ import unicode_literals  
from lib.plugins.Proc_Analysis import *  
from lib.plugins.Config_Analysis import *  
from lib.plugins.File_Analysis import * 
from lib.plugins.Log_Analysis import * 
from lib.plugins.Network_Analysis import * 
from lib.plugins.Backdoor_Analysis import *
import os,time,optparse   

def main():
    parser = optparse.OptionParser()  

    print('Security Scan Start')  

    Network_Analysis().run()
    Proc_Analysis().run()
    Config_Analysis().run() 
    File_Analysis().run() 
    Log_Analysis().run() 
    Backdoor_Analysis().run()

if __name__ == '__main__':
    main()
