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
    banner = '''
         ad88888ba  88        88 88888888888 88          88
        d8"     "8b 88        88 88          88          88
        Y8,         88        88 88          88          88
        `Y8aaaaa,   88aaaaaaaa88 88aaaaa     88          88
          `"""""8b, 88""""""""88 88"""""     88          88
                `8b 88        88 88          88          88
        Y8a     a8P 88        88 88          88          88
         "Y88888P"  88        88 88888888888 88888888888 88888888888

                                                                      {author:patrickstar}

         ad88888ba    ,ad8888ba,        db        888b      88
        d8"     "8b  d8"'    `"8b      d88b       8888b     88
        Y8,         d8'               d8'`8b      88 `8b    88
        `Y8aaaaa,   88               d8'  `8b     88  `8b   88
          `"""""8b, 88              d8YaaaaY8b    88   `8b  88
                `8b Y8,            d8""""""""8b   88    `8b 88
        Y8a     a8P  Y8a.    .a8P d8'        `8b  88     `8888
         "Y88888P"    `"Y8888Y"' d8'          `8b 88      `888
        '''
    print(banner)
    parser = optparse.OptionParser()  

    Network_Analysis().run()
    Proc_Analysis().run()
    Config_Analysis().run() 
    File_Analysis().run() 
    Log_Analysis().run() 
    Backdoor_Analysis().run()

if __name__ == '__main__':
    main()
