#!/usr/bin/env python
# coding=utf-8
import argparse   
import pdb 

def cmd_parse():
    parser = argparse.ArgumentParser(description='User information') 
    parser.add_argument('-h','--help',dest='help',action='store',help='python main.py',default=[]) 

    args = parser.parse_args() 

    if not any(args.__dict__.values()):
        parser.print_help() 
        raise SystemExit 

    return args 



if __name__=='__main__':
    args = cmd_parse()  
    print(args)
