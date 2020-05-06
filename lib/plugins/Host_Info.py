#!/usr/bin/env python
# coding=utf-8 
import platform

class Host_Info:

    def __init__(self):
        self.hostname = platform.node()
        self.ip = ""
        self.version = ""
