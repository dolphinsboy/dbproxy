#!/usr/bin/env python
#-*- coding:utf8-*-
import os
import sys

def conver(input_str):
    hex_list = []
    for i in input_str:
        hex_c = "%s" % hex(ord(i))
        hex_list.append(hex_c.replace("0x", "\\x"))

    print ''.join(hex_list)

if __name__ == '__main__':
    conver(sys.argv[1])
