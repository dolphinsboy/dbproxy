#!/usr/bin/env python
#-*- coding:utf8 -*-
import os
import sys

def conver(in_str):
    in_str= in_str.replace(' ','')

    if in_str.startswith("0x"):
        input_list = in_str.split("0x")[1:]
    else:
        input_list = in_str.split("\\x")[1:]

    convert_list = []
    for byte in input_list:
        convert_list.append('%c' % int(byte,16))

    print ''.join(convert_list)
    print len(convert_list)

if __name__ == '__main__':

    in_str = ''.join(sys.argv[1:])
    ret = conver(in_str)

