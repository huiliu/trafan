#!/usr/bin/env python
import os, sys

env = Environment()

env.ParseConfig('pkg-config --cflags --libs glib-2.0')
env.Append(CFLAGS="-O3")
env.Append(LIBS='pcap')
env.Append(LIBS='event')

if 'LDFLAGS' in os.environ:
    env.Append(LINKFLAGS=os.environ['LDFLAGS'])

if 'CFLAGS' in os.environ:
    env.Append(CFLAGS=os.environ['CFLAGS'])

if ARGUMENTS.get('static') and ARGUMENTS.get('static') == 'yes':
    env.Append(LIBS='rt')
    env.Append(LINKFLAGS='-static')

env.Program('trafan', ['trafan.c'])
