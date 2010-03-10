#!/usr/bin/env python
import os, sys

env = Environment()

env.ParseConfig('pkg-config --cflags --libs glib-2.0')
env.Append(CFLAGS="-ggdb")
env.Append(LIBS='pcap')
env.Append(LIBS='event')
env.Append(LIBS='rt')
env.Append(LINKFLAGS='-static')
env.Program('trafan', ['trafan.c'])
