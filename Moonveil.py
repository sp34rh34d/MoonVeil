#!/usr/bin/env python3

import argparse
from core.core import *
from core.bind.bind import *
from core.msfvenom.msfvenom import *
from core.hoaxshell.hoaxshell import *
from core.reverse.linux.reverse import *
from core.reverse.windows.reverse import *
from core.reverse.mac.reverse import *
import sys

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-s','--shell',default='sh',help='Set shell - bash, /bin/bash, sh, /bin/sh, cmd, powershell (sh by default)')
parser.add_argument('mode',help='Set what kind of shell you want reverse,bind,msfvenom,hoaxshell')
parser.add_argument('--os',default='all',help='Set OS windows,linux,mac')
parser.add_argument('--lhost',default='10.10.14.15',help='Set listening IP')
parser.add_argument('--lport',default='9001',help='Set listening port')
parser.add_argument('--payload',default='all',help='Set payload language - python,ruby,php,etc (all by default)')
args = parser.parse_args()

MODE=args.mode
OS=args.os
LHOST=args.lhost
LPORT=args.lport
SHELL=args.shell
PAYLOAD=args.payload

shell_list=['bash','sh','/bin/bash','/bin/sh','cmd','powershell','pwsh','ash','bsh','csh','ksh','zsh','pdksh','tcsh','mksh','dash']



if MODE=="help":
	help.help()
	sys.exit()


main.banner()
print(f"""Mode: {TerminalColor.Green}{MODE}{TerminalColor.Reset}
OS: {TerminalColor.Green}{OS}{TerminalColor.Reset}
LHOST: {TerminalColor.Green}{LHOST}{TerminalColor.Reset}
LPORT: {TerminalColor.Green}{LPORT}{TerminalColor.Reset}
SHELL: {TerminalColor.Green}{SHELL}{TerminalColor.Reset}
PAYLOAD: {TerminalColor.Green}{PAYLOAD}{TerminalColor.Reset}
======================================================================================================""")

if MODE=="bind":
	bind_shell=bind(lport=LPORT)
	print(bind_shell.get())
if MODE=="msfvenom":
	if OS=='all' or OS=='linux':
		msfvenom_linux=msfvenom_linux(lport=LPORT,lhost=LHOST)
		print(msfvenom_linux.get())

	if OS=='all' or OS=='windows':
		msfvenom_windows=msfvenom_windows(lport=LPORT,lhost=LHOST)
		print(msfvenom_windows.get())

	if OS=='all' or OS=='mac':
		msfvenom_mac=msfvenom_mac(lport=LPORT,lhost=LHOST)
		print(msfvenom_mac.get())

if MODE=='hoaxshell':
	hoaxshell_shell=hoaxshell(lport=LPORT,lhost=LHOST)
	print(hoaxshell_shell.get())

if MODE=='reverse':
	if not SHELL in shell_list:
		print(f'{TerminalColor.Red}Invalid shell!{TerminalColor.Reset}')
		sys.exit()

	if OS=='all' or OS=='linux':
		reverse_linux=reverse_linux(lport=LPORT,lhost=LHOST,shell=SHELL,payload=PAYLOAD)
		reverse_linux.main()

	if OS=='all' or OS=='windows':
		reverse_windows=reverse_windows(lport=LPORT,lhost=LHOST,shell=SHELL,payload=PAYLOAD)
		reverse_windows.main()

	if OS=='all' or OS=='mac':
		reverse_mac=reverse_mac(lport=LPORT,lhost=LHOST,shell=SHELL,payload=PAYLOAD)
		reverse_mac.main()



