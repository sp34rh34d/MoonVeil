class TerminalColor:
	Black = '\033[30m'
	Red = '\033[31m'
	Green = '\033[32m'
	Orange = '\033[33m'
	Blue = '\033[34m'
	Purple = '\033[35m'
	Reset = '\033[0m'
	Cyan = '\033[36m'
	LightGrey = '\033[37m'
	DarkGrey = '\033[90m'
	LightRed = '\033[91m'
	LightGreen = '\033[92m'
	Yellow = '\033[93m'
	LightBlue = '\033[94m'
	Pink = '\033[95m'
	LightCyan = '\033[96m'

class main():
	def banner():
		print(f'''
@@@@@@@@@@    @@@@@@    @@@@@@   @@@  @@@  @@@  @@@  @@@@@@@@  @@@  @@@       
@@@@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@  @@@  @@@@@@@@  @@@  @@@       
@@! @@! @@!  @@!  @@@  @@!  @@@  @@!@!@@@  @@!  @@@  @@!       @@!  @@!       
!@! !@! !@!  !@!  @!@  !@!  @!@  !@!!@!@!  !@!  @!@  !@!       !@!  !@!       
@!! !!@ @!@  @!@  !@!  @!@  !@!  @!@ !!@!  @!@  !@!  @!!!:!    !!@  @!!       
!@!   ! !@!  !@!  !!!  !@!  !!!  !@!  !!!  !@!  !!!  !!!!!:    !!!  !!!       
!!:     !!:  !!:  !!!  !!:  !!!  !!:  !!!  :!:  !!:  !!:       !!:  !!:       
:!:     :!:  :!:  !:!  :!:  !:!  :!:  !:!   ::!!:!   :!:       :!:   :!:      
:::     ::   ::::: ::  ::::: ::   ::   ::    ::::     :: ::::   ::   :: ::::  
 :      :     : :  :    : :  :   ::    :      :      : :: ::   :    : :: : :  
Coded by:{TerminalColor.Red} Adonis Izaguirre {TerminalColor.Reset} Email:{TerminalColor.Red} adonis.izaguirre@kapa7.com / adons@outlook.com {TerminalColor.Reset}
twitter: {TerminalColor.Red}@AdonsIzaguirre{TerminalColor.Reset}
Welcome to MoonVeil v1.0 [{TerminalColor.Green}https://github.com/AdonsIzaguirre/MoonVeil{TerminalColor.Reset}]
======================================================================================================''')                                                                            

class help():
	def help():
		print(f"""
Usage:
    python3 Moonveil.py [module] [args]

Modules
	bind         Show only bind code
	reverse      Show only reverse shell code
	msfvenom     Show only msfvenom generator code
	hoaxshell    Show only hoaxshell code
	help         Help about any command

Optional args:
	--shell      Select interpreter [cmd, sh, bash, /bin/bash, /bin/sh, powershell, etc]
	--payload    Select payload type [all, python, socket, rvim, vim, openssl, rview, view, ksh, gimp, gdb, irb, cpan, easyinstall, bash, netcat, c, c#, haskell, perl, php, ruby, socat, nodejs, java, javascript, telnet, zsh, lua, golang, vlang, awk, dart]
	--os         Select target arc [linux, windows, mac]

Examples:
	python3 Moonveil.py reverse --os linux --payload php --shell sh

	python3 Moonveil.py reverse --os linux --payload openssl --shell /bin/bash

	python3 Moonveil.py reverse --os linux --payload awk

	python3 Moonveil.py msfvenom --os windows 

			""")