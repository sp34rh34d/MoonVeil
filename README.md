# MoonVeil
offline reverse shell generator tool
```
Usage:
    python3 Moonveil.py [module] [args]

Modules
	bind         Show only bind code
	reverse      Show only reverse shell code
	msfvenom     Show only msfvenom generator code
	hoaxshell    Show only hoaxshell code
	help         Help about any command

Optional args:
	--shell      Select interpreter [cmd, sh, bash, /bin/bash, /bin/sh, powershell, pwsh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, mksh, dash]
	--payload    Select payload type [all, python, socket, rvim, vim, openssl, rview, view, ksh, gimp, gdb, irb, cpan, easyinstall, bash, netcat, c, c#, haskell, perl, php, ruby, socat, nodejs, java, javascript, telnet, zsh, lua, golang, vlang, awk, dart]
	--os         Select target arc [linux, windows, mac]
	--lhost      Set attacker IP
	--lport      Set attacker port

Examples:
	python3 Moonveil.py reverse --os linux --payload php --shell sh

	python3 Moonveil.py reverse --os linux --payload openssl --shell /bin/bash

	python3 Moonveil.py reverse --os linux --payload awk

	python3 Moonveil.py msfvenom --os windows
```
<img width="1680" alt="Screenshot 2023-03-22 at 23 53 00" src="https://user-images.githubusercontent.com/94752464/227115769-9aaaf295-84b4-4c6d-8745-8bb6884f8d90.png">

<img width="1042" alt="Screenshot 2023-03-22 at 16 10 59" src="https://user-images.githubusercontent.com/94752464/227052241-e22d585a-c661-49d0-b859-2abbff87e85e.png">

<img width="1400" alt="Screenshot 2023-03-22 at 16 12 00" src="https://user-images.githubusercontent.com/94752464/227052268-deb8a64a-016e-479e-8567-ebbe0e2f1f74.png">
     
<img width="1508" alt="Screenshot 2023-03-22 at 16 21 19" src="https://user-images.githubusercontent.com/94752464/227052324-148c2f57-633b-4cd2-85b1-6598e5238594.png">



