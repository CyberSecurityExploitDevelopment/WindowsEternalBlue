# WindowsEternalBlue
Fully Functional MS17-10 EternalBlue Exploit Written in C++ on windows for windows

This was developed previously and separately from https://github.com/bhassani/EternalBlueC and this version of eternalblue in C++ uses a fully functioning minimalist implementation of the SMB protocol.

This EternalBlue creates the correct \\UNCPATH\\IPC$ dynamically, TID, UID, MID, PID are fully functional as well.
This EternalBlue is Similar to https://github.com/bhassani/EternalBlueC except that it goes one step further than wannacry and it is almost an exact replica of the original eternalblue in functionality.

It builds well on Visual Studio 2019 and is thread safe by design however it is only designed to be run on windows 10 x64.

It can install, uninstall, as well as ping the DoublePulsar Backdoor, and it also has an MS17-10 vulnerability check before it will procede with an exploit attempt.

usage is as follows:

//EternalBlue.exe < ip address > [optional <--killdopu> to kill doublepulsar if its already installed]

Happy Hunting.
