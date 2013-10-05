multiroute
==========

This project provides a Linux Lua script. It is a first attempt at a
tool that can modify routing tables as follows. If the tool is
successful, network interfaces will be "sticker". For example,
if a session recieves data on a give interface, it will usually
respond on the same interface. This will happen if a VPN is
turned on; or, at least this is the goal.


Usage:  
clone this git repo  
lua mroute.lua [COMMAND]  

where [COMMAND] is the command to bring up the new network

currently, this does nothing but list properties of the network
from whence it was started till it reaches end of execution.

