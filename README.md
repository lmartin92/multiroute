multiroute
==========

This project takes a computer and goes thru it in a couple of
different states.
When started, only the original interfaces will be up, and it will
be given a command meant to bring up further interfaces.
When it brings up more interfaces it will tell the difference between
before and after and build up new routing tables as appropriate
such that traffic recieved on one interface is sent out thru the
same interface, same going for traffic sent.

Usage:

clone this git repo

lua mroute.lua [COMMAND]

where [COMMAND] is the command to bring up the new network

