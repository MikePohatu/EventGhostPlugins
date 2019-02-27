# -*- coding: utf-8 -*-
#
# This file is a plugin for EventGhost.
# Copyright (C) 2005-2009 Lars-Peter Voss <bitmonster@eventghost.org>
#
# This plugin is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the
# Free Software Foundation;
#
# EventGhost is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# This plugin is built using code from the default NetworkReceiver and Broadcaster plugins. The intention of this plugin
# is to make traversing firewalls easier by being able to have a machine in a subnet act as a relay for messages you 
# would normal use the Broadcaster plugin for

import eg

eg.RegisterPlugin(
    name = "Network Event Relay",
    description = "Receives events from Network Event Sender plugins and relays the message via UDP broadcast",
    version = "1.0",
    author = "Mike Pohatu",
    guid = "{F537B1B4-7B32-4364-B034-D2A706D91252}",
    canMultiLoad = True,
    icon = (
        "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABmJLR0QAAAAAAAD5Q7t/"
        "AAAACXBIWXMAAAsSAAALEgHS3X78AAAAB3RJTUUH1gIQFgQb1MiCRwAAAVVJREFUOMud"
        "kjFLw2AQhp8vif0fUlPoIgVx6+AgopNI3fwBViiIoOAgFaugIDhUtP4BxWDs4CI4d3MR"
        "cSyIQ1tDbcHWtjFI4tAWG5pE8ca7997vnrtP4BOZvW0dSBAcZ0pAMTEzPUs4GvMsVkvP"
        "6HktGWRAOBpjIXVNKOSWWdYXN7lFAAINhBCEQgqxyTHAAQQAD/dFbLurUYJYT7P7TI2C"
        "VavwIiZodyyaH6ZLo/RZVTXiOYVhGOh5jcpbq5eRAXAc5wdBVSPMLR16GtxdbgJgN95d"
        "OxicACG6bPH4uIu1UHjE7sFqR/NDVxhaoixLvFYbtDufNFtu1tzxgdeAaZfBU7ECTvd1"
        "WRlxsa4sp1ydkiRxkstmlEFRrWT4nrRer3vmlf6mb883fK8AoF1d+Bqc6Xkt+cufT6e3"
        "dnb9DJJrq+uYpunZ2WcFfA0ol8v8N5Qgvr/EN8Lzfbs+L0goAAAAAElFTkSuQmCC"
    ),
    url = "https://github.com/MikePohatu/EventGhostPlugins",
)

import wx
import asynchat
import asyncore
from hashlib import md5
import random
import socket


class Text:
    tcpPort = "TCP Port:"
    password = "Password:"
    eventPrefix = "Event Prefix:"
    tcpBox = "TCP/IP Settings"
    securityBox = "Security"
    eventGenerationBox = "Event generation"

    relay = "Relay"
    broadcastAddr = "Broadcast Address:"
    udpPort = "UDP port: (0 = default)"
    delim = "Payload delimiter"
    zone = "Broadcast zone:"
    listenAddr = "Listening address:"


DEBUG = False
if DEBUG:
    log = eg.Print
else:
    def log(dummyMesg):
        pass


class ServerHandler(asynchat.async_chat):
    """Telnet engine class. Implements command line user interface."""

    def __init__(self, sock, addr, password, plugin, server):
        log("Server Handler inited")
        self.plugin = plugin

        # Call constructor of the parent class
        asynchat.async_chat.__init__(self, sock)

        # Set up input line terminator
        self.set_terminator('\n')

        # Initialize input data buffer
        self.data = ''
        self.state = self.state1
        self.ip = addr[0]
        self.payload = [self.ip]
        #self.cookie = hex(random.randrange(65536))
        #self.cookie = self.cookie[len(self.cookie) - 4:]
        self.cookie = format(random.randrange(65536), '04x')
        self.hex_md5 = md5(self.cookie + ":" + password).hexdigest().upper()


    def handle_close(self):
        self.plugin.EndLastEvent()
        asynchat.async_chat.handle_close(self)


    def collect_incoming_data(self, data):
        """Put data read from socket to a buffer
        """
        # Collect data in input buffer
        log("<<" + repr(data))
        self.data = self.data + data


    if DEBUG:
        def push(self, data):
            log(">>", repr(data))
            asynchat.async_chat.push(self, data)


    def found_terminator(self):
        """
        This method is called by asynchronous engine when it finds
        command terminator in the input stream
        """
        # Take the complete line
        line = self.data

        # Reset input buffer
        self.data = ''

        #call state handler
        self.state(line)


    def initiate_close(self):
        if self.writable():
            self.push("close\n")
        #asynchat.async_chat.handle_close(self)
        self.plugin.EndLastEvent()
        self.state = self.state1


    def state1(self, line):
        """
        get keyword "quintessence\n" and send cookie
        """
        if line == "quintessence":
            self.state = self.state2
            self.push(self.cookie + "\n")
        else:
            self.initiate_close()


    def state2(self, line):
        """get md5 digest
        """
        line = line.strip()[-32:]
        if line == "":
            pass
        elif line.upper() == self.hex_md5:
            self.push("accept\n")
            self.state = self.state3
        else:
            eg.PrintError("NetworkReceiver md5 error")
            self.initiate_close()


    def state3(self, line):
        line = line.decode(eg.systemEncoding)
        if line == "close":
            self.initiate_close()
        elif line[:8] == "payload ":
            self.payload.append(line[8:])
        else:
            if line == "ButtonReleased":
                self.plugin.EndLastEvent()
            else:
                if self.payload[-1] == "withoutRelease":
                    self.plugin.TriggerEnduringEvent(line, self.payload)
                else:
                    self.plugin.TriggerEvent(line, self.payload)
            self.bcastSend(line, self.payload)
            #self.payload = [self.ip]
    
    
    def bcastSend(self, eventString, payload=None):
        #log("bcastSend: " + self.plugin.zone + ":" + self.plugin.udpport,eventString)
        addr = (self.plugin.zone, self.plugin.udpport)
        UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create socket
        UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #if (payload==None):
        UDPSock.sendto(eg.ParseString(eventString),addr)
        #else:
        #    UDPSock.sendto(eg.ParseString(eventString)+self.plugin.payDelim+eg.ParseString(payload),addr)
        log("sent")
        UDPSock.close()


class Server(asyncore.dispatcher):

    def __init__ (self, port, password, handler):
        self.handler = handler
        self.password = password

        # Call parent class constructor explicitly
        asyncore.dispatcher.__init__(self)

        # Create socket of requested type
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)

        # restart the asyncore loop, so it notices the new socket
        eg.RestartAsyncore()

        # Set it to re-use address
        #self.set_reuse_addr()

        # Bind to all interfaces of this host at specified port
        self.bind(('', port))

        # Start listening for incoming requests
        #self.listen (1024)
        self.listen(5)


    def handle_accept (self):
        """Called by asyncore engine when new connection arrives"""
        # Accept new connection
        log("handle_accept")
        (sock, addr) = self.accept()
        ServerHandler(
            sock,
            addr,
            self.password,
            self.handler,
            self
        )	



class NetworkRelay(eg.PluginBase):
    text = Text

    def __init__(self):
        self.AddEvents()

    def __start__(self, port, password, prefix, udpport, zone, payDelim):
        self.port = port
        self.password = password
        self.info.eventPrefix = prefix
        self.udpport = udpport
        self.zone = zone
        self.payDelim = payDelim
        
        try:
            self.server = Server(self.port, self.password, self)
        except socket.error, exc:
            raise self.Exception(exc[1])


    def __stop__(self):
        if self.server:
            self.server.close()
        self.server = None


    def Configure(self, port=1024, password="", prefix="RELAY", udpport=1234, zone="255.255.255.255", payDelim="&&"):
        text = self.text
        panel = eg.ConfigPanel()
            
        portCtrl = panel.SpinIntCtrl(port, max=65535)
        passwordCtrl = panel.TextCtrl(password, style=wx.TE_PASSWORD)
        eventPrefixCtrl = panel.TextCtrl(prefix)
        st1 = panel.StaticText(text.tcpPort)
        st2 = panel.StaticText(text.password)
        st3 = panel.StaticText(text.eventPrefix)
        
        """ UDP part """
        udpPortCtrl = panel.SpinIntCtrl(udpport, min=1, max=65535) 
        zoneCtrl = panel.TextCtrl(zone)
        payDelimCtrl = panel.TextCtrl(payDelim)     

        st4 = panel.StaticText(text.udpPort)
        st5 = panel.StaticText(text.zone)
        st6 = panel.StaticText(text.delim)
        
        eg.EqualizeWidths((st1, st2, st3, st4, st5, st6))
        box1 = panel.BoxedGroup(text.tcpBox, (st1, portCtrl))
        box2 = panel.BoxedGroup(text.securityBox, (st2, passwordCtrl))
        box3 = panel.BoxedGroup(
            text.eventGenerationBox, (st3, eventPrefixCtrl)
        )
        box4 = panel.BoxedGroup(text.relay, (st4, udpPortCtrl), (st5, zoneCtrl), (st6, payDelimCtrl))
        
        panel.sizer.AddMany([
            (box1, 0, wx.EXPAND),
            (box2, 0, wx.EXPAND|wx.TOP, 10),
            (box3, 0, wx.EXPAND|wx.TOP, 10),
            (box4, 0, wx.EXPAND|wx.TOP, 10),
        ])
        
        while panel.Affirmed():
            panel.SetResult(
                portCtrl.GetValue(),
                passwordCtrl.GetValue(),
                eventPrefixCtrl.GetValue(),
                udpPortCtrl.GetValue(),
                zoneCtrl.GetValue(),
                payDelimCtrl.GetValue(),
            )


