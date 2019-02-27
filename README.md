# EventGhostPlugins

This repos contains plugins for EventGhost (http://www.eventghost.net/)


## Network Event Relay
This plugin is built using code from the default NetworkReceiver and Broadcaster plugins. The intention of this plugin
is to make traversing firewalls easier by being able to have a machine in a subnet act as a relay for messages you 
would normal use the Broadcaster plugin for. It receives a message via TCP like the network receiver, then sends it
like the broadcaster. 

## Network Event Sender Generic
This plugin is an edit of the NetworkSender plugin. This plugin differs in that 
the destination and port are set on the action rather than the plugin. This allows 
the same plugin to reused for many destination devices if desired