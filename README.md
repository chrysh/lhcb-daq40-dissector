# lhcb-daq40-dissector

The plugin was written for wireshark 1.12.1.

For activating the plugin, copy the lhcb-daq40-dissector folder into the wireshark source plugin folder wireshark/plugins
Then compile it and copy the shared object file into one of the folders wireshark looks in for finding plugins on startup.

```
$ make
$ cp .libs/lhcb-daq40-dissector.so ~/.wireshark/plugins/
```
