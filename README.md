More info see my own youdaoyunNote, which locates on ```SDN/wireshark```.

Take steps as follow:
```
sudo vim /usr/share/wireshark/init.lua

disable_lua=false  # find this line, chage to 'false', enable init lua file
dofile("~/workspace/wireshark/plugins/pof.lua")  # add at the last line
```

However, if you run ```sudo wireshark```, there is still an error. Because ```sudo``` will not init ```*.lua``` file. Please enter command:

```
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
```

Then, run ```wireshark```, you can use wireshark to parse POF protocol.
