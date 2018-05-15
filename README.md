More info see my own youdaoyunNote, which locates on ```SDN/wireshark```.

Take steps as follow:

- fisrt
```
sudo vim /usr/share/wireshark/init.lua
```
- second
```
disable_lua=false  # find this line, chage to 'false', enable init lua file
dofile("~/workspace/wireshark/plugins/pof.lua")  # add at the last line
```

- third

However, if you run ```sudo wireshark```, there is still an error. Because ```sudo``` will not init ```*.lua``` file. Please enter command under the ```root``` right:

```
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo getcap /usr/bin/dumpcap
```

Then, run ```wireshark```, you can use wireshark to parse POF protocol.
