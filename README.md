# eth-ws-someip
Automotive Ethernet SOME/IP and SOME/IP-SD Wireshark LUA dissectors (Autosar CP & AP, Foundation 1.5.0)

## Installation
In order to use this LUA plugins, they need to be added to Wireshark's 'personal plugins' folder.

If you prefer not to directly copy your dissector files there, this is the option I like best (assuming you are a Linux user too) :
- clone this repository to your preferred location : **\<repo_location>**
- identify where Wireshark expects to find user created plugins
    - Help -> About -> Folders 
    - on v.2.4.4 this folder is **/$HOME/.config/wireshark/plugins**
- create some symlinks from **$HOME/.config/wireshark/plugins** to **\<repo_location>**
  - $ ln -s \<repo_location>/someip.lua ~/.config/wireshark/plugins/
  - $ ln -s \<repo_location>/sd.lua ~/.config/wireshark/plugins/
  - $ ln -s \<repo_location>/sd_entries.lua ~/.config/wireshark/plugins/
  - $ ln -s \<repo_location>/sd_options.lua ~/.config/wireshark/plugins/

##  Extras
In case you need a nice python-based environment to quickly prototype a SOME/IP-SD host, design a SOME/IP test suite or just 
generate traffic, check this other project out : [eth-scapy_someip](https://github.com/jamores/eth-scapy-someip)
