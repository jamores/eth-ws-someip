# eth-ws-someip
Automotive Ethernet SOME/IP-SD Wireshark LUA dissectors (Autosar 4.2)

## Installation
In order to use this LUA plugins, they need to be added wireshark's 'personal plugins' folder. If you prefer not to directly copy your dissector files there, this is the option I like best (assuming you are a Linux user too) :

- clone this repository to your preferred location : \<repo_location>
- identify where wireshark expects to find user created plugins
    - Help -> About -> Folders 
    - at v.2.4.4, this folder is '/$HOME/.config/wireshark/plugins'
- create some symlinks from **$HOME/.config/wireshark/plugins** to **\<repo_location>**
  - $ ln -s \<repo_location>/someip.lua ~/.config/wireshark/plugins/
  - $ ln -s \<repo_location>/sd.lua ~/.config/wireshark/plugins/
  - $ ln -s \<repo_location>/sd_entries.lua ~/.config/wireshark/plugins/
  - $ ln -s \<repo_location>/sd_options.lua ~/.config/wireshark/plugins/

## VLAN configuration (linux)
TODO
