# eth-ws-someip
Automotive Ethernet SOME/IP-SD Wireshark LUA dissectors (Autosar 4.2)

## Installation
In order to use this LUA plugins, best option would be refer to official wireshark LUA documenation (the wiki could be a goot starting point : https://wiki.wireshark.org/Lua). However, if you too are a Linux user, this is the option I like best:
- clone this repository to your preferred location : \<repo_location>
- one of the default directories where Wireshark will look for LUA plugins is **$HOME/.wireshark/plugins**
- simply create some symlinks from **$HOME/.wireshark/plugins** to **\<repo_location>**
  - $ ln -s \<repo_location>/someip.lua ~/.wireshark/plugins/
  - $ ln -s \<repo_location>/sd.lua ~/.wireshark/plugins/
  - $ ln -s \<repo_location>/sd_entries.lua ~/.wireshark/plugins/
  - $ ln -s \<repo_location>/sd_options.lua ~/.wireshark/plugins/
