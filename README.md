## Iptables Bash Completion

Copy contents of `httpie-bash-completion.sh` file to `~/.bash_completion`.  
open new terminal and try auto completion.


```sh
bash$ lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 22.04 LTS
Release:        22.04
Codename:       jammy

bash$ iptables -v
iptables v1.8.7 (nf_tables): no command specified
Try `iptables -h' or 'iptables --help' for more information.

bash$ iptables -[tab]
--ahspi             --line-numbers      --tcp-flags         -N
--append            --list              --tcp-option        -P
--check             --list-rules        --verbose           -R
--chunk-types       --modprobe=         --wait              -S
--delete            --new-chain         --wait-interval     -W
--delete-chain      --numeric           --zero              -X
--destination-port  --policy            -A                  -Z
--dport             --rename-chain      -C                  -h
--espspi            --replace           -D                  -n
--exact             --source-port       -E                  -t
--flush             --sport             -F                  -v
--icmp-type         --syn               -I                  -w
--insert            --table             -L                  -x
```

