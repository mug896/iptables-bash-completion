## Iptables Bash Completion

Copy contents of `httpie-bash-completion.sh` file to `~/.bash_completion`.  
open new terminal and try auto completion !


```sh
bash$ hostnamectl
Operating System: Ubuntu 22.04.1 LTS
          Kernel: Linux 5.15.0-43-generic
    Architecture: x86-64

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

> please leave an issue above if you have any problems using this script.
