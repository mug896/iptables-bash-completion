## Iptables Bash Completion

Copy contents of `httpie-bash-completion.sh` file to `~/.bash_completion`.  
open new terminal and try auto completion.


```sh
bash$ iptables -v
iptables v1.8.7 (nf_tables): no command specified
Try `iptables -h' or 'iptables --help' for more information.

bash$ iptables -[tab]
--ahspi             --line-numbers      --tcp-option        -P
--append            --list              --verbose           -R
--check             --list-rules        --wait              -S
--chunk-types       --modprobe=         --wait-interval     -W
--delete            --new-chain         --zero              -X
--delete-chain      --numeric           -A                  -Z
--destination-port  --policy            -C                  -h
--dport             --rename-chain      -D                  -n
--espspi            --replace           -E                  -v
--exact             --source-port       -F                  -w
--flush             --sport             -I                  -x
--icmp-type         --syn               -L                  
--insert            --tcp-flags         -N
```

