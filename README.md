## Iptables Bash Completion

Copy contents of `httpie-bash-completion.sh` file to `~/.bash_completion`.  
open new terminal and try auto completion.


```sh
bash$ iptables -v
iptables v1.8.7 (nf_tables): no command specified
Try `iptables -h' or 'iptables --help' for more information.

bash$ iptables -[tab]
--append         --list-rules     --wait           -L               -n
--check          --modprobe=      --wait-interval  -N               -t
--delete         --new-chain      --zero           -P               -v
--delete-chain   --numeric        -A               -R               -w
--exact          --policy         -C               -S               -x
--flush          --rename-chain   -D               -W               
--insert         --replace        -E               -X               
--line-numbers   --table          -F               -Z               
--list           --verbose        -I               -h 
```

