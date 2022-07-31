_iptables_check() 
{
    local arg1 arg2
    for arg1 in "$@"; do
        for arg2 in "${COMP_WORDS[@]}"; do
            [[ $arg1 = $arg2 ]] && return
        done
    done        
    echo "$@"
}
_iptables_options()
{
    if [[ $LOPT = @(-m|--match|-p|--protocol) ]]; then
        case $LVAL in
            addrtype) WORDS+=" --src-type --dst-type --limit-iface-in --limit-iface-out" ;;
            ah) if [[ $CMD = ip6tables ]]; then
                    WORDS+=" --ahspi --ahlen --ahres"
                else
                    WORDS+=" --ahspi"
                fi ;;
            bpf) WORDS+=" --object-pinned --bytecode" ;;
            cgroup) WORDS+=" --path --cgroup" ;;
            cluster) WORDS+=" --cluster-total-nodes --cluster-local-node 
                    --cluster-local-nodemask --cluster-hash-seed" ;;
            comment) WORDS+=" --comment" ;;
            connbytes) WORDS+=" --connbytes --connbytes-dir --connbytes-mode" ;;
            connlabel) WORDS+=" --label --set" ;;
            connlimit) WORDS+=" --connlimit-upto --connlimit-above --connlimit-mask 
                    --connlimit-saddr --connlimit-daddr" ;;
            connmark) WORDS+=" --mark" ;;
            conntrack) WORDS+=" --ctstate --ctproto --ctorigsrc --ctorigdst --ctreplsrc 
                    --ctrepldst --ctorigsrcport --ctorigdstport --ctreplsrcport 
                    --ctrepldstport --ctstatus --ctexpire --ctdir" ;;
            cpu) WORDS+=" --cpu" ;;
            dccp) WORDS+=" --source-port --sport --destination-port --dport --dccp-types --dccp-option" ;;
            devgroup) WORDS+=" --src-group --dst-group" ;;
            dscp) WORDS+=" --dscp --dscp-class" ;;
            dst) WORDS+=" --dst-len --dst-opts" ;;
            ecn) WORDS+=" --ecn-tcp-cwr --ecn-tcp-ece --ecn-ip-ect" ;;
            esp) WORDS+=" --espspi" ;;
            frag) WORDS+=" --fragid --fraglen --fragres --fragfirst --fragmore --fraglast" ;;
            hashlimit) WORDS+=" --hashlimit-upto --hashlimit-above --hashlimit-burst 
                    --hashlimit-mode --hashlimit-srcmask --hashlimit-dstmask 
                    --hashlimit-name --hashlimit-htable-size --hashlimit-htable-max 
                    --hashlimit-htable-expire --hashlimit-htable-gcinterval 
                    --hashlimit-rate-match --hashlimit-rate-interval" ;;
            hbh) WORDS+=" --hbh-len --hbh-opts" ;;
            helper) WORDS+=" --helper" ;;
            hl) WORDS+=" --hl-eq --hl-lt --hl-gt" ;;
            icmp|icmp6) WORDS+=" --icmp-type --icmpv6-type" ;;
            iprange) WORDS+=" --src-range --dst-range" ;;
            ipv6header) WORDS+=" --soft --header" ;;
            ipvs) WORDS+=" --ipvs --vproto --vaddr --vport --vdir --vmethod --vportctl" ;; 
            length) WORDS+=" --length" ;;
            limit) WORDS+=" --limit --limit-burst" ;;
            mac) WORDS+=" --mac-source" ;;
            mark) WORDS+=" --mark" ;;
            mh) WORDS+=" --mh-type" ;;
            multiport) WORDS+=" --source-ports --sports --destination-ports --dports --ports" ;; 
            nfacct) WORDS+=" --nfacct_name" ;;
            osf) WORDS+=" --genre --ttl --log" ;;
            owner) WORDS+=" --uid-owner --gid-owner --suppl-groups --socket-exists" ;;
            physdev) WORDS+=" --physdev-in --physdev-out --physdev-is-in --physdev-is-out --physdev-is-bridged" ;;
            pkttype) WORDS+=" --pkt-type" ;;
            policy) WORDS+=" --dir --pol --strict --reqid --spi --proto --mode 
                        --tunnel-src --tunnel-dst --next" ;;
            quota) WORDS+=" --quota" ;;
            rateest) WORDS+=" --rateest-delta --rateest-lt --rateest-gt --rateest-eq
                            --rateest --rateest1 --rateest2 --rateest-bps --rateest-pps
                            --rateest-bps1 --rateest-bps2 --rateest-pps1 --rateest-pps2" ;;
            realm) WORDS+=" --realm" ;;
            recent) WORDS+=" --name --set --rsource --rdest --mask --rcheck --update 
                        --remove --seconds --reap --hitcount --rttl" ;;
            rpfilter) WORDS+=" --loose --validmark --accept-local --invert" ;;
            rt) WORDS+=" --rt-type --rt-segsleft --rt-len --rt-0-res --rt-0-addrs --rt-0-not-strict" ;;
            sctp) WORDS+=" --source-port --sport --destination-port --dport --chunk-types" ;;
            set) WORDS+=" --match-set --return-nomatch --update-counters 
                --update-subcounters --packets-eq --packets-lt --packets-gt 
                --bytes-eq --bytes-lt --bytes-gt" ;;
            socket) WORDS+=" --transparent --nowildcard --restore-skmark" ;;
            state) WORDS+=" --state" ;;
            statistic) WORDS+=" --mode --probability --every --packet" ;;
            string) WORDS+=" --algo --from --to --string --hex-string --icase" ;;
            tcp) WORDS+=" --source-port --sport --destination-port --dport --tcp-flags --syn --tcp-option" ;;
            tcpmss) WORDS+=" --mss" ;;
            time) WORDS+=" --datestart --datestop --timestart --timestop --monthdays
                --weekdays --contiguous --kerneltz" ;;
            tos) WORDS+=" --tos" ;;
            ttl) WORDS+=" --ttl-eq --ttl-gt --ttl-lt" ;;
            u32) WORDS+=" --u32" ;;
            udp) WORDS+=" --source-port --sport --destination-port --dport" ;;
        esac
    
    elif [[ $LOPT = @(-j|--jump) ]]; then
        case $LVAL in
            AUDIT) WORDS+=" --type" ;;
            CHECKSUM) WORDS+=" --checksum-fill" ;;
            CLASSIFY) WORDS+=" --set-class" ;;
            CLUSTERIP) WORDS+=" --new --hashmode --clustermac --total-nodes --local-node --hash-init" ;;
            CONNMARK) WORDS+=" --set-xmark --save-mark --restore-mark --nfmask --ctmask
                    --and-mark --or-mark --xor-mark --set-mark --save-mark --restore-mark" ;;
            CONNSECMARK) WORDS+=" --save --restore" ;;
            CT) WORDS+=" --notrack --helper --ctevents --expevents --zone-orig 
                    --zone-reply --zone --timeout" ;;
            DNAT) WORDS+=" --to-destination --random --persistent" ;;
            DNPT) WORDS+=" --src-pfx --dst-pfx" ;;
            DSCP) WORDS+=" --set-dscp --set-dscp-class" ;;
            ECN) WORDS+=" --ecn-tcp-remove" ;;
            HL) WORDS+=" --hl-set --hl-dec --hl-inc" ;;
            HMARK) WORDS+=" --hmark-tuple --hmark-mod --hmark-offset --hmark-src-prefix 
                    --hmark-dst-prefix --hmark-sport-mask --hmark-dport-mask 
                    --hmark-spi-mask --hmark-proto-mask --hmark-rnd" ;;
            IDLETIMER) WORDS+=" --timeout --label" ;;
            LED) WORDS+=" --led-trigger-id --led-delay --led-always-blink" ;;
            LOG) WORDS+=" --log-level --log-prefix --log-tcp-sequence --log-tcp-options --log-ip-options --log-uid" ;;
            MARK) WORDS+=" --set-xmark --set-mark --and-mark --or-mark --xor-mark" ;;
            MASQUERADE) WORDS+=" --to-ports --random --random-fully" ;;
            NETMAP) WORDS+=" --to" ;;
            NFLOG) WORDS+=" --nflog-group --nflog-prefix --nflog-range --nflog-size --nflog-threshold" ;;
            NFQUEUE) WORDS+=" --queue-num --queue-balance --queue-bypass --queue-cpu-fanout" ;;
            RATEEST) WORDS+=" --rateest-name --rateest-interval --rateest-ewmalog" ;;
            REDIRECT) WORDS+=" --to-ports --random" ;;
            REJECT) WORDS+=" --reject-with" ;; 
            SECMARK) WORDS+=" --selctx" ;;
            SET) WORDS+=" --add-set --del-set --map-set --timeout --exist --map-set
                        --map-mark --map-prio --map-queue" ;;
            SNAT) WORDS+=" --to-source --random --random-fully --persistent" ;;
            SNPT) WORDS+=" --src-pfx --dst-pfx" ;;
            SYNPROXY) WORDS+=" --mss --wscale --sack-perm --timestamps" ;;
            TCPMSS) WORDS+=" --set-mss --clamp-mss-to-pmtu" ;;
            TCPOPTSTRIP) WORDS+=" --strip-options" ;;
            TEE) WORDS+=" --gateway" ;;
            TOS) WORDS+=" --set-tos --and-tos --or-tos --xor-tos" ;;
            TPROXY) WORDS+=" --on-port --on-ip --tproxy-mark" ;;
            TTL) WORDS+=" --ttl-set --ttl-dec --ttl-inc" ;;
            ULOG) WORDS+=" --ulog-nlgroup --ulog-prefix --ulog-cprange --ulog-qthreshold" ;;
        esac
    fi
}
_iptables_arguments()
{
    if [[ $LOPT = @(-m|--match|-p|--protocol) ]]; then

        if [[ $LVAL = addrtype && $PREV = @(--src-type|--dst-type) ]]; then
            WORDS="UNSPEC UNICAST LOCAL BROADCAST ANYCAST MULTICAST BLACKHOLE
            UNREACHABLE PROHIBIT THROW NAT XRESOLVE"

        elif [[ $LVAL = connbytes ]]; then
            case $PREV in
                --connbytes-dir) WORDS="original reply both" ;;
                --connbytes-mode) WORDS="packets bytes avgpkt" ;;
            esac

        elif [[ $LVAL = conntrack ]]; then
            case $LPRE in
                --ctstate) WORDS="INVALID NEW ESTABLISHED RELATED UNTRACKED SNAT DNAT" ;;
                --ctstatus) WORDS="NONE EXPECTED SEEN_REPLY ASSURED CONFIRMED" ;;
            esac
            [[ $CUR = "," ]] && CUR=""

        elif [[ $LVAL = dccp && $PREV = --dccp-types ]]; then
            WORDS="REQUEST RESPONSE DATA ACK DATAACK CLOSEREQ CLOSE RESET SYNC SYNCACK INVALID"
        elif [[ $LVAL = hashlimit && $LPRE = --hashlimit-mode ]]; then
            WORDS="srcip srcport dstip dstport"
            [[ $CUR = "," ]] && CUR=""
        
        elif [[ $LVAL = ipv6header && $LPRE = --header ]]; then
            WORDS="hop hop-by-hop dst route frag auth esp none prot"
            [[ $CUR = "," ]] && CUR=""
        
        elif [[ $LVAL = ipvs ]]; then
            case $PREV in
                --vdir) WORDS="ORIGINAL REPLY" ;;
                --vmethod) WORDS="GATE IPIP MASQ" ;;
            esac

        elif [[ $LVAL = pkttype && $PREV = --pkt-type ]]; then
            WORDS="unicast broadcast multicast"

        elif [[ $LVAL = policy ]]; then
            case $PREV in
                --dir) WORDS="in out" ;;
                --pol) WORDS="none ipsec" ;;
                --proto) WORDS="ah esp ipcomp" ;;
                --mode) WORDS="tunnel transport" ;;
            esac

        elif [[ $LVAL = sctp ]]; then
            if [[ $PREV = --chunk-types ]]; then
                WORDS="all any only"
            elif [[ $PREV = DATA && $CUR = ":" ]]; then
                WORDS="I U B E i u b e"
            elif [[ $PREV = @(ABORT|SHUTDOWN_COMPLETE) && $CUR = ":" ]]; then
                WORDS="T t ."
            elif [[ $LPRE = --chunk-types ]]; then
                WORDS="DATA INIT INIT_ACK SACK HEARTBEAT HEARTBEAT_ACK ABORT SHUTDOWN
                    SHUTDOWN_ACK ERROR COOKIE_ECHO COOKIE_ACK ECN_ECNE  ECN_CWR
                    SHUTDOWN_COMPLETE ASCONF ASCONF_ACK FORWARD_TSN"
            fi
            [[ $CUR = @(,|:) ]] && CUR=""
        
        elif [[ $LVAL = state && $LPRE = --state ]]; then
            WORDS="INVALID ESTABLISHED NEW RELATED UNTRACKED"
            [[ $CUR = "," ]] && CUR=""

        elif [[ $LVAL = string && $PREV = --algo ]]; then
            WORDS="bm kmp"
        
        elif [[ $LVAL = tcp && $LPRE = --tcp-flags ]]; then
            WORDS="SYN ACK FIN RST URG PSH ALL NONE"
            [[ $CUR = "," ]] && CUR=""

        elif [[ $LVAL = time && $LPRE = --weekdays ]]; then
            WORDS="Mon Tue Wed Thu Fri Sat Sun"
            [[ $CUR = "," ]] && CUR=""

        fi
        
    elif [[ $LOPT = @(-j|--jump) ]]; then

        if [[ $LVAL = AUDIT && $PREV = --type ]]; then
            WORDS="accept drop reject"
        
        elif [[ $LVAL = CLUSTERIP && $PREV = --hashmode ]]; then
            WORDS="sourceip  sourceip-sourceport sourceip-sourceport-destport"

        elif [[ $LVAL = CT && $LPRE = --ctevents ]]; then
            WORDS="new related destroy reply assured protoinfo helper mark natseqinfo secmark"
            [[ $CUR = "," ]] && CUR=""

        elif [[ $LVAL = HMARK && $LPRE = --hmark-tuple ]]; then
            WORDS="src dst sport dport spi ct"
            [[ $CUR = "," ]] && CUR=""
        
        elif [[ $LVAL = LOG && $PREV = --log-level ]]; then
            WORDS="emerg alert crit error warning notice info debug"

        elif [[ $LVAL = REJECT && $PREV = --reject-with ]]; then
            if [[ $CMD = ip6tables ]]; then
            WORDS="icmp6-no-route no-route icmp6-adm-prohibited 
                adm-prohibited icmp6-addr-unreachable addr-unreach icmp6-port-unreachable"
            else
            WORDS="icmp-net-unreachable icmp-host-unreachable icmp-port-unreachable
                icmp-proto-unreachable icmp-net-prohibited icmp-host-prohibited 
                icmp-admin-prohibited"
            fi
        fi
    fi
}
_iptables() 
{
    if ! [[ $PROMPT_COMMAND =~ "COMP_WORDBREAKS=" ]]; then
        PROMPT_COMMAND="COMP_WORDBREAKS=$' \t\n\"'\''@><=;|&(:'; "$PROMPT_COMMAND
    fi
    if ! [[ $COMP_WORDBREAKS =~ "," ]]; then COMP_WORDBREAKS+=","; fi

    local CMD=${COMP_WORDS[0]}
    local CUR=${COMP_WORDS[COMP_CWORD]}
    local PREV=${COMP_WORDS[COMP_CWORD-1]}
    local PREV2=${COMP_WORDS[COMP_CWORD-2]}
    local IFS=$' \t\n' WORDS 

    if [ "${CUR:0:1}" = "-" ]; then
        WORDS=$( _iptables_check -t --table )
        WORDS+=" "$( _iptables_check -A --append -C --check -D --delete \
        -I --insert -R --replace -L --list -S --list-rules -F --flush -Z --zero \
        -N --new-chain -X --delete-chain -P --policy -E --rename-chain )
        if [[ ${WORDS%%+( )} = "" || ${WORDS%%+( )} = "-t --table" ]]; then
        WORDS+=" -4 --ipv4 -6 --ipv6 -p --protocol -s --source -d --destination 
        -m --match -j --jump -g --goto -i --in-interface -o --out-interface
        -f --fragment -c --set-counters"
        fi
        WORDS+=" -h -v --verbose -w --wait -W --wait-interval -n --numeric -x --exact 
        --line-numbers --modprobe="
    fi

    if [[ $PREV = @(-t|--table) && ${CUR:0:1} != "-" ]]; then
        WORDS="filter nat mangle raw security"

    elif [[ ($PREV = @(-A|--append|-C|--check|-D|--delete|-I|--insert|-R|--replace|\
-L|--list|-S|--list-rules|-F|--flush|-Z|--zero|-N|--new-chain|-X|--delete-chain|\
-P|--policy|-E|--rename-chain|-g|--goto) 
        || $PREV2 = @(-E|--rename-chain)) && ${CUR:0:1} != "-" ]]; then
        WORDS="INPUT OUTPUT FORWARD PREROUTING POSTROUTING"
        WORDS+=" "$( sudo iptables -S | awk '{print $2}' )

    elif [[ $PREV = @(-i|--in-interface|-o|--out-interface|--rateest1|--rateest2|--rateest-name) && ${CUR:0:1} != "-" ]]; then
        WORDS=$( \ls /sys/class/net/ )

    elif [[ $PREV = @(-p|--protocol) && ${CUR:0:1} != "-" ]]; then
        WORDS="tcp udp udplite icmp icmpv6 esp ah sctp mh all"
    
    elif [[ $PREV2 = @(-P|--policy) && ${CUR:0:1} != "-" ]]; then
        WORDS="ACCEPT DROP"

    elif [[ $PREV = @(-j|--jump) && ${CUR:0:1} != "-" ]]; then
        WORDS="ACCEPT DROP RETURN"
        WORDS+=" "$( sudo iptables -S | awk '{print $2}' )
        WORDS+=" AUDIT CHECKSUM CLASSIFY CONNMARK CONNSECMARK CT DNAT DSCP HMARK 
        IDLETIMER LED LOG MARK MASQUERADE NETMAP NFLOG NFQUEUE NOTRACK RATEEST 
        REDIRECT REJECT SECMARK SET SNAT SYNPROXY TCPMSS TCPOPTSTRIP TEE TOS TPROXY TRACE"
        [[ $CMD = iptables ]] && WORDS+=" CLUSTERIP ECN TTL ULOG"
        [[ $CMD = ip6tables ]] && WORDS+=" DNPT HL SNPT"

    elif [[ $PREV = @(-m|--match) && ${CUR:0:1} != "-" ]]; then
        WORDS="addrtype ah bpf cgroup cluster comment connbytes connlabel connlimit
        connmark conntrack cpu dccp devgroup dscp ecn esp hashlimit helper iprange
        ipvs length limit mac mark multiport nfacct osf owner physdev pkttype policy 
        quota rateest recent rpfilter sctp set socket state statistic string tcp 
        tcpmss time tos u32 udp"
        [[ $CMD = iptables ]] && WORDS+=" icmp realm ttl"
        [[ $CMD = ip6tables ]] && WORDS+=" dst eui64 frag hbh hl icmp6 ipv6header mh rt"

    else
        [[ ${COMP_LINE% *} =~ .*" "(-p|--protocol|-m|--match|-j|--jump)" "+([[:alnum:]]+) ]]
        local LOPT=${BASH_REMATCH[1]}
        local LVAL=${BASH_REMATCH[2]}
        [[ ${COMP_LINE% *} =~ .*" "(--[[:alnum:]-]+) ]]
        local LPRE=${BASH_REMATCH[1]}

        if [ "${CUR:0:1}" = "-" ]; then
            _iptables_options
        else
            _iptables_arguments
        fi
    fi

    COMPREPLY=( $(compgen -W "$WORDS" -- $CUR) )
    [[ "${COMPREPLY: -1}" =~ =|: ]] && compopt -o nospace
}

complete -F _iptables iptables ip6tables
