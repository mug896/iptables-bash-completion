_iptables_option()
{
    if [[ $LOPT = @(-m|--match|-p|--protocol) ]]; then
        case $LVAL in
            all|0) WORDS+=" --source-port --sport --destination-port --dport
                --tcp-flags --syn --tcp-option --chunk-types --espspi --ahspi"
                if [[ $CMD = ip6tables ]]; then
	                WORDS+=" --ahlen --ahres --icmpv6-type --mh-type"
                else
	                WORDS+=" --icmp-type"
                fi ;;
            addrtype) WORDS+=" --src-type --dst-type --limit-iface-in --limit-iface-out" ;;
            ah) WORDS+=" --ahspi"
                [[ $CMD = ip6tables ]] && WORDS+=" --ahlen --ahres" ;;
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
            icmp) WORDS+=" --icmp-type" ;;
            icmp6) WORDS+=" --icmpv6-type" ;;
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
_iptables_argument()
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

        elif [[ $LVAL = dccp && $PREV = --dccp-types ]]; then
            WORDS="REQUEST RESPONSE DATA ACK DATAACK CLOSEREQ CLOSE RESET SYNC SYNCACK INVALID"

        elif [[ $LVAL = hashlimit && $LPRE = --hashlimit-mode ]]; then
            WORDS="srcip srcport dstip dstport"
        
        elif [[ $LVAL = @(icmp|all|0) && $PREV = --icmp-type ]]; then
            WORDS=$(sudo $CMD -p icmp -h | sed -En '/^Valid ICMP Types:/I,/\a/{ //d; /^\S/{ s/^(\S+).*/\1/p }}')

        elif [[ $LVAL = @(icmp6|all|0) && $PREV = --icmpv6-type ]]; then
            WORDS=$(sudo $CMD -p icmpv6 -h | sed -En '/^Valid ICMPv6 Types:/I,/\a/{ //d; /^\S/{ s/^(\S+).*/\1/p }}')
        
        elif [[ $LVAL = @(mh|all|0) && $PREV = --mh-type ]]; then
            WORDS=$(sudo $CMD -p mh -h | sed -En '/^Valid MH Types:/I,/\a/{ //d; /^\S/{ s/^(\S+).*/\1/p }}')

        elif [[ $LVAL = ipv6header && $LPRE = --header ]]; then
            WORDS="hop hop-by-hop dst route frag auth esp none prot"
        
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

        elif [[ $LVAL = @(tcp|all|0) && $LPRE = --tcp-flags ]]; then
            WORDS="SYN ACK FIN RST URG PSH ALL NONE"

        elif [[ $LVAL = @(sctp|all|0) ]]; then
            if [[ $PREV = --chunk-types ]]; then
                WORDS="all any only"
            elif [[ $PREV = DATA && ${COMP_WORDS[COMP_CWORD]} = ":" ]]; then
                WORDS="I U B E i u b e"
            elif [[ $PREV = @(ABORT|SHUTDOWN_COMPLETE) && ${COMP_WORDS[COMP_CWORD]} = ":" ]]; then
                WORDS="T t ."
            elif [[ $LPRE = --chunk-types ]]; then
                WORDS="DATA INIT INIT_ACK SACK HEARTBEAT HEARTBEAT_ACK ABORT SHUTDOWN
                    SHUTDOWN_ACK ERROR COOKIE_ECHO COOKIE_ACK ECN_ECNE  ECN_CWR
                    SHUTDOWN_COMPLETE ASCONF ASCONF_ACK FORWARD_TSN"
            fi
        
        elif [[ $LVAL = state && $LPRE = --state ]]; then
            WORDS="INVALID ESTABLISHED NEW RELATED UNTRACKED"

        elif [[ $LVAL = statistic && $PREV = --mode ]]; then
            WORDS="random nth"

        elif [[ $LVAL = string && $PREV = --algo ]]; then
            WORDS="bm kmp"
        
        elif [[ $LVAL = time && $LPRE = --weekdays ]]; then
            WORDS="Mon Tue Wed Thu Fri Sat Sun"
        fi
        
    elif [[ $LOPT = @(-j|--jump) ]]; then

        if [[ $LVAL = AUDIT && $PREV = --type ]]; then
            WORDS="accept drop reject"
        
        elif [[ $LVAL = CLUSTERIP && $PREV = --hashmode ]]; then
            WORDS="sourceip  sourceip-sourceport sourceip-sourceport-destport"

        elif [[ $LVAL = CT && $LPRE = --ctevents ]]; then
            WORDS="new related destroy reply assured protoinfo helper mark natseqinfo secmark"

        elif [[ $LVAL = HMARK && $LPRE = --hmark-tuple ]]; then
            WORDS="src dst sport dport spi ct"
        
        elif [[ $LVAL = LOG && $PREV = --log-level ]]; then
            WORDS="emerg alert crit error warning notice info debug"

        elif [[ $LVAL = REJECT && $PREV = --reject-with ]]; then
            if [[ $CMD = ip6tables ]]; then
            WORDS="icmp6-no-route no-route icmp6-adm-prohibited tcp-reset
                adm-prohibited icmp6-addr-unreachable addr-unreach icmp6-port-unreachable"
            else
            WORDS="icmp-net-unreachable icmp-host-unreachable icmp-port-unreachable
                icmp-proto-unreachable icmp-net-prohibited icmp-host-prohibited 
                icmp-admin-prohibited tcp-reset"
            fi

        elif [[ $LVAL = TCPOPTSTRIP && $LPRE = --strip-options ]]; then
            WORDS="wscale mss sack-permitted sack timestamp md5"
        fi
    fi
}
_iptables_match()
{
    # man iptables-extensions | sed -En '/^MATCH EXTENSIONS$/,/^TARGET EXTENSIONS$/{ //d; /^[ ]{3}[[:alnum:]]/p }'
    WORDS="addrtype ah bpf cgroup cluster comment connbytes connlabel connlimit
    connmark conntrack cpu dccp devgroup dscp ecn esp hashlimit helper iprange
    ipvs length limit mark multiport nfacct osf physdev pkttype policy 
    quota rateest recent sctp set socket state statistic string tcp 
    tcpmss time tos u32 udp"
    [[ $CHAIN = @(PREROUTING|INPUT|FORWARD) ]] && WORDS+=" mac"
    [[ $CHAIN = @(POSTROUTING|OUTPUT) ]] && WORDS+=" owner"
    [[ $TABLE = @(raw|mangle) && $CHAIN = PREROUTING ]] && WORDS+=" rpfilter"
    [[ $CMD = iptables ]] && WORDS+=" icmp realm ttl"
    if [[ $CMD = ip6tables ]]; then
        WORDS+=" dst frag hbh hl icmp6 ipv6header mh rt"
        [[ $CHAIN = @(PREROUTING|INPUT|FORWARD) ]] && WORDS+=" eui64"
    fi
}
_iptables_target()
{
    # man iptables-extensions | sed -En '/^TARGET EXTENSIONS/,/\a/{ //d; /^[ ]{3}[[:alnum:]]/p }'
    WORDS="ACCEPT DROP RETURN"
    WORDS+=" AUDIT CLASSIFY CONNMARK HMARK IDLETIMER LED LOG MARK NFLOG 
            NFQUEUE RATEEST SET SYNPROXY TCPMSS TCPOPTSTRIP TEE"
    [[ $CMD = iptables ]] && WORDS+=" CLUSTERIP ULOG"
    [[ $CHAIN = @(INPUT|OUTPUT|FORWARD|USER_DEFINED) ]] && WORDS+=" REJECT"
    case $TABLE in
        raw) WORDS+=" CT NOTRACK TRACE" ;;
        nat) WORDS+=" NETMAP"
            [[ $CHAIN = @(PREROUTING|OUTPUT|USER_DEFINED) ]] && WORDS+=" DNAT REDIRECT"
            [[ $CHAIN = @(POSTROUTING|INPUT|USER_DEFINED) ]] && WORDS+=" SNAT"
            [[ $CHAIN = POSTROUTING ]] && WORDS+=" MASQUERADE" ;;
        mangle) WORDS+=" CHECKSUM CONNSECMARK SECMARK DSCP TOS" 
            [[ $CMD = iptables ]] && WORDS+=" ECN TTL"
            [[ $CMD = ip6tables ]] && WORDS+=" DNPT SNPT HL"
            [[ $CHAIN = @(PREROUTING|USER_DEFINED) ]] && WORDS+=" TPROXY" ;;
        security) WORDS+=" CONNSECMARK SECMARK" ;;
    esac
    WORDS+=" "$( sudo $CMD -t $TABLE -S | gawk '{ if ($1 == "-N") print $2 }' )
}
_iptables_check() 
{
    local arg1 arg2
    for arg1 in "$@"; do
        for arg2 in "${COMP_WORDS[@]}"; do
            [[ ${arg2:0:1} != "-" ]] && continue
            if [[ ${arg2:0:2} = "--" ]]; then 
                [[ $arg2 = $arg1 ]] && return
            else
                [[ ${arg1:0:2} = "--" ]] && continue
                [[ $arg2 =~ ${arg1:1} ]] && return
            fi
        done
    done        
    echo "$@"
}
_iptables_number()
{
    local table=$1 chain=$2
    WORDS=$( sudo $CMD -t $table -S $chain 2>/dev/null | gawk '{
        if ($1 == "-A") { 
            $1 = $2 = ""; sub(/^ +/,"")
            a[i++] = $0 
        }
    } END { 
        if (isarray(a)) {
            len = length(i)
            for (j in a) 
                printf "%0*d) %s\n", len, j+1, a[j]
    }}')
    IFS=$'\n' COMPREPLY=( $WORDS )
    [[ ${#COMPREPLY[@]} = 1 ]] && COMPREPLY+=( "2) __END__" )
}
_iptables() 
{
    if ! [[ $PROMPT_COMMAND =~ "COMP_WORDBREAKS=" ]]; then
        PROMPT_COMMAND="COMP_WORDBREAKS=${COMP_WORDBREAKS@Q}; "$PROMPT_COMMAND
    fi
    ! [[ $COMP_WORDBREAKS = *,* ]] && COMP_WORDBREAKS+=","

    local CMD=$1 CUR=$2 PREV=$3 PREV2=${COMP_WORDS[COMP_CWORD-2]}
    local IFS=$' \t\n' WORDS 
    [[ $COMP_LINE =~ .*" "(-t|--table)" "+([[:alnum:]]+) ]]
    local TABLE=${BASH_REMATCH[2]:-filter}
    [[ $COMP_LINE =~ .*" "(-A|--append|-I|--insert|-R|--replace)" "+([[:alnum:]]+) ]]
    local CHAIN=${BASH_REMATCH[2]}
    if [[ -n $CHAIN && $CHAIN != @(PREROUTING|INPUT|OUTPUT|FORWARD|POSTROUTING) ]]; then
        CHAIN=USER_DEFINED
    fi
    local COMP_LINE2=${COMP_LINE:0:$COMP_POINT}

    if [[ ${CUR:0:1} = "-" ]]; then
        WORDS=$( _iptables_check -t --table )
        WORDS+=" "$( _iptables_check -A --append -C --check -D --delete \
        -I --insert -R --replace -L --list -S --list-rules -F --flush -Z --zero \
        -N --new-chain -X --delete-chain -P --policy -E --rename-chain )
        if [[ ${WORDS%%*( )} = "" || ${WORDS%%*( )} = "-t --table" ]]; then
            WORDS+=" -p --protocol -s --source -d --destination -m --match -j --jump
            -g --goto -i --in-interface -o --out-interface -c --set-counters"
            [[ $CMD = iptables ]] && WORDS+=" -f --fragment"
        fi
        WORDS+=" -h -v --verbose -w --wait -W --wait-interval -n --numeric -x --exact 
        --line-numbers --modprobe="
    fi

    if [[ $PREV = @(-!(-*)t|--table) && ${CUR:0:1} != "-" ]]; then
        WORDS="filter nat mangle raw security"

    elif [[ $PREV = @(-!(-*)[ACDIRLSFZNXPEg]|--append|--check|--delete|--insert|\
--replace|--list|--list-rules|--flush|--zero|--new-chain|--delete-chain|--policy|\
--rename-chain|--goto) && ${CUR:0:1} != "-" ]]; then

        if [[ $PREV != @(-E|--rename-chain|-N|--new-chain) ]]; then
            case $TABLE in
                raw) WORDS="PREROUTING OUTPUT" ;;
                nat) WORDS="PREROUTING INPUT OUTPUT POSTROUTING" ;;
                mangle) WORDS="PREROUTING OUTPUT INPUT FORWARD POSTROUTING" ;;
                security) WORDS="INPUT OUTPUT FORWARD" ;;
                *) WORDS="INPUT FORWARD OUTPUT" ;;             # filter table
            esac
        fi
        if [[ $PREV != @(-P|--policy) ]]; then
            WORDS+=" "$( sudo $CMD -t $TABLE -S | gawk '{ if ($1 == "-N") print $2 }' )
        fi

    elif [[ $PREV = @(-!(-*)[io]|--in-interface|--out-interface|--rateest1|--rateest2|\
--rateest-name) && ${CUR:0:1} != "-" ]]; then
        WORDS=$( \ls /sys/class/net/ )

    elif [[ $PREV = @(-!(-*)p|--protocol) && ${CUR:0:1} != "-" ]]; then
        WORDS="tcp udp udplite esp ah sctp all"
        [[ $CMD = iptables ]] && WORDS+=" icmp"
        [[ $CMD = ip6tables ]] && WORDS+=" icmp6 mh"
    
    elif [[ $PREV2 = @(-!(-*)P|--policy) && ${CUR:0:1} != "-" ]]; then
        WORDS="ACCEPT DROP"

    elif [[ $PREV = @(-!(-*)j|--jump) && ${CUR:0:1} != "-" ]]; then
        _iptables_target

    elif [[ $PREV = @(-!(-*)m|--match) && ${CUR:0:1} != "-" ]]; then
        _iptables_match

    elif [[ $PREV2 = @(-!(-*)[DCR]|--delete|--check|--replace) && ${CUR:0:1} != "-" ]]; then
        _iptables_number $TABLE $PREV
        return

    else
        local LOPT LVAL LPRE
        if [[ ${CUR:0:1} = "-" ]]; then
            [[ $COMP_LINE2 =~ .*" "(-p|--protocol)" "+([[:alnum:]]+)" " ]]
            LOPT=${BASH_REMATCH[1]:--p}
            LVAL=${BASH_REMATCH[2]:-all}
            _iptables_option
        fi
        [[ $COMP_LINE2 =~ .*" "(-p|--protocol|-m|--match|-j|--jump)" "+([[:alnum:]]+)" " ]]
        LOPT=${BASH_REMATCH[1]}
        LVAL=${BASH_REMATCH[2]}
        [[ $COMP_LINE2 =~ .*" "(--[[:alnum:]-]+)" " ]]
        LPRE=${BASH_REMATCH[1]}
        if [[ ${CUR:0:1} = "-" && $LOPT != @(-p|--protocol) ]]; then
            _iptables_option
        else
            _iptables_argument
        fi
    fi

    COMPREPLY=( $(compgen -W "$WORDS" -- $CUR) )
    [[ ${COMPREPLY: -1} =~ "=" ]] && compopt -o nospace
}

complete -F _iptables iptables ip6tables

