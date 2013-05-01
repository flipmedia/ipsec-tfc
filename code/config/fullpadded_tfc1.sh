echo 1 > /proc/sys/net/ipv4/tfc/10-0-1-2\:3/dummy_enable
echo 5 > /proc/sys/net/ipv4/tfc/10-0-1-2\:3/pkt_send_num 
echo 200 > /proc/sys/net/ipv4/tfc/10-0-1-2\:3/pkt_queue_len 
echo 200 > /proc/sys/net/ipv4/tfc/10-0-1-2\:3/pkt_queue_warn 
echo 800 > /proc/sys/net/ipv4/tfc/10-0-1-2\:3/pkt_len_avg 
echo 81 > /proc/sys/net/ipv4/tfc/10-0-1-2\:3/pkt_delay_avg 
