start_at=$(date +%s,%N)
_s1=$(echo $start_at | cut -d',' -f1)   # sec
_s2=$(echo $start_at | cut -d',' -f2)   # nano sec
while read line; do nc localhost 5555 $line; done < random.txt
end_at=$(date +%s,%N)
_e1=$(echo $end_at | cut -d',' -f1)
_e2=$(echo $end_at | cut -d',' -f2)
time_cost=$(bc <<< "scale=3; $_e1 - $_s1 + ($_e2 -$_s2)/1000000000")
echo $time_cost