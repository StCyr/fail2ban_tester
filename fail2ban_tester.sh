#!/bin/sh

show_help ()
{
  echo "USAGE: $0 -v <level> -t <time> -i <ip_list> -n <trigger> -I <interval>"
  echo "       <interval> is a time inteval (in seconds) during which a maximum of <nbr> requests is allowed (default: 60 seconds)"
  echo "       <ip_list> is a list of IP addresses for which rate analyse should be done (defaut: all IP addresses found at the date specified)"
  echo "       <level> is the verbose level (0,1,2, or 3)"
  echo "       <nbr> is the maxium number of requests during the specified <interval> (default: 100 requests)"
  echo "       <time> is a the time interval during wich the analyse shall be made (Format is \"DD/Month/YYYY\", eg: 25/Sep/2016)"
}

# Process arguments and initialise variables
day=""
interval=60
ip_list=""
tmpfile="/tmp/ratelimit"$(shuf -i 1-100000 -n 1)".tmp"
trigger=100
verbose=0
while getopts "h?v:t:n:i:I:" opt; do
    case "$opt" in
    h|\?)
  	show_help
        exit 0
        ;;
    i)  ip_list=$OPTARG
        ;;
    I)  interval=$OPTARG
        ;;
    n)  trigger=$OPTARG
        ;;
    t)  day=$OPTARG
        ;;
    v)  verbose=$OPTARG
        ;;
    esac
done

if [ -z $day ];then
  show_help
  exit 0
fi

# Format day as in Apache's logs
day=$(echo $day | sed -e 's|/|\\/|g')

# Now, that all variables have been initialized, we can source the configuration files
. ./fail2ban_tester.conf
. ./fail2ban_tester.local

[ $verbose -ge 1 ] && echo "Found $day in logfiles: $logfiles" > /dev/stderr

# When no IP address is specified, get the list of all IP addresses that sent requests on the specfied date
if [ -z $ip_list ];then
  ip_list=$(zgrep -h "\[$day" $logfiles | cut -f 1 -d " " | sort -u)
fi

# process all IP addresses
for ip in $ip_list;do

  [ $verbose -ge 1 ] && echo "Processing IP address $ip" > /dev/stderr

  # put all requests in a tmp file for faster processing
  zgrep -h "\[$day" $logfiles | grep "$ip" > $tmpfile

  # get all requests time
  request_time=$(cat $tmpfile | awk -e '{start=substr($4,2);print start}')

  # initialise ban end time at 1970/01/01
  ban_endtime=0

  # analyse rate at each request
  for start in $request_time;do

    # extract and transform info from request time
    date=$(echo $start | cut -f 1 -d ':')
    date_epoch=$(echo $date | tr '/' ' ')
    hour=$(echo $start | cut -f 2 -d ':')
    second=$(echo $start | cut -f 4 -d ':')
    minute=$(echo $start | cut -f 3 -d ':')
 
    # skip request if IP address is currently banned
    start_epoch=$(date -d "$date_epoch $hour:$minute:$second" +%s)
    if [ $start_epoch -lt $ban_endtime ];then
      [ $verbose -ge 2 ] && echo "  skipping request at $start ($start_epoch lt $ban_endtime)" > /dev/stderr
      continue
    fi
   
    [ $verbose -ge 1 ] && echo -n "  Analyzing rate at $start" > /dev/stderr

    # Create 2 regex to match all requests logged during <interval> seconds before request
    end_epoch=$((start_epoch - interval + 1))
    end_hour=$(date -d "@$end_epoch" +%H)
    end_min=$(date -d "@$end_epoch" +%M)
    end_sec=$(date -d "@$end_epoch" +%S)

    if [ $end_min -ne $minute ];then 
      seconds1=$(seq -f %02g 0 $second)
      seconds2=$(seq -f %02g $end_sec 59)
    else 
      seconds1=$(seq -f %02g $end_sec $second)
      seconds2="invalid" 
    fi

    seconds1=$(echo $seconds1 | tr ' ' '|')
    seconds1="("$seconds1")"
    regex1=$date":"$hour:"$minute":"$seconds1"
 
    if [ "X$seconds2" != "Xinvalid" ];then
      seconds2=$(echo $seconds2 | tr ' ' '|')
      seconds2="("$seconds2")"
      regex2=$date":"$end_hour":"$end_min":"$seconds2
    else
      regex2="SOMETHINGTHATSHOULDNEVEROCCURINAPACHELOGS"
    fi

    # Get the number of requests within 1 minute after start time
    nbr1=$(egrep -e "$regex1" $tmpfile | wc -l)
    nbr2=$(egrep -e "$regex2" $tmpfile | wc -l)
    nbr=$((nbr1 + nbr2))
  
    [ $verbose -ge 1 ] && echo "  (received $nbr requests within $interval second(s). Maximum allowed is $trigger)" > /dev/stderr

    [ $verbose -ge 3 ] && echo "  regex1 = $regex1" > /dev/stderr
    [ $verbose -ge 3 ] && echo "  regex2 = $regex2" > /dev/stderr
 
    # print a warning 
    if [ $nbr -ge $trigger ];then
      echo -n "*** IP address " 
      printf %-40s $ip
      echo " would be banned at $start ($nbr requests within $interval second(s).) ***"
      
      ban_endtime=$((start_epoch + 59))
    fi 

  done

done

#rm -f $tmpfile
