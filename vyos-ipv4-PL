### TODO:
### Maybe use https://github.com/bgp/bgpq4
### Because it supports prefix aggregation

#!/usr/bin/env bash
DEBUG="0"
OUTPUT="1"
MY_PDB_API_FILE=~/.pdb_api.txt

if [ -z $1 ]; then
 echo "Usage: Please specify two arguments for mode and query."
 echo " "
 echo "Mode: {raw|pdb}"
 echo "--------------"
 echo "RAW mode: specify second argument in the format of IRR::AS_SET, example:"
 echo "vyos-pl.sh raw RADB::AS16970:AS-MIDNET-ALL"
 echo " "
 echo "PDB mode: specify second argument as target ASN, numeric only, example:"
 echo "16970"
 echo " " 
 exit 1
fi

MODE="$1"

if [ "$MODE" == "raw" ]; then
 REG=${2%::*}
 AS_SET=${2#*::}
 AS_SET_DASH=$(echo $AS_SET | tr ':' '-')
 PL4NAME="PL4-IRR-$REG--$AS_SET_DASH"
 if [ "$DEBUG" == "1" ]; then
  echo "raw mode"
  echo "arg1 $1"
  echo "arg2 $2"
  echo "reg: $REG"
  echo "as set: $AS_SET"
  echo "as set transform: $AS_SET_DASH"
  echo "pl4name: $PL4NAME"
 fi
fi

if [ "$MODE" == "pdb" ]; then
 ASN=$2
 PDB_API=`cat $MY_PDB_API_FILE`
 AS_SET=$(curl -s -H "Authorization: Api-Key $PDB_API" -H "Content-Type: application/json" -X GET https://www.peeringdb.com/api/as_set/{$ASN})
 if [ -z "$AS_SET" ]; then
  echo "ERROR: null value retrieved for as-set from PeeringDB"
  exit 1
 fi
 REG=$(echo $AS_SET | jq -r '.data[0][]' | cut -d':' -f1)
 if [ -z "$REG" ]; then
  echo "ERROR: null value retrieved for registry from PeeringDB"
  exit 1
 fi
 AS_SET=$(echo $AS_SET | jq -r '.data[0] | to_entries[0].value' | cut -d':' -f3- | sed 's/^://')
 AS_SET_DASH=$(echo $AS_SET | tr ':' '-')
 PL4NAME="PL4-IRR-$REG--$AS_SET_DASH"
 if [ "$DEBUG" == "1" ]; then
  echo "reg: $REG"
  echo "asn: $ASN"
  echo "as set: $AS_SET"
  echo "pl4name: $PL4NAME"
 fi
fi

if [ "$OUTPUT" == "0" ]; then
 echo "now we would generate the filter list, but output supressed by flag."
fi

if [ "$OUTPUT" == "1" ]; then
 PREFIXES=$(whois -h filtergen.dan.me.uk "!g -RADB $AS_SET" | grep -v %)
 RULENUM=10
 echo "configure"
 echo "delete policy prefix-list $PL4NAME"
 while read PREFIX; do 
        echo "set policy prefix-list $PL4NAME rule $RULENUM action permit"  
        echo "set policy prefix-list $PL4NAME rule $RULENUM prefix $PREFIX" 
        echo "set policy prefix-list $PL4NAME rule $RULENUM le 24"
        RULENUM=$((RULENUM+10))
 done <<< "$PREFIXES"
 echo "commit"
 echo "save"
 echo "exit"
fi
