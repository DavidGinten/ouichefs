#!/bin/bash

RUNS=100
SUM=0
COUNT=0

echo "Running ./bench $RUNS times..."

for ((i=1; i<=RUNS; i++)); do
    OUTPUT=$(./bench)
    
    # Make sure the output is a number
    if [[ "$OUTPUT" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        SUM=$(echo "$SUM + $OUTPUT" | bc)
        ((COUNT++))
    else
        echo "Run $i: Invalid output -> $OUTPUT"
    fi
done

if [ "$COUNT" -eq 0 ]; then
    echo "No valid runs completed."
    exit 1
fi

AVG=$(echo "scale=6; $SUM / $COUNT" | bc)
echo "Average over $COUNT runs: $AVG"
