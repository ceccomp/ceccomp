#!/bin/bash

macros=($(grep -P '(?<=^#define )[A-Z0-9_]+' -ohr include --exclude-dir=lib/ | sort | uniq))
echo "Collected ${#macros[@]} macros from include"

not_found=()
for macro in "${macros[@]}"; do
    grep -E "\b$macro\b" -r src -r ebpf &>/dev/null
    if [ $? -ne 0 ]; then
        not_found+=("$macro")
    fi
done
echo "Found $((${#macros[@]} - ${#not_found[@]})) macro reference in src"

if [ ${#not_found[@]} -eq 0 ]; then
    echo "All macros found"
    exit 0
fi

unused=()
for macro in "${not_found[@]}"; do
    cnt=$(grep -E "\b$macro\b" -ohr include --exclude-dir=lib/ --exclude-dir=ebpf/ 2>/dev/null | wc -l)
    if [ $cnt -eq 1 ]; then
        unused+=("$macro")
    fi
done
echo "Found $((${#not_found[@]} - ${#unused[@]})) macro reference in include"

if [ ${#unused[@]} -eq 0 ]; then
    echo "All macros found"
    exit 0
fi

echo "Found ${#unused[@]} macros unused!"
for macro in "${unused[@]}"; do
    grep -E "\b$macro\b" -nr include --exclude-dir=lib/ --exclude-dir=ebpf/ --color=auto
done
exit 1
