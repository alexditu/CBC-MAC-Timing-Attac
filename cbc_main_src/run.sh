#!/bin/bash

for i in `seq 1 20`; do
    taskset -c 5 ./$1
done
