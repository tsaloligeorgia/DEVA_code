#!/bin/bash

dserver=2
dthreshold=1
dmu=2


echo "Running experiments..."

# User-Server Changes

for (( n = 100; n <= 500; n = n+50 ))
do
	for (( m = 2; m <= 10; m=m+1 ))
	do 
		for (( dropout = 0; dropout <= 30; dropout=dropout+10 ))
		do 		
			python3 main.py -c $n -s $m -k 1 -t 1 -f $dropout
		done
	done
done

for (( n = 100; n <= 500; n = n+50 ))
do
	for (( m = 2; m <= 10; m=m+1 ))
	do 
				
		python3 main.py -c $n -s $m -k 1 -t 1 -f 70
		
	done
done


# for (( n = 100; n <= 500; n = n+50 ))
# do
# 	for (( m = 2; m <= 5; m=m+1 ))
# 	do 
# 		for (( dropout = 0; dropout <= 30; dropout=dropout+10 ))
# 		do 		
# 			python3 main.py -c $n -s $m -k 1 -t 1 -f $dropout
# 		done
# 	done
# done

# for (( n = 1000; n <= 5000; n = n+500 ))
# do
# 	for (( m = 2; m <= 5; m=m+1 ))
# 	do 
# 		for (( dropout = 0; dropout <= 30; dropout=dropout+10 ))
# 		do 		
# 			python3 main.py -c $n -s $m -k 1 -t 1 -f $dropout
# 		done
# 	done
# done