#!/bin/bash

echo "What is your name?"
read name

echo "How old are you?"
read age
echo "How good are you? (0-9)"
read skills

echo "Hello $name, You are $age years old. Lets calculate when you will be a millionaire by using your skills."

echo "Calculating... Lets dring some hot chocolate."
sleep 1

getrich=$((( $RANDOM % 24 ) + $age - $skills))

echo "You will be rich when you will $getrich years old."
