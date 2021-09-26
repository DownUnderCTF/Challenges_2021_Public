#!/bin/bash

POW_DIFFICULTY=8000

if ! /chal/pow.py ask "$POW_DIFFICULTY"; then
    echo 'pow fail'
    exit 1
fi

exec "./server.py"