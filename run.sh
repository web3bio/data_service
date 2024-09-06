#!/bin/sh

# use supervisor to start module sbin
supervisord -c /app/supervisord.conf

# use supervisord
if [ $? -eq 0 ]
then
    echo "supervisorctl restart all"
    supervisorctl -c /app/supervisord.conf restart all

# not use supervisord
else
    echo "not use supervisord"
fi