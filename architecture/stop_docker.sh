#!/bin/bash
docker compose rm -fs
docker compose down
service mysql stop
service nginx stop
