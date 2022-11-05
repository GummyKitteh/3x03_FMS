#!/bin/bash
docker compose rm -fs
docker compose down
service mysql stop
service nginx stop
sudo ufw-docker delete allow Flask4Nginx 5000
sudo ufw-docker delete allow Nginx4Flask 80
sudo ufw-docker delete allow Nginx4Flask 443
sudo ufw-docker delete allow jenkins 8080
sudo ufw-docker delete allow jenkins 50000
sudo ufw-docker delete allow docker 3000
sudo ufw-docker delete allow docker 5555
sudo ufw-docker delete allow docker 2376
sudo ufw disable
sudo systemctl restart ufw
