#!/bin/bash
sudo docker compose rm -fs
sudo docker compose up --build -d
sudo ufw enable
sudo ufw-docker allow Nginx4Flask 80
sudo ufw-docker allow Nginx4Flask 443
sudo ufw reload
