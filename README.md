
# Project Group 18

SENG 360 Project repository for group 18

## Description

This communication application is based on python3. We make them run in the docker container as an example of the real world senerio.

There are two part: the server end and the client end. The server part is responsible for store the registration usernames and esatablish the communication between the clients. The client is able to register, login, choose who he/she wants to talk with, send messages, and delete messages stored locally. 

## Installation

First run the command `docker-compose build` to build the docker images

Then, run the command `docker-compose up` to start up the server and two client images

## Usage

Use `docker ps --format "{{.ID}} {{.Names}}"` command to show the ID and name for the online containers.

Then use `docker exec -it <id> /bin/bash` or `docker exec -it <id> /bin/sh` to enter the container. 

Use `python3 client.py` to run the program on the client side.

The server side will automatically run after the docker container is online. 

## Authors

- Erik McKelvey
- Kester Yang
- Daming Wang
- Samuel Gao
