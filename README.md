
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

The server side will automatically run after the docker container is online. 

Use `python3 client.py` to run the program on the client side.


### Client Commands

After run the client program, you can use `help` or `h` will show the help menu.

`register` or `r` will register a new account.

`login` or `l` will log in as the existing account.

`message` or `m` can send the meesage to another user.

`view` or `v` can have a look at the message history stored locally.

`delete` or `d` can delete the message history with another user.

`logout` or `u` can log out the current account.

`quit` or `q` can exit the program safely.

## What's more

For more information and more detailed usage guides, please check the [Documentation](https://gitlab.csc.uvic.ca/courses/2022091/SENG360_COSI/assignments/erikmckelvey/project-group-18/-/wikis/Documentation)

## Authors

- Erik McKelvey
- Kester Yang
- Daming Wang
- Samuel Gao
