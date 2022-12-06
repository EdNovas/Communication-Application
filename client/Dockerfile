# This image uses the latest python image running Alpine Linux
FROM python:3.12-rc-alpine

# Create and set working directory
RUN mkdir /usr/src/client
WORKDIR /usr/src/client

# apk update and install dependancies for cryptography package
RUN apk update && apk add python3-dev \
	gcc \
	libffi-dev \
	musl-dev

# Copy and install pip dependancies
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt

# Copy the entire directory to the working directory
COPY . .
