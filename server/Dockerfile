# This image uses the latest python image running Alpine Linux
FROM python:3.12-rc-alpine

# Create and set working directory
RUN mkdir /usr/src/server
WORKDIR /usr/src/server

# Copy and install pip dependancies
COPY ./requirements.txt .
RUN pip install -r requirements.txt

# Copy the entire directory to the working directory
COPY . .

# Run the server application
CMD ["python3", "./server.py"]
