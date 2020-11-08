# SecureChat2020
Secure Chat app for Secure Programming 2020 course


# Documentation
The underneath text forms the documentation of the SecureChat program developed for the Secure Programming course of the Deep Programming minor academic year '20/'21. All functionality and design decisions are documented in here and are structued as follows:

	1. Architecture
	2. Server program
	3. Client program

## 1. Architecture
The software in its current state is structured as shown in figure 1. The figure shows roughly how the communication is set up in its current state. It consists of a the following components:

	1. Clients
	2. Workers
	3. Server
	4. SQLite3 Database

The server functions as a central point of communication between these components. It handles all incoming and outgoing messages and stores these in the SQLite3 database, so that they may be recalled whenever required. Once a client connects to the server by providing its address and port (see section 2 on the client program for usage), a worker process is forked off by the server to ensure the possibility of multiple clients. This worker process handles all communication with an individual client. For more information on the client to worker and worker to server communication, please see section 2 and 3 on the server and client programs. 

![Figure 1 - Software Architecture](docs/arch.png)

There are different types of communication present within this architecture, which can be described as follows:

Communication Type | Description
-------------------|-------------
Client <-> worker  | Communication over TCP socket
Worker <-> server  | Communication over File Descriptors
Server <-> database| Communication using SQL queries


## 2. Server Program
The server program serves as a central point of communication within the architecture. It is responsible for managing all incoming and outgoing communication and allows multiple clients to talk to each other over a centralized instance. While it does not handle incoming client messages directly itself, it is responsible for spawning new worker processes, enabling multiple workers to communicate with eachother, creating the database and so on. 

### 2.1 Worker Processes
As mentioned, the server is responsible for spawning worker processes that handle the incoming and outgoing client communication. 

## 3. Client Program
