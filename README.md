# SecureChat2020
Secure Chat app for Secure Programming 2020 course


# Documentation
The underneath text forms the documentation of the SecureChat program developed for the Secure Programming course of the Deep Programming minor academic year '20/'21. All functionality and design decisions are documented in here and are structured as follows:

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
```Usage:
	./server <port>
```

The server program serves as a central point of communication within the architecture. It is responsible for managing all incoming and outgoing communication and allows multiple clients to talk to each other over a centralized instance. While it does not handle incoming client messages directly itself, it is responsible for spawning new worker processes, enabling multiple workers to communicate with eachother, creating the database and so on. 

### 2.1 Worker Processes
As mentioned, the server is responsible for spawning worker processes that handle the incoming and outgoing client communication. Every time a client connects to the server address, the server forks off a child process that becomes a worker. This worker can communicate with the client over a TCP socket. Whenever the client sends a command or message, the worker process that corresponds to the sending client receives the message or command over the socket using the `api_recv()` function, after which it is executed appropriately using the `execute_request()` function (file `worker.c` line 133). This includes (but is not limited to) logging in, registering users and handling regular messages.

Whenever a regular message is received, the worker does not communicate this message directly with the server. Instead, it stores the message in the SQLite3 database with the `insert_global()` function (file `worker.c` line 72) and notifies the server using the `notify_workers()` function (file `worker.c` line 53) by writing over the bidirectional channel (file descriptor) that is set up between the server and worker process for notifications. The server in turn responds to this notification by setting the `pending` bit in a separate struct created for each worker process that is located in `server.c`. Each worker responds to this notification by executing the `handle_s2w_notification()` function (file `worker.c` line 30), in which they request the latest message in the database with an SQL query, of which the result is written back over the client's socket.

## 3. Client Program

## 4. Security
`worker.c line 91 insert_global()`
