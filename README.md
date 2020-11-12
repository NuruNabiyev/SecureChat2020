# SecureChat2020
Secure Chat app for Secure Programming 2020 course


# Documentation
The underneath text forms the documentation of the SecureChat program developed for the Secure Programming course of the Deep Programming minor academic year '20/'21. The software is developed in C. All functionality and design decisions are documented in here and are structured as follows:

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
```
Usage:
	./server <port>
```

The server program serves as a central point of communication within the architecture. It is responsible for managing all incoming and outgoing communication and allows multiple clients to talk to each other over a centralized instance. While it does not handle incoming client messages directly itself, it is responsible for spawning new worker processes, enabling multiple workers to communicate with eachother, creating the database and so on. The server allows a total of 16 clients at once.

### 2.1 Worker Processes
As mentioned, the server is responsible for spawning worker processes that handle the incoming and outgoing client communication. Every time a client connects to the server address, the server forks off a child process that becomes a worker. This worker can communicate with the client over a TCP socket. Whenever the client sends a command or message, the worker process that corresponds to the sending client receives the message or command over the socket using the `api_recv()` function, after which it is executed appropriately using the `execute_request()` function (file `worker.c line 133`). This includes (but is not limited to) logging in, registering users and handling regular messages.

Whenever a regular message is received, the worker does not communicate this message directly with the server. Instead, it stores the message in the SQLite3 database with the `insert_global()` function (file `worker.c line 72`) and notifies the server using the `notify_workers()` function (file `worker.c line 53`) by writing over the bidirectional channel (file descriptor) that is set up between the server and worker process for notifications. The server in turn responds to this notification by setting the `pending` bit in a separate struct created for each worker process that is located in `server.c`. Each worker responds to this notification by executing the `handle_s2w_notification()` function (file `worker.c line 30`), in which they request the latest message in the database with an SQL query, of which the result is written back over the client's socket.

![Figure 2 - Communication Cycle](docs/servercycle.png)

### 2.2 Creation of the database
In order for the workers to store messages in the database, the server must create this database if it does not exist yet. For now, this is done in the `main()` function of `server.c (line 372)`. The filename of the database is `chat.db` and consists of a table called `global_chat` with the following columns:

	- id (primary key)
	- Message

In the future, this could be expanded using a separate column for timestamp, username (foreign key) and chat ID (foreign key). The desired database layout is shown in figure 3 and allows for added security by salting user passwords if a separate user table is made and separate chat logs such as private chat messages.

![Figure 3 - Database setup](docs/database.png)
 

## 3. Client Program
```
Usage:
	./client <server address> <server port>
```

The client program can be used by a user to connect to the server and send messages to other users. It does so by connecting to the server with a TCP socket, unaware of the presence of the worker processes. Its only concern is parsing user commands, writing its message over the socket and handling the response. In the future, an extra task will be added which involves the storing of other client's public keys for use. This is due when cryptography is implemented. Communication with the workers is done through the API-interface provided by the framework, which allows the client to store information about the message and send this to the server.

### 3.1 Command Parsing
For the parsing and handling of user commands, the client uses the file `ui.c`. This file contains all the possible user commands (also listed in table 1) and performs the necessary checks before executing them. Right now, the only functionality provided by parsing is the ability to set the state indicating a client is 'logged in' and exiting the program. Furthermore, empty messages are not allowed and a user is not allowed to send messages before being logged in.

Command | Description
--------|-------------
/login <username> <password>\* | Allow the user to log in
/register <username> <password>\* | Allow the user to register a new account, user is logged in automatically after registering
/users\* | Prints the amount of online users
/exit | Exits the client program

## 4. Security
Because this is only the first phase of development and requires the functionality only, no security implementations have been made so far. However, in order to ensure no vulnerabilities created are overlooked or forgotten, the list underneath is kept to ensure all vulnerabilities will be fixed before the third deadline. 

- [ ] Fix the SQL Injection vulnerability by parameterizing the query at `worker.c line 91`.
- [ ] Fix the double free bug in `worker.c` (yet to be located).
- [x] Fix the nullbyte injection vulnerability in `worker.c`.
- [ ] Fix the buffer overflow vulnerability on client input and worker handler with bounds-checking.


## Notes
In the commands table, a few commands are marked. These are commands that the client program will be able to parse, but of which the functionality has not actually been implemented yet. The login and register commands show very similar behaviour due to the abstraction of a user not being implemented yet. The users function returns a fixed message because of this exact reason.




# Assignment 1.B - Security by Design

## Security Properties of Encryption
In the below image, an overview is given of the earlier presented architecture in combination with the applied encryption. There are, wherever required, two types of encryption used; a hybrid encryption scheme and an asymmetric encryption scheme. The hybrid encryption scheme is used for the messaging protocol and utilizes RSA (asymmetric) and AES (symmetric) to mitigate the overhead of using RSA only. Communication regarding key management can be done with asymmetric encryption only.

![Figure 4 - Applied Cryptography](docs/crypto-arch.png)




