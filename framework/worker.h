#ifndef _WORKER_H_
#define _WORKER_H_

char *db_sql;
sqlite3 *db;
sqlite3_stmt *db_stmt;
int db_rc;

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

#endif /* !defined(_WORKER_H_) */
