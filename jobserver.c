#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <termios.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "socket.h"
#include "jobprotocol.h"

#define QUEUE_LENGTH 5

#ifndef JOBS_DIR
    #define JOBS_DIR "jobs/"
#endif

#define MAX_CONNECTIONS 40
#define BUF_SIZE 256

struct job {
	int pid;
	int watchers[MAX_CONNECTIONS];
};

struct job jobs1[MAX_JOBS];

struct sockname {
    int sock_fd;
    char *username;
};

struct sockname usernames[MAX_CONNECTIONS];

void checker(){
	for (int i = 0; i < MAX_JOBS; i++){
		if (jobs1[i].pid != -1){	
			if (kill(jobs1[i].pid,0) != 0){
				jobs1[i].pid = -1;
			}
		}
	}
}

int max_job_check(){
	checker();
	int check = 0;
	
	for (int i =0; i < MAX_JOBS; i++){
		if (jobs1[i].pid == -1){
			check++;
			break;
		}
	}
	return check;
}

void sig_handler(int signo)
{
	if (signo == SIGINT){
		for (int i = 0; i<MAX_JOBS; i++){
			if (jobs1[i].pid != -1){
				kill(jobs1[i].pid, SIGINT);
			}
		}
		printf("\n[SERVER] Shutting down\r\n");
		for (int i = 0; i < MAX_CONNECTIONS; i++){
			if (usernames[i].sock_fd > -1){
				
				write(usernames[i].sock_fd, "\n[SERVER] Shutting down\r\n", strlen("\n[SERVER] Shutting down\r\n"));
				close(usernames[i].sock_fd);
			}
		}
	}
	exit(0);
}

int setup_new_client(int fd, struct sockname *usernames) {
    int user_index = 0;
    while (user_index < MAX_CONNECTIONS && usernames[user_index].sock_fd != -1) {
        user_index++;
    }

    int client_fd = accept_connection(fd);
    if (client_fd < 0) {
        return -1;
    }

    if (user_index >= MAX_CONNECTIONS) {
        fprintf(stderr, "server: max concurrent connections\n");
        close(client_fd);
        return -1;
    }
	
    usernames[user_index].sock_fd = client_fd;
    usernames[user_index].username = NULL;
	
    return client_fd;
}


int read_from(int client_index, struct sockname *usernames) {
    int fd = usernames[client_index].sock_fd;
    char buf[BUF_SIZE + 1];
	buf[0] = '\0';
	char buf2[BUF_SIZE + 1];
	strncpy(buf2, "[SERVER] ", strlen("[SERVER] "));

	checker();
	
    int num_read = read(fd, &buf, BUF_SIZE);
	if (buf[0] != '\0'){
		printf("[CLIENT %d] %s", usernames[client_index].sock_fd, buf);
	}
	else{
		printf("[CLIENT %d] ", usernames[client_index].sock_fd);
	}
 	if (strstr(buf, "run") == buf && buf[3] == ' '){
		int c = max_job_check();
		if (c == 0){
			char b[BUFSIZE];
			strncpy(b, "[SERVER] MAXJOBS exceeded\r\n", strlen("[SERVER] MAXJOBS exceeded\r\n"));
			printf("%s", b);
			if (num_read == 0 || write(fd, b, strlen(b)) != strlen(b)) {
				usernames[client_index].sock_fd = -1;
				return 1;
			}
			return 0;
		}
		int big_fd[2];
		pipe(big_fd);
		int big_pid = fork();

		if (big_pid < 0){
			perror("fork fail");
			exit(1);
		}
		
		else if (big_pid == 0){
			char * argv[BUFSIZE];
			for (int index = 0; index< BUFSIZE; index++){
				argv[index] = malloc(sizeof(char) * (BUFSIZE+1));
			}
				
			int pid = fork();
			if (pid < 0){
				perror("fork fail");
				exit(1);
			}
			
			else if (pid == 0){
				int n = 0;
				int j = 0;

				for (int i = 4; 1; i++){
					if (buf[i] =='\n' || buf[i] == '\0'){
						break;
					}
					else if (buf[i] != ' '){
						argv[n][j++] = buf[i];
					}
					else{
						n++;
						j=0;
					}
				}
				
				argv[n+1] = NULL;
				char exe_file[BUFSIZE];
				sprintf(exe_file, "%s%s", JOBS_DIR, argv[0]);
				char j1[BUFSIZE];
				strncpy(j1, "[SERVER] ", strlen("[SERVER] "));
				strcat(j1, "Job ");
				char num2[10];
				sprintf(num2, "%d", getpid());
				strcat(j1, num2);
				strcat(j1, " created\n");
				printf("%s", j1);
				if (num_read == 0 || write(fd, j1, strlen(j1)) != strlen(j1)) {
					usernames[client_index].sock_fd = -1;
					return 1;
				}

				if ((dup2(fd, STDOUT_FILENO) == -1)){
					perror("dup2 fail");
					exit(1);
				}
				
				if ((dup2(fd, fileno(stderr)) == -1)){
					perror("dup2 fail");
					exit(1);
				}

				if (execvp(exe_file, argv) < 0){
					char exe_fail[BUFSIZE];
					strncpy(exe_fail, "[SERVER] Encountered a problem running the executable.\n", strlen("[SERVER] Encountered a problem running the executable.\n"));
					if (num_read == 0 || write(fd, exe_fail, strlen(exe_fail)) != strlen(exe_fail)) {
						usernames[client_index].sock_fd = -1;
						return 1;
					}
					perror("execvp fail");
					exit(1);
				}

				exit(0);
			}
			
			else {
				pid_t p;
				int status;
				if (write(big_fd[1], &pid, sizeof(int))==-1){
					perror("write fail");
					exit(1);
				}
				if ((p = wait(&status)) == -1) {
					perror("wait");
				}
				else{
					if (WIFEXITED(status)) {
						close(big_fd[0]);
						if (write(big_fd[1], &pid, sizeof(int))==-1){
							perror("write fail");
							exit(1);
						}
						
						char buf_job[BUFSIZE];
						strncpy(buf_job, "[JOB ", strlen("[JOB "));
						
						char num[10];
						sprintf(num, "%d", WEXITSTATUS(status));
						char pid_j[10];
						sprintf(pid_j, "%d", pid);
						
						strcat(buf_job, pid_j);
						strcat(buf_job, "] Exited with status ");
						strcat(buf_job, num);
						strcat(buf_job, ".\r\n");
					
						printf("%s", buf_job);
						if (num_read == 0 || write(fd, buf_job, strlen(buf_job)) != strlen(buf_job)) {
							usernames[client_index].sock_fd = -1;
							return 1;
						}
								
						exit(0);
					}
				}
				exit(0);
			}
			exit(0);
		}
		
		else{
			int job_pid;
			while (read(big_fd[0], &job_pid, sizeof(int)) > 0) {
				break;
			}
			for (int i = 0; i < MAX_JOBS; i++){
				if (jobs1[i].pid == -1){
					jobs1[i].pid = job_pid;
					for (int j = 0; j < MAX_CONNECTIONS; j++){
						if ((jobs1[i].watchers)[j] == -1){
							(jobs1[i].watchers)[j] = fd;
							break;
						}
					}
					break;
				}
			}

			return 0;
		}
	}
	
	if (strcmp(buf, "jobs\n") == 0){
		char buf3[BUF_SIZE+1];
		int non_zero_jobs=0;
		char pids[BUF_SIZE+1];
		strncpy(pids, " ", strlen(" "));
		for (int i = 0; i < MAX_JOBS; i++){
			if (jobs1[i].pid != -1){
				char * x = malloc(10);
				non_zero_jobs++;
				sprintf(x, "%d", jobs1[i].pid);
				strcat(pids, x);
				strcat(pids, " ");
			}
		}
		
		if (non_zero_jobs==0){
			strncpy(buf3, "[SERVER] ", strlen("[SERVER] "));
			strcat(buf3, "No currently running jobs\r\n");
			buf[num_read] = '\0';
			printf("%s", buf3);
			if (num_read == 0 || write(fd, buf3, strlen(buf3)) != strlen(buf3)) {
				usernames[client_index].sock_fd = -1;
				return 1;
			}
			for (int i = 0; i < BUF_SIZE+1; i++){
				buf[i]='\0';
				buf2[i]='\0';
				buf3[i]='\0';
			}
			return 0;
		}
		
		else{
			strncpy(buf3, "[SERVER]", strlen("[SERVER]"));
			strcat(buf3, pids);
			strcat(buf3, "\r\n");
			printf("%s", buf3);
			if (num_read == 0 || write(fd, buf3, strlen(buf3)) != strlen(buf3)) {
				usernames[client_index].sock_fd = -1;
				return 1;
			}
			
			for (int i = 0; i < BUF_SIZE+1; i++){
				buf[i]='\0';
				buf2[i]='\0';
				pids[i]='\0';
			}
			
			return 0;
		}
		
	}
	
	if (strstr(buf, "kill") == buf && buf[4] == ' '){
		int index = 5;
		while(buf[index]!='\0'){
			index++;
		}
		char * pidstr;
		pidstr = strndup(buf+5, index);

		int pid = strtol(pidstr, NULL, 10);
		if (pid == 0 || pid == -1){
			buf[num_read] = '\0';
			char error[BUFSIZE];
			sprintf(error, "[SERVER] Invalid command: %s\r\n", buf);

			if (num_read == 0 || write(fd, error, strlen(error)) != strlen(error)) {
				usernames[client_index].sock_fd = -1;
				return 1;
			}
			return 0;
		}
		for (int i = 0; i<MAX_JOBS; i++){
			if (jobs1[i].pid == pid){
				kill(pid, SIGINT);
				jobs1[i].pid = -1;
				char buf3[BUF_SIZE+1];
				char * x = malloc(10);
				strncpy(buf3, "\n[Job ", strlen("\n[Job "));
				sprintf(x, "%d", pid);

				strcat(buf3, x);
				strcat(buf3, "] Exited due to signal.\r\n");
				char garbage[BUFSIZE];
				int l=-1;
				
				for (int j = 0; j < MAX_CONNECTIONS; j++){
					if ((jobs1[i].watchers)[j] != -1){
						if((jobs1[i].watchers)[j] == fd){
							l++;
						}
						printf("%s", buf3);
						if (num_read == 0 || write((jobs1[i].watchers)[j], buf3, strlen(buf3)) != strlen(buf3)) {
							usernames[client_index].sock_fd = -1;
							return 1;
						}
						(jobs1[i].watchers)[j] = -1;
					}
				}
				if (l==-1){
					strncpy(garbage, "aaaaaaaaaaa\r\n", strlen("aaaaaaaaaaa\r\n"));
					if (num_read == 0 || write(fd, garbage, strlen(garbage)) != strlen(garbage)) {
						usernames[client_index].sock_fd = -1;
						return 1;
					}
				}
				for (int i = 0; i < BUF_SIZE+1; i++){
					buf[i]='\0';
					buf2[i]='\0';
					buf3[i]='\0';
				}				
				return 0;
			}
		}
		char buf3[BUF_SIZE+1];
		char * x = malloc(10);
		strncpy(buf3, "[SERVER] Job ", strlen("[SERVER] Job "));
		sprintf(x, "%d", pid);
		strcat(buf3, x);
		strcat(buf3, " not found\r\n");
		printf("%s", buf3);
		if (num_read == 0 || write(fd, buf3, strlen(buf3)) != strlen(buf3)) {
			usernames[client_index].sock_fd = -1;
			return 1;
		}
		for (int i = 0; i < BUF_SIZE+1; i++){
			buf[i]='\0';
			buf2[i]='\0';
			buf3[i]='\0';
		}
		return 0;
		
	}
	
	if (strstr(buf, "watch") == buf && buf[5] == ' '){
		int index = 6;
		while(buf[index]!='\0'){
			index++;
		}
		char buff[BUFSIZE];
		
		char * pidstr;
		
		pidstr = strndup(buf+6, index);

		int pid = strtol(pidstr, NULL, 10);
		
		if (pid == 0 || pid == -1){
			buf[num_read] = '\0';
			char error[BUFSIZE];
			sprintf(error, "[SERVER] Invalid command: %s\r\n", buf);

			if (num_read == 0 || write(fd, error, strlen(error)) != strlen(error)) {
				usernames[client_index].sock_fd = -1;
				return 1;
			}
			return 0;
		}
		
		char pid_char[20];
		sprintf(pid_char, "%d", pid);
		int check = 0;
		for (int i = 0; i<MAX_JOBS; i++){
			if (jobs1[i].pid == pid){
				for (int j = 0; j < MAX_CONNECTIONS; j++){
					if ((jobs1[i].watchers)[j] == fd){
						(jobs1[i].watchers)[j] = -1;
						strncpy(buff, "[SERVER] No longer watching job ", strlen("[SERVER] No longer watching job "));
						strcat(buff, pid_char);
						strcat(buff, "\r\n");
						check++;
						break;
					}
				}
				if (check==0){
					for (int j = 0; j < MAX_CONNECTIONS; j++){
						if ((jobs1[i].watchers)[j] == -1){
							(jobs1[i].watchers)[j] = fd;
							strncpy(buff, "[SERVER] Watching job ", strlen("[SERVER] Watching job "));
							strcat(buff, pid_char);
							strcat(buff, "\r\n");
							break;
						}
					}
				}		
				break;
			}
			else{
				strncpy(buff, "[SERVER] Job ", strlen("[SERVER] Job "));
				strcat(buff, pid_char);
				strcat(buff, " not found\r\n");
				break;
			}
		}
		printf("%s", buff);
		if (num_read == 0 || write(fd, buff, strlen(buff)) != strlen(buff)) {
			usernames[client_index].sock_fd = -1;
			return 1;
		}
		
		return 0; 
	}

    buf[num_read] = '\0';
	char error[BUFSIZE];
	sprintf(error, "[SERVER] Invalid command: %s\r\n", buf);

    if (num_read == 0 || write(fd, error, strlen(error)) != strlen(error)) {
        usernames[client_index].sock_fd = -1;
        return 1;
    }

	for (int i = 0; i < BUF_SIZE+1; i++){
		buf[i]='\0';
		buf2[i]='\0';
	}
	
    return 0;
}


int main(void) {
    // This line causes stdout and stderr not to be buffered.
    // Don't change this! Necessary for autotesting.
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct sockaddr_in *self = init_server_addr(PORT);
    int sock_fd = setup_server_socket(self, QUEUE_LENGTH);
	
	
	for (int i = 0; i< MAX_JOBS; i++){
		jobs1[i].pid = -1;
		for (int j = 0; j< MAX_CONNECTIONS; j++){
			(jobs1[i].watchers)[j] = -1;
		}
	}
	
    for (int index = 0; index < MAX_CONNECTIONS; index++) {
        usernames[index].sock_fd = -1;
        usernames[index].username = NULL;
    }

    /* TODO: Initialize job and client tracking structures, start accepting
     * connections. Listen for messages from both clients and jobs. Execute
     * client commands if properly formatted. Forward messages from jobs
     * to appropriate clients. Tear down cleanly.
     */

    /* Here is a snippet of code to create the name of an executable to execute:
     * char exe_file[BUFSIZE];
     * sprintf(exe_file, "%s/%s", JOBS_DIR, <job_name>);
     */
	 
    int max_fd = sock_fd;
    fd_set all_fds, listen_fds;
    FD_ZERO(&all_fds);
    FD_SET(sock_fd, &all_fds);

    while (1) {
		
		if (signal(SIGINT, sig_handler) == SIG_ERR){
			printf("can't catch signal\n");
		}
        listen_fds = all_fds;
        int nready = select(max_fd + 1, &listen_fds, NULL, NULL, NULL);
        if (nready == -1) {
            perror("server: select");
            exit(1);
        }

        // Is it the original socket? Create a new connection ...
        if (FD_ISSET(sock_fd, &listen_fds)) {
            int client_fd = setup_new_client(sock_fd, usernames);
            if (client_fd < 0) {
                continue;
            }
            if (client_fd > max_fd) {
                max_fd = client_fd;
            }
            FD_SET(client_fd, &all_fds);
            printf("Accepted connection\n");
        }

        // Next, check the clients.
        // NOTE: We could do some tricks with nready to terminate this loop early.
        for (int index = 0; index < MAX_CONNECTIONS; index++) {
            if (usernames[index].sock_fd > -1 && FD_ISSET(usernames[index].sock_fd, &listen_fds)) {
                // Note: never reduces max_fd
                int client_closed = read_from(index, usernames);
                if (client_closed > 0) {
					printf("Connection closed\n");
					FD_CLR(client_closed, &all_fds);
                }
            }
        }
	}


    free(self);
    close(sock_fd);
    return 0;
}

