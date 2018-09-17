#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

#include "socket.h"
#include "jobprotocol.h"

int soc;

void sig_handler(int signo)
{
	if (signo == SIGINT){
		close(soc);
		printf("\nClosing client.\n");
		exit(0);
	}
}


int main(int argc, char **argv) {
    // This line causes stdout and stderr not to be buffered.
    // Don't change this! Necessary for autotesting.
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 2) {
        fprintf(stderr, "Usage: jobclient hostname\n");
        exit(1);
    }

    soc = connect_to_server(PORT, argv[1]);

	int max_fd = soc;
	fd_set all_fds, listen_fds;
	FD_ZERO(&all_fds);
	FD_SET(soc, &all_fds);
	FD_SET(STDIN_FILENO, &all_fds);
	
    /* TODO: Accept commands from the user, verify correctness 
     * of commands, send to server. Monitor for input from the 
     * server and echo to STDOUT.
     */

	char * buff = malloc(MAX_JOBS);
	printf("[CLIENT: Enter a command] "); 
	while(1){
		if (signal(SIGINT, sig_handler) == SIG_ERR){
			printf("can't catch signal\n");
		}
		listen_fds = all_fds;
		int ready = select(max_fd+1, &listen_fds, NULL, NULL, NULL);
		if (ready == -1){
			perror("server: select error");
			exit(1);
		}
		
		if(FD_ISSET(STDIN_FILENO, &listen_fds)){
			while(fgets(buff, MAX_JOBS, stdin) ){
				break;
			}
			if (strcmp(buff, "exit\n") == 0){
				close(soc);
				exit(0);
			}
			
			if ((strstr(buff, "run") == buff) || (strcmp(buff, "jobs\n") == 0) || (strstr(buff, "kill") == buff) || (strstr(buff, "watch") == buff)){
				if(write(soc, buff, MAX_JOBS)== -1){
					perror("write to socket");
					exit(1);
				}
			}
			
			else{
				printf("Command not found\n[CLIENT: Enter a command] ");
			}
			
		}
		else if (FD_ISSET(soc, &listen_fds)){
			int num_read = read(soc, buff, 256);
			if (buff[num_read-2]=='\r' && buff[num_read-1]=='\n' && strlen(buff)>7){
				buff[num_read] = '\0';
				if (strcmp(buff, "aaaaaaaaaaa\r\n") != 0){
					printf("%s", buff);
				}
				
				if(strstr(buff, "\n[SERVER] Shutting down\r\n")){
					close(soc);
					return 1;
				}
				else{
					printf("[CLIENT: Enter a command] ");
				}
			}
			
			else{
				buff[num_read] = '\0';
				printf("%s", buff);
			}
		}
		
	}

	close(soc);
    exit(0);
}
