#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

int server_socket;
int client_sockets[MAX_CLIENTS];
char usernames[MAX_CLIENTS][BUFFER_SIZE];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_client(void *arg);
void handle_shutdown(int sig, siginfo_t *info, void *context);

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t tid;
    
    int port_num = atoi(argv[1]);
    
    //Set server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_num);

    //Initialize all client sockets to 0 (not used)
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        client_sockets[i] = 0;
        memset(usernames[i], 0, BUFFER_SIZE);
    }

    //Create server socket TCP
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //Bind socket to the address and port
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    //Listen for incoming connections
    if (listen(server_socket, 3) < 0)
    {
        perror("listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port_num);

    //Graceful shutdown    (Ctrl + C)
    struct sigaction sa;
    sa.sa_sigaction = handle_shutdown;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0)
    {
        perror("sigaction failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) < 0)
        {
            perror("accept failed");
            continue;
        }

        //Add the client socket to the list of clients
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; ++i)
        {
            if (client_sockets[i] == 0) {
                client_sockets[i] = client_socket;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);

        //Create a thread for each client
        if (pthread_create(&tid, NULL, handle_client, (void *)&client_socket) != 0)
        {
            perror("pthread_create failed");
        }
    }

    close(server_socket);
    return 0;
}

void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    char buffer[BUFFER_SIZE];
    int bytes_read;
    char *greeting = "Enter your username: ";

    //Registration
    char username[BUFFER_SIZE];
    write(client_socket, greeting, strlen(greeting));
    if ((bytes_read = read(client_socket, username, sizeof(username) - 1)) > 0)
    {
        username[strcspn(username, "\r\n")] = '\0';
    }

    //Store the username
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (client_sockets[i] == client_socket)
        {
            strncpy(usernames[i], username, BUFFER_SIZE);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    //Chat loop
    while ((bytes_read = read(client_socket, buffer, sizeof(buffer) - 1)) > 0)
    {
        buffer[strcspn(buffer, "\r\n")] = '\0';

        if (strcmp(buffer, "!exit") == 0)
        {
            printf("Logged out %s(id:%d)\n",
                username, client_socket);
            break;
        }

        printf("Received from %s(id:%d): %s\n",
                username, client_socket, buffer);

        //Echo the message back to the client
        // write(client_socket, buffer, strlen(buffer));

        // Broadcast the message to all clients
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; ++i)
        {
            if (client_sockets[i] != 0 && client_sockets[i] != client_socket)
            {
                //Construct the message to include username and id
                char message[BUFFER_SIZE + BUFFER_SIZE + 20];
                snprintf(message, sizeof(message), "%s(id:%d): %s\n",
                         username, client_socket, buffer);
                
                //Send the message to each connected client
                if (write(client_sockets[i], message, strlen(message)) < 0)
                {
                    fprintf(stderr, "Error sending message to client %d: %s\n",
                            i, strerror(errno));
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }

    //Remove the client socket from the list and close it
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (client_sockets[i] == client_socket)
        {
            client_sockets[i] = 0;
            memset(usernames[i], 0, BUFFER_SIZE);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    close(client_socket);
    return NULL;
}

void handle_shutdown(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    char *str = "Server is shutting down\n";

    printf("\nShutting down server...\n");
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (client_sockets[i] != 0)
        {
            if (write(client_sockets[i], str, strlen(str)) < 0)
            {
                fprintf(stderr, "Error sending shutdown message to client %d: %s\n",
                        i, strerror(errno));
            }

            if (close(client_sockets[i]) < 0)
            {
                fprintf(stderr, "Error closing client socket %d: %s\n",
                        i, strerror(errno));
            }
            else
            {
                client_sockets[i] = 0;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (close(server_socket) < 0)
    {
        fprintf(stderr, "Error closing server socket: %s\n", strerror(errno));
    }

    printf("Server shutdown complete.\n");
    exit(0);
}