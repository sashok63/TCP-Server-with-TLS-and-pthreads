#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_USERNAME_LENGTH 256
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int active;
    int socket;
    SSL *ssl;
    pthread_t thread;
    char usernames[BUFFER_SIZE];
} client_info;

SSL_CTX *ctx;
int server_socket;
client_info clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t server_shutting_down = 0;

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
    const SSL_METHOD *method;
    
    int port_num = atoi(argv[1]);

    //Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    //Set server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_num);

    //Initialize all client sockets, pthreads and ssl to 0
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        clients[i].active = 0;
        clients[i].socket = 0;
        clients[i].thread = 0;
        clients[i].ssl = NULL;
        memset(clients[i].usernames, 0, BUFFER_SIZE);
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
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at bind: %s\n", strerror(errno));
        }
        exit(EXIT_FAILURE);
    }

    //Listen for incoming connections
    if (listen(server_socket, 3) < 0)
    {
        perror("listen failed");
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at listen: %s\n", strerror(errno));
        }
        exit(EXIT_FAILURE);
    }

    //TLS encryption
    method = TLS_server_method();
    if (!(ctx = SSL_CTX_new(method)))
    {
        perror("SSL context failed");
        ERR_print_errors_fp(stderr);
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at TLS encryption: %s\n", strerror(errno));
        }
        exit(EXIT_FAILURE);
    }

    //Set SSL/TLS options and protocol versions
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);    //Disable SSLv2 and SSLv3
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);               //Minimum version (e.g., TLSv1.0)
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);             //Maximum version (e.g., TLSv1.2)

    //Set the certificate
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at SSL certificate: %s\n", strerror(errno));
        }
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    
    //Set the key
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at set the key: %s\n", strerror(errno));
        }
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    //Set the cipher
    if (SSL_CTX_set_cipher_list(ctx, "DEFAULT") == 0)
    {
        ERR_print_errors_fp(stderr);
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at set the cipher: %s\n", strerror(errno));
        }
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    //Graceful shutdown "Ctrl + C"
    struct sigaction sa;
    sa.sa_sigaction = handle_shutdown;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0)
    {
        perror("sigaction failed");
        if (close(server_socket) < 0)
        {
            fprintf(stderr, "Error closing server socket at sigaction: %s\n", strerror(errno));
        }
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port_num);

    //Adding clients
    while (!server_shutting_down)
    {
        //Add client to server
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) < 0)
        {
            perror("accept failed");
            continue;
        }

        //Create SSL object and attach it to the socket 
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        //Perform SSL/TLS handshake
        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            if (close(client_socket) < 0)
            {
                fprintf(stderr, "Error closing client socket at SSL/TLS handshake: %s\n", strerror(errno));
            }
            SSL_free(ssl);
            continue;
        }

        //Add the client socket to the list of clients
        pthread_mutex_lock(&clients_mutex);
        int i = 0;
        while (i < MAX_CLIENTS)
        {
            if (clients[i].socket == 0)
            {
                clients[i].socket = client_socket;
                clients[i].ssl = ssl;
                clients[i].active = 1;
                break;
            }
            ++i;
        }
        pthread_mutex_unlock(&clients_mutex);

        //If no slot found for the new client
        if (i == MAX_CLIENTS)
        {
            const char *msg = "Server is full, try again later\n";
            if (SSL_write(ssl, msg, strlen(msg)) <= 0)
            {
                fprintf(stderr, "Error sending no slot found for the new client to client %d:\n", i);
                ERR_print_errors_fp(stderr);
            }

            //Should call SSL_shutdown again, according to the OpenSSL documentation 
            int shutdown_result = SSL_shutdown(clients[i].ssl);
            if (shutdown_result == 0)
            {
                shutdown_result = SSL_shutdown(clients[i].ssl);
            }
            if (shutdown_result < 0)
            {
                int ssl_error = SSL_get_error(clients[i].ssl, shutdown_result);
                if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_SYSCALL)
                {
                    fprintf(stderr, "Error shutting down SSL for client socket %d:\n", i);
                    ERR_print_errors_fp(stderr);
                }
            }

            SSL_free(ssl);
            
            if (close(client_socket) < 0)
            {
                fprintf(stderr, "Error closing server socket at slot found for the new client: %s\n", strerror(errno));
            }
            continue;
        }

        //Create a thread for each client
        if (pthread_create(&clients[i].thread, NULL, handle_client, (void *)&clients[i]) != 0)
        {
            perror("pthread_create failed");
            pthread_mutex_lock(&clients_mutex);
            clients[i].active = 0;
            clients[i].socket = 0;
            SSL_free(clients[i].ssl);
            clients[i].ssl = NULL;
            pthread_mutex_unlock(&clients_mutex);
        }
    }

    if (close(server_socket) < 0)
    {
        fprintf(stderr, "Error closing server socket at end of main: %s\n", strerror(errno));
    }
    SSL_CTX_free(ctx);
    return 0;
}

//Handle client IO
void *handle_client(void *arg)
{
    client_info *client = (client_info *)arg;
    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    char truncated_username[MAX_USERNAME_LENGTH + 1];
    int bytes_read;
    int client_socket = client->socket;

    //Welcome message
    const char *welcome_msg = "Enter your username: ";
    if (SSL_write(client->ssl, welcome_msg, strlen(welcome_msg)) <= 0)
    {
        fprintf(stderr, "Error sending greeting to client\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    //Read username from client
    if ((bytes_read = SSL_read(client->ssl, username, sizeof(username) - 1)) <= 0)
    {
        int ssl_error = SSL_get_error(client->ssl, bytes_read);
        if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL)
        {
            fprintf(stderr, "SSL read error at username: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
        }
        else
        {
            perror("recv failed");
        }
        goto cleanup;
    }

    //Remove trailing newline character
    username[bytes_read - 1] = '\0';

    //Truncate username if it exceeds the maximum length
    if (strlen(username) > MAX_USERNAME_LENGTH)
    {
        strncpy(truncated_username, username, MAX_USERNAME_LENGTH);
        truncated_username[MAX_USERNAME_LENGTH] = '\0';
    }
    else
    {
        strncpy(truncated_username, username, MAX_USERNAME_LENGTH + 1);
    }
    
    //Store the username
    pthread_mutex_lock(&clients_mutex);
    strncpy(client->usernames, username, BUFFER_SIZE - 1);
    pthread_mutex_unlock(&clients_mutex);

    //Broadcast join message
    snprintf(buffer, sizeof(buffer), "%s has joined the chat\n", truncated_username);
    printf("%s", buffer);    //Print the logout message to the server console
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i].socket != 0 && clients[i].socket != client->socket)
        {
            if (SSL_write(clients[i].ssl, buffer, strlen(buffer)) <= 0)
            {
                fprintf(stderr, "Error sending joining to client\n");
                ERR_print_errors_fp(stderr);
                goto cleanup;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    //Chat loop
    while ((bytes_read = SSL_read(client->ssl, buffer, sizeof(buffer) - 1)) > 0)
    {
        buffer[strcspn(buffer, "\t\r\n")] = '\0';    //TODO:

        //Handle client exit
        if (strcmp(buffer, "!exit") == 0)
        {
            snprintf(buffer, sizeof(buffer), "%s has left the chat\n", truncated_username);
            printf("%s", buffer);    //Print the logout message to the server console
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; ++i)
            {
                if (clients[i].socket != 0 && clients[i].socket != client->socket)
                {
                    if (SSL_write(clients[i].ssl, buffer, strlen(buffer)) <= 0)
                    {
                        fprintf(stderr, "Error client leaving\n");
                        ERR_print_errors_fp(stderr);
                        goto cleanup;
                    }
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            break;
        }

        //Print the message to the server console
        printf("%s(id:%d): %s\n", username, client->socket, buffer);

        //Broadcast message to all clients
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; ++i)
        {
            //Construct the message to include username and id
            char message[BUFFER_SIZE + BUFFER_SIZE + 20];
            snprintf(message, sizeof(message), "%s(id:%d): %s\n", username, client_socket, buffer);
            if (clients[i].socket != 0 && clients[i].socket != client->socket)
            {
                //Send the message to each connected client
                if (SSL_write(clients[i].ssl, message, strlen(message)) < 0)
                {
                    fprintf(stderr, "Error sending message to client %d: %s\n", i, strerror(errno));
                    ERR_print_errors_fp(stderr);
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }

    int ssl_error = SSL_get_error(client->ssl, bytes_read);
    if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL)
    {
        fprintf(stderr, "SSL read error: %d\n", ssl_error);
        ERR_print_errors_fp(stderr);
    }

    //If the connection is closed, broadcast the leave message
    snprintf(buffer, sizeof(buffer), "%s has left the chat\n", truncated_username);
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i].socket != 0 && clients[i].socket != client->socket)
        {
            if (SSL_write(clients[i].ssl, buffer, strlen(buffer)) <= 0)
            {
                fprintf(stderr, "Error client leaving\n");
                ERR_print_errors_fp(stderr);
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);

cleanup:
    pthread_mutex_lock(&clients_mutex);
    if (client->ssl != NULL)
    {
        int shutdown_result = SSL_shutdown(client->ssl);
        if (shutdown_result == 0)
        {
            shutdown_result = SSL_shutdown(client->ssl);
        }
        if (shutdown_result < 0)
        {
            int ssl_error = SSL_get_error(client->ssl, shutdown_result);
            if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_SYSCALL)
            {
                fprintf(stderr, "Error shutting down SSL for client socket %d:\n", client->socket);
                ERR_print_errors_fp(stderr);
            }
        }
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->socket != 0)
    {
        if (close(client->socket) < 0)
        {
            fprintf(stderr, "Error closing client socket %d at handle_shutdown: %s\n", client->socket, strerror(errno));
        }
        client->socket = 0;
    }
    if (pthread_join(client->thread, NULL) < 0)
    {
        perror("pthread join error");
    }
    pthread_mutex_unlock(&clients_mutex);

    pthread_exit(NULL);

    printf("Client %d disconnected and cleaned up.\n", client_socket);
    
    return NULL;
}

//Shutdown entire system
void handle_shutdown(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    server_shutting_down = 1;
    printf("\nShutting down server...\n");

    //Close all client sockets and SSL connections
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i].socket != 0)
        {
            //Check if the socket is still valid
            if (fcntl(clients[i].socket, F_GETFD) != -1 || errno != EBADF)
            {
                //Close the client socket
                if (close(clients[i].socket) < 0)
                {
                    fprintf(stderr, "Error closing client socket %d at handle_shutdown: %s\n", i, strerror(errno));
                }
                clients[i].socket = 0;
                
                if (clients[i].ssl)
                {
                    int shutdown_result = SSL_shutdown(clients[i].ssl);
                    if (shutdown_result == 0)
                    {
                        shutdown_result = SSL_shutdown(clients[i].ssl);
                    }
                    if (shutdown_result < 0)
                    {
                        int ssl_error = SSL_get_error(clients[i].ssl, shutdown_result);
                        if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_SYSCALL)
                        {
                            fprintf(stderr, "Error shutting down SSL for client socket %d:\n", i);
                            ERR_print_errors_fp(stderr);
                        }
                    }
                    SSL_free(clients[i].ssl);
                    clients[i].ssl = NULL;
                }
            }
            else
            {
                fprintf(stderr, "Invalid socket descriptor %d at handle_shutdown\n", clients[i].socket);
                clients[i].socket = 0;
                clients[i].ssl = NULL;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    //Join active threads
    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i].active)
        {
            int err_pthread = pthread_cancel(clients[i].thread);
            if (err_pthread != 0)
            {
                fprintf(stderr, "Error joining thread %d, error=%d\n", i, err_pthread);
            }
            clients[i].active = 0;
        }
    }

    //Release the listening port
    if (close(server_socket) < 0)
    {
        fprintf(stderr, "Error closing server socket at release the listening port: %s\n", strerror(errno));
    }

    SSL_CTX_free(ctx);
    
    printf("Server shutdown complete.\n");
    exit(EXIT_SUCCESS);
}