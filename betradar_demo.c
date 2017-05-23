#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <signal.h>

#define FAIL    -1
#define USER ""
#define PASSWORD ""

SSL_CTX *ctx;
SSL *ssl;

int OpenConnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	if( (host = gethostbyname(hostname)) == NULL )
	{
		printf("Error: %s\n",hostname);
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if( connect(sd, (struct sockaddr*)&addr,sizeof(addr)) != 0 )
	{
		printf("connect error\n");
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}
SSL_CTX *InitCTX(void)
{
	SSL_CTX *ctx;
	SSL_library_init();  
	OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
	SSL_load_error_strings();  /* Bring in and register error messages */
	ctx = SSL_CTX_new(SSLv23_client_method());  
	if( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		printf("Eroor: %s\n",stderr);
		abort();
	}
	return ctx;
}
void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);/* get the server"s certificate */
	if( cert != NULL )
	{
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		free(line);      /* free the malloc"ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		free(line);      /* free the malloc"ed string */
		X509_free(cert);    /* free the malloc"ed certificate copy */
	}
	else
	{
		printf("No certificates.\n");
	}
}

void heartbeat(int signo)
{
	char *msg = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<ct/>\n";
	SSL_write(ssl, msg,strlen(msg));  /* encrypt & send message */
}

int main(int count, char* strings[])
{
	int server;
	char buf[1024];
	char rec[6];
	char book_msg[128];
	int bytes;
	char*hostname, *portnum, *matchid;

	struct itimerval time_value, old_time_value;
	struct sigaction act;

	if( count != 4 )
	{
		printf("usage: %s <hostname> <portnum> <matchid>\n", strings[0]);
		exit(0);
	}

	// 设置定时器
	time_value.it_interval.tv_sec = 20;
	time_value.it_interval.tv_usec = 0;
	time_value.it_value.tv_sec = 20;
	time_value.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &time_value, 0);

	signal(SIGALRM, heartbeat);

	SSL_library_init();
	hostname = strings[1];
	portnum = strings[2];
	matchid = strings[3];
	ctx = InitCTX();
	server = OpenConnection(hostname,atoi(portnum));
	ssl = SSL_new(ctx);     /* create new SSL connection state */
	SSL_set_fd(ssl, server);   /* attach the socket descriptor */
	if(SSL_connect(ssl) == FAIL)  /* perform the connection */
	{
		printf("Error: %s\n", stderr);
		ERR_print_errors_fp(stderr);
	}
	else
	{
		FILE *fd;
		char filename[20];
		bzero(filename, 20);
		sprintf(filename, "match_%s.log", matchid);
		fd = fopen(filename, "a+");
		time_t now;
		struct tm *ptm;
		char receive[1024];
		char bmsg[256];
		bzero(receive, sizeof(receive));
		bzero(bmsg, sizeof(bmsg));

		ShowCerts(ssl);       /* get any certs */
		char *msg = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<login><credential><loginname value=\""USER"\"/><password value=\""PASSWORD"\"/></credential></login>\n";
		SSL_write(ssl, msg, strlen(msg));  /* encrypt & send message */

		// book
		sprintf(bmsg, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<bookmatch matchid=\"%s\"/>\n", matchid);
		SSL_write(ssl, bmsg, strlen(bmsg));

		sprintf(book_msg, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<match matchid=\"%s\"/>\n", matchid);
		SSL_write(ssl, book_msg, strlen(book_msg));

		bzero(rec, sizeof(rec));
		while (1)
		{
			bytes = SSL_read(ssl, buf, sizeof(buf));/* get reply & decrypt */
			if (bytes == 0)
			{
				break;
			}
			strncpy(rec, buf, 5);
			if (strcmp(rec, "<ct/>") != 0)
			{
				now = time(NULL);
				ptm = localtime(&now);
				if (bytes < sizeof(buf))
				{
					sprintf(receive, "%s\n<sendtime:%d-%d %d:%d:%d>\n\n", buf, (ptm->tm_mon + 1), ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
				}
				else
				{
					sprintf(receive, "%s", buf);
				}
				fwrite(receive, strlen(receive), 1, fd);
				fflush(fd);

				bzero(receive, sizeof(receive));
			}
			bzero(&buf, sizeof(buf));
		}

		fclose(fd);
		SSL_free(ssl);       /* release connection state */
	}

	close(server);        /* close socket */
	SSL_CTX_free(ctx);       /* release context */
	return 0;
}
