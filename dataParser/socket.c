#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define PORT_META   1234
#define PORT_DATA   1235

#define BUFLEN  512

int main(int argc, char *argv) {
    int sock_meta;
    int port = PORT_DATA;
    struct hostent *server;
    char buf[BUFLEN + 1] = "AAAAAAA";
    int ret;
    struct sockaddr_in sin_meta;

    sock_meta = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_meta < 0) {
        perror("Opening socket failed: ");
        return sock_meta;
    }

    memset(&sin_meta, 0, sizeof(sin_meta));
    sin_meta.sin_family = AF_INET;
    sin_meta.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin_meta.sin_port = htons(PORT_META);

    ret = connect(sock_meta, (struct sockaddr*)&sin_meta, sizeof(sin_meta));
    if (ret != 0) {
        perror("Connecting to socket failed: ");
        return ret;
    }
    ret = write(sock_meta, buf, strlen(buf));
    if (ret < 0) {
        perror("Failed sending data: ");
        return ret;
    }

    return 0;
}
