#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PATHNAME    "/tmp/metapipe"

/** Before runing this program, the fifo should already have been created! */
int main()
{
    int ret = 0;
    char *fifopath = PATHNAME;
    int fd = 0;
    char *pkt = "AAAAAA";

    fd = open(fifopath, O_WRONLY);
    write(fd, pkt, sizeof(pkt));
    close(fd);
    return 0;
}
