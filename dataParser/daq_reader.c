#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DAQ_DEV    "/dev/random"
#define BASIC_BSIZE 64  /* Basic size of data is 64 byte */

/* Prototypes for PCIe40 driver */
/** Metadata functions */
extern int p40_ctl_open(int dev);
extern void p40_ctl_close(int fd);
extern int p40_ctl_start(int fd);
extern int p40_ctl_stop(int fd);

/** DAQ data functions */
extern int  p40_daq_open(int dev, void **buffer);
extern void p40_daq_close(int fd, void *buffer);
extern int      p40_daq_set_read_off(int fd, uint32_t off);
extern uint32_t p40_daq_get_read_off(int fd);
extern uint32_t p40_daq_get_write_off(int fd);
extern uint64_t p40_daq_get_buf_size(int fd);

extern int send_data_wireshark(void *waddr, uint32_t size);
static int fd;

static uint32_t *databuf = NULL;

int dataParser_init()
{
    fd = open(DAQ_DEV, O_RDONLY);
    int ret = p40_ctl_open(fd);
    if (ret < 0) {
        perror("p40_ctl_open");
        return ret;
    }

    /* p40_daq_open will store the pointer to the data in databuf */
    ret = p40_daq_open(fd, (void **)&databuf);
    if (ret < 0) {
        perror("p40_daq_open");
        return ret;
    }

    p40_ctl_start(fd);
    return 0;
}

void dataParser_exit()
{
    int ret = 0;

    p40_daq_close(fd, databuf);

    ret = p40_ctl_stop(fd);
    if (ret < 0) {
        /* FIXME: print error */
        return;
    }
    p40_ctl_close(fd);
}

/* Reading data and sending it to wireshark should be one function,
 * with no need to pass buffer pointers between each other */
int read_send_data(int fd)
{
    uint32_t roff = p40_daq_get_read_off(fd);
    uint32_t woff = p40_daq_get_write_off(fd);
    /* Data can be read from databuf+roff now */

    int ret = send_data_wireshark((void *)databuf+roff, roff-woff);
    if (ret != 0) {
        printf("Error sending data to wireshark\n");
        return ret;
    }
    p40_daq_set_read_off(fd, roff);
}

int check_for_data()
{
    fd_set daq_fd_set;
    struct timeval timeout;

    /* FIXME: How much timeout time makes sense? */
    timeout.tv_sec = 15;
    timeout.tv_usec = 0;

    FD_ZERO (&daq_fd_set);
    FD_SET (fd, &daq_fd_set);

    /* On success, ret contains number of file descr, that fired */
    int ret = select( FD_SETSIZE, &daq_fd_set, NULL, NULL, &timeout);

    printf("ret: %d\n", ret);
    if (ret == 0) {
        printf("Timeout triggered\n");
    } else if (ret < 0) {
        perror("Error on DAQ_DEV I/O");
    }else if (FD_ISSET(fd, &daq_fd_set)) {
        read_send_data(fd);
    } else {
        printf("Something went terribly wrong (more than one fd triggered?)\n");
    }
    return ret;
}