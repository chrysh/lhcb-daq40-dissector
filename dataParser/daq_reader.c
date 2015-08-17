#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/* FIXME: What is the real meta device number? */
#define META_DEV    0
#define DATA_DEV    0
#define BASIC_BSIZE 64  /* Basic size of data is 64 byte */

/* Prototypes for PCIe40 driver */
extern int p40_ctl_open(int dev);
extern void p40_ctl_close(int fd);

extern int p40_ctl_start(int fd);
extern int p40_ctl_stop(int fd);

extern int  p40_daq_open(int dev, void **buffer);
extern void p40_daq_close(int fd, void *buffer);


extern int      p40_daq_set_read_off(int fd, uint32_t off);
extern uint32_t p40_daq_get_read_off(int fd);
extern uint32_t p40_daq_get_write_off(int fd);
extern uint64_t p40_daq_get_buf_size(int fd);

static char *databuf = NULL;

int dataParser_init()
{
    int fd_meta = p40_ctl_open(META_DEV);
    if (fd_meta < 0) {
        perror("p40_ctl_open");
        return fd_meta;
    }

    /* p40_daq_open will store the pointer to the data in databuf */
    int fd_data = p40_daq_open(DATA_DEV, (void **)&databuf);
    if (fd_data < 0) {
        perror("p40_daq_open");
        return fd_data;
    }

    p40_ctl_start(META_DEV);
    p40_ctl_start(DATA_DEV);
    return 0;
}

void dataParser_exit()
{
    int ret = 0;

    p40_daq_close(DATA_DEV, databuf);

    ret = p40_ctl_stop(META_DEV);
    if (ret < 0) {
        /* FIXME: print error */
        return;
    }
    p40_ctl_close(META_DEV);
}

/* Reading data and sending it to wireshark should be one function,
 * with no need to pass buffer pointers between each other */
int read_send_data()
{
    uint32_t roff = p40_daq_get_read_off(DATA_DEV);
    /* TODO: Read metadata, send it to wireshark */

    /* FIXME: Who updates the read offset? */
    /* Data can be read from databuf+off now */

    /* Send data to wireshark*/
    send_data_wireshark(databuf+roff, BASIC_BSIZE);
}

int check_for_data()
{
    fd_set meta_set;
    struct timeval timeout;

    /* FIXME: How much timeout time makes sense? */
    timeout.tv_sec = 15;
    timeout.tv_usec = 0;

    FD_ZERO (&meta_set);
    FD_SET (META_DEV, &meta_set);

    /* FIXME: Do we have to wait for both, the metadata and data dev? */
    /* On success, ret contains number of file descr, that fired */
    int ret = select( FD_SETSIZE, &meta_set, NULL, NULL, &timeout);

    printf("ret: %d\n", ret);
    if (ret == 0) {
        printf("Timeout triggered\n");
    } else if (ret < 0) {
        perror("Error on META_DEV I/O");
    }else if (FD_ISSET(DATA_DEV, &meta_set)) {
        read_send_data();
    } else {
        printf("Something went terribly wrong (more than one fd triggered?)\n");
    }
    return ret;
}
