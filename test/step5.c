#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
    (void)s;
    terminate = 1;
}

int main(int argc, char *argv[])
{
    struct net_device *dev;

    signal(SIGINT, on_signal);

    int ret_net_init = net_init();
    if (ret_net_init == -1)
    {
        errorf("net_init() failure");
        return -1;
    }

    dev = loopback_init();
    if (!dev)
    {
        errorf("loopback_init() failure");
        return -1;
    }

    int ret_net_run = net_run();
    if (ret_net_run == -1)
    {
        errorf("net_run() failure");
        return -1;
    }

    while (!terminate)
    {
        int ret_net_device_output = net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL);
        if (ret_net_device_output == -1)
        {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }

    net_shutdown();
    return 0;
}