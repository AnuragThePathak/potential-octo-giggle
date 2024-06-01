# Answers

### Problem statement 1: Drop packets using eBPF

**Solution:**

**filter.c**: eBPF program

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Define a map to store the configurable port
struct bpf_map_def SEC("maps") drop_port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

SEC("tc")
int drop_tcp_packets(struct __sk_buff *skb) {
    // Load the data from the packet
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Get the port to drop from the map
    int key = 0;
    int *port = bpf_map_lookup_elem(&drop_port_map, &key);
    if (!port)
        return TC_ACT_OK;

    // Drop the packet if the destination port matches
    if (tcp->dest == htons(*port)) {
        return TC_ACT_SHOT; // Drop the packet
    }

    return TC_ACT_OK; // Pass the packet
}

char _license[] SEC("license") = "GPL";
```

**port.c**: User-space program to set the port

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DROP_PORT_MAP "/sys/fs/bpf/tc/globals/drop_port_map"

void set_drop_port(int port) {
    int key = 0;
    int map_fd = bpf_obj_get(DROP_PORT_MAP);
    if (map_fd < 0) {
        fprintf(stderr, "Error opening map: %s\n", strerror(errno));
        return;
    }

    if (bpf_map_update_elem(map_fd, &key, &port, BPF_ANY) < 0) {
        fprintf(stderr, "Error updating map: %s\n", strerror(errno));
    }

    close(map_fd);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    set_drop_port(port);

    printf("Set drop port to %d\n", port);
    return 0;
}
```

**Compile the eBPF program:**

```
clang -O2 -target bpf -c filter.c -o filter.o
```

**Compile and run the user space program:**

```
gcc -o port port.c -lbpf
./port 4040
```

**Load the eBPF program using tc:**

```
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf da obj filter.o sec tc
```

**Pin the map**

```
mkdir -p /sys/fs/bpf/tc/globals
bpftool map pin id <map_id> /sys/fs/bpf/tc/globals/drop_port_map
```

<map_id> is the ID of the map, which can be found using `bpftool map show`.

### Problem statement 3: Explain the code snippet

**Solution:**
 
 1. The highlighted contructs work uses channel and go routine. Flow of code can be described as -
    1. A channel cnp of buffer 10 is created.
    2. Then we have a for loop that has four iterations.
    3. Each iteration starts a new goroutine.
    4. Each goroutine reads the cnp channel that we have created earlier. However, the channel will be empty due to lack of input and the goroutines will wait for something to enter the channel.
    5. After spawning the 4th goroutine, the loop will complete and we move to next step which is sending a function to the channel.
    6. After that only, scheduler will let one of the waiting go rotuines to read the channel and it'll execute the function and complete. Ideally the others will wait until they get something to read.
    7. However, once the line on the main function printing "Hello" is executed, all the goroutines will have exit.
 2. These type of contructs can be used for various cases, that demand working asynchronously. It is often required when we process a time-consuming task for example fetching a database or calling an external API.
 3. The significance of the for loop with 4 iterations is that it spawns 4 goroutines that reads the channel.
 4. The signficance of `make (chan func(), 10)` is that it creates a channel with a buffer of 10. The channels are required to send data from one goroutine to another one.
 5. "HERE1" is not getting printed because after sending the function containing "HERE1" to the channel, the main function prints and exits, before goroutines actually can have time to read and then execute the function from the channel.
 

