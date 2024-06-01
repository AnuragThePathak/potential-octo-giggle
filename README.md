# Answers

### Problem statement 1: Drop packets using eBPF

**Solution:**

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define TARGET_PORT 4040

SEC("filter")
int drop_tcp(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, ETH_HLEN);
    if (eth->h_proto != htons(ETH_P_IP)) {
        return BPF_OK;
    }

    struct iphdr *ip = bpf_hdr_pointer(skb, ETH_HLEN + sizeof(*eth));
    if (ip->protocol != IPPROTO_TCP) {
        return BPF_OK;
    }

    struct tcphdr *tcp = bpf_hdr_pointer(skb, ETH_HLEN + sizeof(*eth) + sizeof(*ip));
    int port = ntohs(tcp->dest);
    if (port == TARGET_PORT) {
        return BPF_DROP;
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
```

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
 

