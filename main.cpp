#include <iostream>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

using namespace std;

// linked list node
template <typename T>
class node {
public:
    T data;
    node* next;
    node(T val) {
        data = val;
        next = nullptr;
    }
};

// simple queue class
template <typename T>
class simple_queue {
private:
    node<T>* front;
    node<T>* back;
    int count;

public:
    simple_queue() {
        front = nullptr;
        back = nullptr;
        count = 0;
    }

    ~simple_queue() {
        while (!empty()) dequeue();
    }

    void enqueue(T value) {
        node<T>* n = new node<T>(value);
        if (!back) {
            front = back = n;
        } else {
            back->next = n;
            back = n;
        }
        count++;
    }

    T dequeue() {
        if (empty()) throw runtime_error("queue is empty");
        node<T>* temp = front;
        T val = front->data;
        front = front->next;
        if (!front) back = nullptr;
        delete temp;
        count--;
        return val;
    }

    bool empty() {
        return front == nullptr;
    }

    int size() {
        return count;
    }

    node<T>* first() {
        return front;
    }
};

// simple stack class
template <typename T>
class simple_stack {
private:
    node<T>* topNode;
    int count;

public:
    simple_stack() {
        topNode = nullptr;
        count = 0;
    }

    ~simple_stack() {
        while (!empty()) pop();
    }

    void push(T value) {
        node<T>* n = new node<T>(value);
        n->next = topNode;
        topNode = n;
        count++;
    }

    T pop() {
        if (empty()) throw runtime_error("stack is empty");
        node<T>* temp = topNode;
        T val = topNode->data;
        topNode = topNode->next;
        delete temp;
        count--;
        return val;
    }

    bool empty() {
        return topNode == nullptr;
    }
};

// structure to hold packet data
struct packet {
    int id;
    time_t timestamp;
    unsigned char* raw;
    int length;
    string src;
    string dst;
    int retries;

    packet() {
        id = 0;
        timestamp = 0;
        raw = nullptr;
        length = 0;
        retries = 0;
    }

    packet(int pid, unsigned char* data, int len) {
        id = pid;
        timestamp = time(nullptr);
        length = len;
        raw = new unsigned char[len];
        memcpy(raw, data, len);
        retries = 0;
    }

    packet(const packet& other) {
        id = other.id;
        timestamp = other.timestamp;
        length = other.length;
        src = other.src;
        dst = other.dst;
        retries = other.retries;
        if (other.raw) {
            raw = new unsigned char[length];
            memcpy(raw, other.raw, length);
        } else raw = nullptr;
    }
};

// structure to store protocol layer info
struct layer_info {
    string name;
    string detail;
    layer_info(string n = "", string d = "") {
        name = n;
        detail = d;
    }
};

// global queues
simple_queue<packet> main_queue;
simple_queue<packet> filtered_queue;
simple_queue<packet> retry_queue;
int total_packets = 0;

// open raw socket on a given interface
int open_socket(const char* iface) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        perror("socket creation failed");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("invalid interface");
        close(s);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(s, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind failed");
        close(s);
        return -1;
    }

    cout << "socket opened successfully on " << iface << endl;
    return s;
}

// capture packets for a given duration
void capture_packets(int sockfd, int seconds) {
    unsigned char buffer[65536];
    time_t start = time(nullptr);
    cout << "\nstarting capture for " << seconds << " seconds...\n";

    while (time(nullptr) - start < seconds) {
        int len = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len < 0) continue;

        packet p(++total_packets, buffer, len);

        struct ethhdr* eth = (struct ethhdr*)buffer;
        unsigned short type = ntohs(eth->h_proto);

        if (type == ETH_P_IP) {
            struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            struct in_addr s, d;
            s.s_addr = iph->saddr;
            d.s_addr = iph->daddr;
            p.src = inet_ntoa(s);
            p.dst = inet_ntoa(d);
        } else if (type == ETH_P_IPV6) {
            struct ip6_hdr* ip6 = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
            inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
            p.src = src;
            p.dst = dst;
        }

        main_queue.enqueue(p);

        if (total_packets % 10 == 0)
            cout << "captured " << total_packets << " packets...\n";
    }

    cout << "\ncapture complete! total packets: " << total_packets << endl;
}

// analyze packet layers
void parse_layers(packet& p, simple_stack<layer_info>& layers) {
    unsigned char* data = p.raw;
    int len = p.length;

    if (len < (int)sizeof(struct ethhdr)) return;

    struct ethhdr* eth = (struct ethhdr*)data;
    char details[256];
    snprintf(details, sizeof(details),
             "src mac: %02x:%02x:%02x:%02x:%02x:%02x, dst mac: %02x:%02x:%02x:%02x:%02x:%02x, type: 0x%04x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
             eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
             ntohs(eth->h_proto));
    layers.push(layer_info("ethernet", details));

    unsigned short proto = ntohs(eth->h_proto);
    data += sizeof(struct ethhdr);
    len -= sizeof(struct ethhdr);

    if (proto == ETH_P_IP && len >= (int)sizeof(struct iphdr)) {
        struct iphdr* iph = (struct iphdr*)data;
        struct in_addr s, d;
        s.s_addr = iph->saddr;
        d.s_addr = iph->daddr;
        char info[256];
        snprintf(info, sizeof(info), "src ip: %s, dst ip: %s, ttl: %d, protocol: %d",
                 inet_ntoa(s), inet_ntoa(d), iph->ttl, iph->protocol);
        layers.push(layer_info("ipv4", info));

        data += iph->ihl * 4;
        len -= iph->ihl * 4;

        if (iph->protocol == IPPROTO_TCP && len >= (int)sizeof(struct tcphdr)) {
            struct tcphdr* t = (struct tcphdr*)data;
            char tcp_info[256];
            snprintf(tcp_info, sizeof(tcp_info),
                     "src port: %d, dst port: %d, seq: %u, ack: %u",
                     ntohs(t->source), ntohs(t->dest), ntohl(t->seq), ntohl(t->ack_seq));
            layers.push(layer_info("tcp", tcp_info));
        } else if (iph->protocol == IPPROTO_UDP && len >= (int)sizeof(struct udphdr)) {
            struct udphdr* u = (struct udphdr*)data;
            char udp_info[128];
            snprintf(udp_info, sizeof(udp_info),
                     "src port: %d, dst port: %d, length: %d",
                     ntohs(u->source), ntohs(u->dest), ntohs(u->len));
            layers.push(layer_info("udp", udp_info));
        }
    }
}

// filter packets by source or destination ip
void filter_packets(const string& src_ip, const string& dst_ip) {
    cout << "\nfiltering packets..." << endl;
    node<packet>* cur = main_queue.first();
    int count = 0;

    while (cur) {
        packet& p = cur->data;
        bool match_src = src_ip.empty() || p.src == src_ip;
        bool match_dst = dst_ip.empty() || p.dst == dst_ip;
        if (match_src && match_dst) {
            filtered_queue.enqueue(p);
            count++;
        }
        cur = cur->next;
    }

    cout << "matched " << count << " packets" << endl;
}

// resend packets
void replay_packets(int sockfd) {
    cout << "\nreplaying packets..." << endl;
    int success = 0, fail = 0;

    while (!filtered_queue.empty()) {
        packet p = filtered_queue.dequeue();
        int delay = p.length / 1000;
        if (delay > 0) usleep(delay * 1000);

        ssize_t sent = send(sockfd, p.raw, p.length, 0);
        if (sent < 0) {
            p.retries++;
            if (p.retries <= 2)
                retry_queue.enqueue(p);
            else
                fail++;
        } else success++;
    }

    cout << "retrying failed packets..." << endl;

    while (!retry_queue.empty()) {
        packet p = retry_queue.dequeue();
        if (send(sockfd, p.raw, p.length, 0) >= 0)
            success++;
        else
            fail++;
    }

    cout << "replay finished: " << success << " success, " << fail << " failed" << endl;
}

// display a list of captured packets
void show_packets() {
    cout << "\ncaptured packets:\n";
    cout << "id  time                    src ip           dst ip           size\n";

    node<packet>* cur = main_queue.first();
    int shown = 0;
    while (cur && shown < 20) {
        packet& p = cur->data;
        char t[26];
        ctime_r(&p.timestamp, t);
        t[24] = '\0';
        printf("%d  %s  %s  %s  %d\n",
               p.id, t, p.src.c_str(), p.dst.c_str(), p.length);
        cur = cur->next;
        shown++;
    }
    if (main_queue.size() > 20)
        cout << "... (" << main_queue.size() - 20 << " more)\n";
}

// show dissected layers for a packet
void show_layers(int id) {
    node<packet>* cur = main_queue.first();
    while (cur) {
        if (cur->data.id == id) {
            simple_stack<layer_info> s;
            parse_layers(cur->data, s);
            int i = 1;
            while (!s.empty()) {
                layer_info l = s.pop();
                cout << "layer " << i++ << ": " << l.name << " -> " << l.detail << endl;
            }
            return;
        }
        cur = cur->next;
    }
    cout << "packet not found" << endl;
}

int main() {
    cout << "\nnetwork packet analyzer\n";

    const char* iface = "lo";
    int sockfd = open_socket(iface);
    if (sockfd < 0) {
        cout << "error: could not open socket (try running with sudo)\n";
        return 1;
    }

    capture_packets(sockfd, 60);

    cout << "\nparsing a few packets...\n";
    for (int i = 1; i <= min(5, total_packets); i++)
        show_layers(i);

    show_packets();
    filter_packets("", "");
    replay_packets(sockfd);

    cout << "\nsummary:\n";
    cout << "total packets: " << total_packets << endl;
    cout << "in main queue: " << main_queue.size() << endl;
    cout << "in filtered queue: " << filtered_queue.size() << endl;
    cout << "in retry queue: " << retry_queue.size() << endl;

    close(sockfd);
    cout << "\nprogram finished.\n";
    return 0;
}
