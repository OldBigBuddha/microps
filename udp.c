#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

/* see https://tools.ietf.org/html/rfc6335 */
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

struct udp_pcb
{
    int state;
    struct ip_endpoint local;
    struct queue_head queue; /* receive queue */
    int wc;                  /* wait count */
};

struct udp_queue_entry
{
    struct ip_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif

    funlockfile(stderr);
}

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static struct udp_pcb *
udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_FREE)
        {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
    }

    return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    if (pcb->wc)
    {
        pcb->state = UDP_PCB_STATE_CLOSING;
        return;
    }

    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;

    while (1)
    {
        /* Discard the entries in the queue */
        entry = queue_pop(&pcb->queue);
        if (!entry)
        {
            break;
        }

        memory_free(entry);
    }
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_OPEN)
        {
            if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port)
            {
                return pcb;
            }
        }
    }

    return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs))
    {
        /* out of range*/
        return NULL;
    }

    pcb = &pcbs[id];
    if (pcbs->state != UDP_PCB_STATE_OPEN)
    {
        return NULL;
    }

    return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }

    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len))
    {
        /* just to make sure*/
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }

    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    udp_dump(data, len);

    mutex_lock(&mutex);

    pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb)
    {
        /* port is not in use */
        mutex_unlock(&mutex);
        return;
    }

    // Exercise 19-1: 受信キューへデータを格納
    // (1) 受信キューのエントリのメモリを確保
    // (2) エントリの各項目に値を設定し、データをコピー
    // (3) PCBの受信キューにエントリをプッシュ
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return;
    }

    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len;
    memcpy(entry->data, data, len);

    queue_push(&pcb->queue, entry);

    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
    mutex_unlock(&mutex);
}

ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr))
    {
        errorf("too long");
        return -1;
    }
    hdr = (struct udp_hdr *)buf;

    // Exercise 18-1: UDPデータグラムの生成
    // ・チェックサムの計算には疑似ヘッダを含めること
    hdr->src = src->port;
    hdr->dst = dst->port;
    total = len + sizeof(*hdr);
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);

    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);

    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);

    // Exercise 18-2: IPの送信関数を呼び出す
    if (ip_output(IP_PROTOCOL_UDP, buf, total, src->addr, dst->addr) == -1)
    {
        errorf("ip_output() failure");
        return -1;
    }

    return len;
}

int udp_init(void)
{
    // Exercise 18-3: IPの上位プロトコルとしてUDPを登録する
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}

/*
 * UDP User Commands
 */

int udp_open(void)
{
    struct udp_pcb *pcb;
    // Exercise 19-2: UDPソケットのオープン
    // ・新しくPCBを割り当てる
    // 　・失敗したらエラー（-1）を返す
    // ・PCBのIDを取得して返す
    pcb = udp_pcb_alloc();
    if (!pcb)
    {
        errorf("memory_alloc() failure");
        return -1;
    }

    return udp_pcb_id(pcb);
}

int udp_close(int id)
{
    struct udp_pcb *pcb;

    // Exercise 19-3: UDPソケットのクローズ
    // ・IDからPCBのポインタを取得
    // 　・失敗したらエラー（-1）を返す
    // ・PCBを解放して 0 を返す
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("udp_pcb_id() failure");
        return -1;
    }

    udp_pcb_release(pcb);

    return 0;
}

int udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    // Exercise 19-4: UDPソケットへアドレスとポート番号を紐づけ
    // (1) IDからPCBのポインタを取得
    // 　・失敗したらエラー（-1）を返す
    // (2) 引数 local で指定されたIPアドレスとポート番号をキーにPCBを検索
    // 　・PCBが見つかったらエラーを返す（そのアドレスとポート番号の組み合わせは既に使用されている）※ mutexのアンロックを忘れずに
    // (3) pcb->local に local の値をコピー
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        mutex_unlock(&mutex);

        errorf("udp_pcb_id() failure");
        return -1;
    }

    exist = udp_pcb_select(local->addr, local->port);
    if (exist)
    {
        mutex_unlock(&mutex);

        errorf("udp_pcb_select() failure");
        return -1;
    }

    pcb->local.addr = local->addr;
    pcb->local.port = local->port;

    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);

    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("udp_pcb_get() failure");
        mutex_unlock(&mutex);
        return -1;
    }

    local.addr = pcb->local.addr;
    if (local.addr == IP_ADDR_ANY)
    {
        iface = ip_route_get_iface(foreign->addr);
        if (!iface)
        {
            errorf("iface not found that can reach foreign address, addr=%s",
                   ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->unicast;
        debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
    }

    if (!pcb->local.port)
    {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++)
        {
            if (!udp_pcb_select(local.addr, hton16(p)))
            {
                pcb->local.port = hton16(p);
                debugf("dynamic assign local port, port=%d", p);
                break;
            }
        }
        if (!pcb->local.port)
        {
            debugf("failed to dynamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
    }
    local.port = pcb->local.port;

    mutex_unlock(&mutex);
    return udp_output(&local, foreign, data, len);
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ssize_t len;

    mutex_lock(&mutex);

    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }

    // 受信キューからエントリを取り出す
    while (1)
    {
        entry = queue_pop(&pcb->queue);
        if (entry)
        {
            break;
        }

        pcb->wc++;
        mutex_unlock(&mutex);
        sleep(1);
        mutex_lock(&mutex);
        pcb->wc--;

        if (pcb->state == UDP_PCB_STATE_CLOSING)
        {
            debugf("closed");
            udp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }

    mutex_unlock(&mutex);
    if (foreign)
    {
        *foreign = entry->foreign;
    }

    len = MIN(size, entry->len); /* truncate */
    memcpy(buf, entry->data, len);
    memory_free(entry);

    return len;
}
