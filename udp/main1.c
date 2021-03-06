#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>

struct socket *sock;

unsigned char buffer[10]=
{ 1,2,3,4,5,6,7,8,9,0,
};

static int ker_send_udp(char* ip_addr, unsigned char * data, size_t len )
{
int ret;

u32 remote_ip = ntohl(in_aton(ip_addr));

struct sockaddr_in sin = {
.sin_family = AF_INET,
.sin_port = htons(65530),
.sin_addr = {.s_addr = remote_ip}
};

struct kvec iov = {.iov_base = (void *)data, .iov_len = len};
struct msghdr udpmsg;

udpmsg.msg_name = (void *)&sin;
udpmsg.msg_namelen = sizeof(sin);
udpmsg.msg_control = NULL;
udpmsg.msg_controllen = 0;
udpmsg.msg_flags=0;

ret = kernel_sendmsg(sock, &udpmsg, &iov, 1, len);
printk("rets = %d\n",ret);

return 0;
}

static int socket_init (void)
{
int ret;
ret = sock_create_kern (PF_INET, SOCK_DGRAM,IPPROTO_UDP, &sock);
printk("retc = %d\n",ret);

ker_send_udp("192.168.1.100", buffer, 10);
return 0;
}

static void socket_exit (void)
{
sock_release (sock);
}

module_init (socket_init);
module_exit (socket_exit);
MODULE_LICENSE ("GPL");
