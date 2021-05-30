#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> // for sockaddr_in
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <pthread.h>
#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>


#define CERTF "client.crt"          /*客户端的证书(需经CA签名)*/
#define KEYF "client.pem"           /*客户端的私钥(建议加密存储)*/
#define CACERT "ca.crt"             /*CA 的证书*/
#define SERVERIP "xxx.xxx.xxx.xxx"

#define CHK_NULL(x)      if ((x) == NULL)  exit(-1)
#define CHK_ERR(err, s)  if ((err) == -1)  { perror(s);  exit(-2); }
#define CHK_SSL(err)     if ((err) == -1)  { ERR_print_errors_fp(stderr);exit(-3); }

pthread_mutex_t mutex;

//发送信息到0x123这一帧
void Send123(unsigned &count301, int &sd, can_frame &pframe, sockaddr_can &paddr); //50ms
//与车辆can总线通讯
void *mythread_can0read(void *);
//与云端通讯
void *mythread_cloud(void *);

int main()
{

    pthread_t id0, id1;
    int ret;

    ret = pthread_create(&id0, NULL, &mythread_can0read, NULL);
    if (ret != 0)
    {
        printf("Create pthread error.\n");
        exit(1);
    }
    ret = pthread_create(&id1, NULL, &mythread_cloud, NULL);
    if (ret != 0)
    {
        printf("Create pthread error.\n");
        exit(1);
    }

    while (1)
    {
        //主进程处理逻辑部分
        pthread_mutex_lock(&mutex);
        /*
        ...
        ...
        */
        pthread_mutex_unlock(&mutex);
        usleep(200000);
    }
    return 0;
}


void Send123(unsigned &count123, int &sd, can_frame &pframe, sockaddr_can &paddr) //50ms
{
    for(int i = 0 ; i < 8 ;i++ ){
        pframe.data[i] = 0x01;   
    }
    pframe.can_dlc = 8;
    sendto(sd, &pframe, sizeof(struct can_frame), 0, (struct sockaddr *)&paddr, sizeof(paddr));
    count123++;
}

void *mythread_can1read(void *)
{
    int ss;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame frame;
    struct can_filter rfilter[3];
    if ((ss = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0)
    {
        perror("Socket");
    }
    strcpy(ifr.ifr_name, "can1");
    ioctl(ss, SIOCGIFINDEX, &ifr);
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(ss, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Bind");
    }
    int xunhuan;
    while (1)
    {
        //读取并发送相关can帧报文
        rfilter[0].can_id = 0x666;
        rfilter[0].can_mask = 0xFFF;
        rfilter[1].can_id = 0x333;
        rfilter[1].can_mask = 0xFFF;
        rfilter[2].can_id = 0x555;
        rfilter[2].can_mask = 0xFFF;
        setsockopt(ss, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter));
        read(ss, &frame, sizeof(struct can_frame));
        pthread_mutex_lock(&mutex);
        if (frame.can_id == 0x666)
        {
            //。。。
        }
        //第7个 0x155
        else if (frame.can_id == 0x555)
        {
            //。。。
        }
        else if (frame.can_id == 0x333)
        {
            //。。。
        }
        pthread_mutex_unlock(&mutex);
        Send123(count123, sd, pframe, paddr); 
        usleep(20000);
    }
    close(ss);
}

void *mythread_cloud(void *)
{
    int err;
    int tsd;
    int ret;
    struct sockaddr_in sa;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *server_cert;
    char *str;
    int ss;

    fd_set readfds, tempfds;
    struct timeval select_timeval;
    // struct sockaddr_can addr;
    struct ifreq ifr;
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();                   /*初始化*/
    SSL_load_error_strings();                       /*为打印调试信息作准备*/
    const SSL_METHOD *meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);
    printf("%d\n", __LINE__);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /*验证与否*/
    printf("%d\n", __LINE__);
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL); /*若验证,则放置CA证书*/
    printf("%d\n", __LINE__);
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }
    printf("%d\n", __LINE__);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, KEY_PASSWD);
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        printf("%d\n", __LINE__);
        ERR_print_errors_fp(stderr);
        exit(-3);
    }
    printf("%d\n", __LINE__);
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the certificate public key\n");
        exit(-4);
    }
    /*以下是正常的TCP socket建立过程 .............................. */
    printf("Begin tcp socket...\n");
    tsd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(tsd, "socket");
    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SERVERIP); /* Server IP */
    sa.sin_port = htons(50002);                      /* Server Port number */
    printf("port is %d\n", 50002);
    printf("server is %s\n", SERVERIP);
    err = connect(tsd, (struct sockaddr *)&sa, sizeof(sa));
    printf("err is %d\n", err);
    CHK_ERR(err, "connect");
    /* TCP 链接已建立.开始 SSL 握手过程.......................... */
    printf("Begin SSL negotiation \n");
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    SSL_set_fd(ssl, tsd);
    err = SSL_connect(ssl);
    CHK_SSL(err);
    /*打印所有加密算法的信息(可选)*/
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
    /*得到服务端的证书并打印些信息(可选) */
    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate:\n");
    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    free(str);
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    free(str);
    X509_free(server_cert); /*如不再需要,需将证书释放 */
    printf("Begin SSL data exchange\n");

    while (1)
    {
        //ssl read & write
        //...
    }
    SSL_shutdown(ssl);
    shutdown(tsd, 2);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
