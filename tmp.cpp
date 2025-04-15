/*
 * 程序名：tmp.cpp    此程序用于演示采用epoll模型实现网络通讯的服务端。
*/
#include "net.h"
// 1、设置2和15的信号。
// 2、在信号处理函数中停止主从事件循环和工作线程。
// 3、服务程序主动退出。

EchoServer *echoserver;

void Stop(int sig)    // 信号2和15的处理函数，功能是停止服务程序。
{
    printf("sig=%d\n",sig);
    // 调用EchoServer::Stop()停止服务。
    echoserver->Stop();
    printf("echoserver已停止。\n");
    delete echoserver;
    printf("delete echoserver。\n");
    exit(0); 
}

void handleTrap(int sig) {
printf("we received signal sigtrap.\n");
}

int main(int argc,char *argv[])
{
    signal(SIGTERM,Stop);    // 信号15，系统kill或killall命令默认发送的信号。
    signal(SIGINT,Stop);        // 信号2，按Ctrl+C发送的信号。
    signal(SIGTRAP,handleTrap);        // 信号2，按Ctrl+C发送的信号。

    echoserver=new EchoServer("10.0.4.8",64000,3,2);
    echoserver->Start();

    return 0;
}

