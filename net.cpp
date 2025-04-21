#include "net.h"
#include <sys/syscall.h>
#include <unistd.h>

///////////////////////////////////////////////////////////
////TimeStamp
Timestamp::Timestamp()
{
    secsinceepoch_=time(0);          // 取系统当前时间。
}

Timestamp::Timestamp(int64_t secsinceepoch): secsinceepoch_(secsinceepoch) 
{

}

// 当前时间。
Timestamp Timestamp::now() 
{ 
    return Timestamp();   // 返回当前时间。
}

time_t Timestamp::toint() const
{
    return secsinceepoch_;
}

std::string Timestamp::tostring() const
{
    char buf[32] = {0};
    tm *tm_time = localtime(&secsinceepoch_);
    snprintf(buf, 20, "%4d-%02d-%02d %02d:%02d:%02d",
             tm_time->tm_year + 1900,
             tm_time->tm_mon + 1,
             tm_time->tm_mday,
             tm_time->tm_hour,
             tm_time->tm_min,
             tm_time->tm_sec);
    return buf;
}

////////////////////////////////////////////////////////////
////ThreadPool

ThreadPool::ThreadPool(size_t threadnum,const std::string& threadtype):stop_(false),threadtype_(threadtype)
{
    // 启动threadnum个线程，每个线程将阻塞在条件变量上。
	for (size_t ii = 0; ii < threadnum; ii++)
    {
        // 用lambda函创建线程。
		threads_.emplace_back([this]
        {
            printf("create %s thread(%d).\n",threadtype_.c_str(),syscall(SYS_gettid));     // 显示线程类型和线程ID。

			while (stop_==false)
			{
				std::function<void()> task;       // 用于存放出队的元素。

				{   // 锁作用域的开始。 ///////////////////////////////////
					std::unique_lock<std::mutex> lock(this->mutex_);

					// 等待生产者的条件变量。
					this->condition_.wait(lock, [this] 
                    { 
                        return ((this->stop_==true) || (this->taskqueue_.empty()==false));
                    });

                    // 在线程池停止之前，如果队列中还有任务，执行完再退出。
					if ((this->stop_==true)&&(this->taskqueue_.empty()==true)) return;

                    // 出队一个任务。
					task = std::move(this->taskqueue_.front());
					this->taskqueue_.pop();
				}   // 锁作用域的结束。 ///////////////////////////////////

                // printf("%s(%d) execute task.\n",threadtype_.c_str(),syscall(SYS_gettid));
				task();  // 执行任务。
			}
		});
    }
}

void ThreadPool::addtask(std::function<void()> task)
{
    {   // 锁作用域的开始。 ///////////////////////////////////
        std::lock_guard<std::mutex> lock(mutex_);
        taskqueue_.push(task);
    }   // 锁作用域的结束。 ///////////////////////////////////

    condition_.notify_one();   // 唤醒一个线程。
}

// 停止线程。
void ThreadPool::stop()
{
    if (stop_) return;

    stop_ = true;

	condition_.notify_all();  // 唤醒全部的线程。

    // 等待全部线程执行完任务后退出。
	for (std::thread &th : threads_) 
        th.join();
}

ThreadPool::~ThreadPool()
{
    stop();
}

// 获取线程池的大小。
size_t ThreadPool::size()
{
    return threads_.size();
}


///////////////////////////////////////////////////////
////InetAddress 
InetAddress::InetAddress()
{

}
InetAddress::InetAddress(const std::string &ip,uint16_t port)      // 如果是监听的fd，用这个构造函数。
{
    addr_.sin_family = AF_INET;                                 // IPv4网络协议的套接字类型。
    addr_.sin_addr.s_addr = inet_addr(ip.c_str());      // 服务端用于监听的ip地址。
    addr_.sin_port = htons(port);                              // 服务端用于监听的端口。
}

InetAddress::InetAddress(const sockaddr_in addr):addr_(addr)  // 如果是客户端连上来的fd，用这个构造函数。
{

}

InetAddress::~InetAddress()
{

}

const char *InetAddress::ip() const                // 返回字符串表示的地址，例如：192.168.150.128
{
    return inet_ntoa(addr_.sin_addr);
}

uint16_t InetAddress::port() const                // 返回整数表示的端口，例如：80、8080
{
    return ntohs(addr_.sin_port);
}

const sockaddr *InetAddress::addr() const   // 返回addr_成员的地址，转换成了sockaddr。
{
    return (sockaddr*)&addr_;
}

void InetAddress::setaddr(sockaddr_in clientaddr)   // 设置addr_成员的值。
{
    addr_=clientaddr;
}

//////////////////////////////////////////////////////
////Socket

int createnonblocking()
{
    // 创建服务端用于监听的listenfd。
    int listenfd = socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,IPPROTO_TCP);
    if (listenfd < 0)
    {
        // perror("socket() failed"); exit(-1);
        printf("%s:%s:%d listen socket create error:%d\n", __FILE__, __FUNCTION__, __LINE__, errno); exit(-1);
    }
    return listenfd;
}

 // 构造函数，传入一个已准备好的fd。
Socket::Socket(int fd):fd_(fd)            
{

}

// 在析构函数中，将关闭fd_。
Socket::~Socket()
{
    ::close(fd_);
}

int Socket::fd() const                              // 返回fd_成员。
{
    return fd_;
}

std::string Socket::ip() const                   // 返回ip_成员。
{
    return ip_;
}
uint16_t Socket::port() const                  // 返回port_成员。
{
    return port_;
}

void Socket::setipport(std::string ip,uint16_t port)
{
    ip_ = ip; port_ = port;
}

void Socket::settcpnodelay(bool on)
{
    int optval = on ? 1 : 0;
    ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)); // TCP_NODELAY包含头文件 <netinet/tcp.h>
}

void Socket::setreuseaddr(bool on)
{
    int optval = on ? 1 : 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)); 
}

void Socket::setreuseport(bool on)
{
    int optval = on ? 1 : 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)); 
}

void Socket::setkeepalive(bool on)
{
    int optval = on ? 1 : 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)); 
}

void Socket::bind(const InetAddress& servaddr)
{
    setipport(servaddr.ip(),servaddr.port());
    if (::bind(fd_,servaddr.addr(),sizeof(sockaddr)) < 0 )
    {
        perror("bind() failed"); close(fd_); exit(-1);
    }
}

void Socket::listen(int nn)
{
    if (::listen(fd_,nn) != 0 )        // 在高并发的网络服务器中，第二个参数要大一些。
    {
        perror("listen() failed"); close(fd_); exit(-1);
    }
}

int Socket::accept(InetAddress& clientaddr)
{
    sockaddr_in peeraddr;
    socklen_t len = sizeof(peeraddr);
    int clientfd = accept4(fd_,(sockaddr*)&peeraddr,&len,SOCK_NONBLOCK);

    clientaddr.setaddr(peeraddr);             // 客户端的地址和协议。

    return clientfd;    
}

////////////////////////////////////////////////////
////Epoll

Epoll::Epoll()
{
    if ((epollfd_=epoll_create(1))==-1)       // 创建epoll句柄（红黑树）。
    {
        printf("epoll_create() failed(%d).\n",errno); exit(-1);
    }
}

Epoll::~Epoll()                                          
{
    close(epollfd_);           // 在析构函数中关闭epollfd_。
}

// 把channel添加/更新到红黑树上，channel中有fd，也有需要监视的事件。
void Epoll::updatechannel(Channel *ch)
{
    epoll_event ev;                 // 声明事件的数据结构。
    ev.data.ptr=ch;                 // 指定channel。
    ev.events=ch->events();  // 指定事件。

    if (ch->inpoll())         // 如果channel已经在树上了。
    {
        if (epoll_ctl(epollfd_,EPOLL_CTL_MOD,ch->fd(),&ev)==-1)
        {
            perror("epoll_ctl() failed.\n"); exit(-1);
        }
    }
    else                           // 如果channel不在树上。
    {
        if (epoll_ctl(epollfd_,EPOLL_CTL_ADD,ch->fd(),&ev)==-1)
        {
            perror("epoll_ctl() failed.\n"); exit(-1);
        }
        ch->setinepoll();   // 把channel的inepoll_成员设置为true。
    }
}

 // 从红黑树上删除channel。
 void Epoll::removechannel(Channel *ch)                        
 {
     if (ch->inpoll())         // 如果channel已经在树上了。
    {
        printf("removechannel()\n");

        if (epoll_ctl(epollfd_,EPOLL_CTL_DEL,ch->fd(),0)==-1)
        {
            perror("epoll_ctl() failed.\n"); exit(-1);
        }
    }
 }

// 运行epoll_wait()，等待事件的发生，已发生的事件用vector容器返回。
std::vector<Channel *> Epoll::loop(int timeout)   
{
    std::vector<Channel *> channels;        // 存放epoll_wait()返回的事件。

    bzero(events_,sizeof(events_));
    int infds=epoll_wait(epollfd_,events_,MaxEvents,timeout);       // 等待监视的fd有事件发生。

    // 返回失败。
    if (infds < 0)
    {
        // EBADF ：epfd不是一个有效的描述符。
        // EFAULT ：参数events指向的内存区域不可写。
        // EINVAL ：epfd不是一个epoll文件描述符，或者参数maxevents小于等于0。
        // EINTR ：阻塞过程中被信号中断，epoll_pwait()可以避免，或者错误处理中，解析error后重新调用epoll_wait()。
        // 在Reactor模型中，不建议使用信号，因为信号处理起来很麻烦，没有必要。------ 陈硕
        perror("epoll_wait() failed"); exit(-1);
    }
    // 超时。
    if (infds == 0)
    {
        // 如果epoll_wait()超时，表示系统很空闲，返回的channels将为空。
        // printf("epoll_wait() timeout.\n"); 
        return channels;
    }

    // 如果infds>0，表示有事件发生的fd的数量。
    for (int ii=0;ii<infds;ii++)       // 遍历epoll返回的数组events_。
    {
        Channel *ch=(Channel *)events_[ii].data.ptr;       // 取出已发生事件的channel。
        ch->setrevents(events_[ii].events);                       // 设置channel的revents_成员。
        channels.push_back(ch);
    }

    return channels;
}

//////////////////////////////////////////
////Channel

Channel::Channel(EventLoop* loop,int fd):loop_(loop),fd_(fd)      // 构造函数。
{

}

Channel::~Channel()                           // 析构函数。 
{
    // 在析构函数中，不要销毁loop_，也不能关闭fd_，因为这两个东西不属于Channel类，Channel类只是需要它们，使用它们而已。
}

int Channel::fd()                                            // 返回fd_成员。
{
    return fd_;
}

void Channel::useet()                                    // 采用边缘触发。
{
    events_=events_|EPOLLET;
}

void Channel::enablereading()                     // 让epoll_wait()监视fd_的读事件。
{
    events_|=EPOLLIN;
    loop_->updatechannel(this);
}

void Channel::disablereading()                    // 取消读事件。
{
    events_&=~EPOLLIN;
    loop_->updatechannel(this);
}

void Channel::enablewriting()                      // 注册写事件。
{
    events_|=EPOLLOUT;
    loop_->updatechannel(this);
}

void Channel::disablewriting()                     // 取消写事件。
{
    events_&=~EPOLLOUT;
    loop_->updatechannel(this);
}

void Channel::setinepoll()                           // 把inepoll_成员的值设置为true。
{
    inepoll_=true;
}

void Channel::setrevents(uint32_t ev)         // 设置revents_成员的值为参数ev。
{
    revents_=ev;
}

bool Channel::inpoll()                                  // 返回inepoll_成员。
{
    return inepoll_;
}

void Channel::disableall()                             // 取消全部的事件。
{
    events_=0;
    loop_->updatechannel(this);
}


void Channel::remove()                                // 从事件循环中删除Channel。
{
    disableall();                                // 先取消全部的事件。
    loop_->removechannel(this);    // 从红黑树上删除fd。
}

uint32_t Channel::events()                           // 返回events_成员。
{
    return events_;
}

uint32_t Channel::revents()                          // 返回revents_成员。
{
    return revents_;
} 

// 事件处理函数，epoll_wait()返回的时候，执行它。
void Channel::handleevent()
{
    if (revents_ & EPOLLRDHUP)                     // 对方已关闭，有些系统检测不到，可以使用EPOLLIN，recv()返回0。
    {
        closecallback_();      // 回调Connection::closecallback()。
    }                               
    else if (revents_ & (EPOLLIN|EPOLLPRI))   // 接收缓冲区中有数据可以读。
    {
        readcallback_();   // 如果是acceptchannel，将回调Acceptor::newconnection()，如果是clientchannel，将回调Connection::onmessage()。
    }  
    else if (revents_ & EPOLLOUT)                  // 有数据需要写。
    {
        writecallback_();      // 回调Connection::writecallback()。     
    }
    else                                                           // 其它事件，都视为错误。
    {
        errorcallback_();       // 回调Connection::errorcallback()。
    }
}

 // 设置fd_读事件的回调函数。
 void Channel::setreadcallback(std::function<void()> fn)    
 {
    readcallback_=fn;
 }

 // 设置关闭fd_的回调函数。
 void Channel::setclosecallback(std::function<void()> fn)    
 {
    closecallback_=fn;
 }

 // 设置fd_发生了错误的回调函数。
 void Channel::seterrorcallback(std::function<void()> fn)    
 {
    errorcallback_=fn;
 }

 // 设置写事件的回调函数。
 void Channel::setwritecallback(std::function<void()> fn)   
 {
    writecallback_=fn;
 }
///////////////////////////////////////////////
////EventLoop

int createtimerfd(int sec=30)
{
    int tfd=timerfd_create(CLOCK_MONOTONIC,TFD_CLOEXEC|TFD_NONBLOCK);   // 创建timerfd。
    struct itimerspec timeout;                                // 定时时间的数据结构。
    memset(&timeout,0,sizeof(struct itimerspec));
    timeout.it_value.tv_sec = sec;                             // 定时时间，固定为5，方便测试。
    timeout.it_value.tv_nsec = 0;
    timerfd_settime(tfd,0,&timeout,0);
    return tfd;
}

// 在构造函数中创建Epoll对象ep_。
EventLoop::EventLoop(bool mainloop,int timetvl,int timeout):ep_(new Epoll),mainloop_(mainloop),
                   timetvl_(timetvl),timeout_(timeout),stop_(false),
                   wakeupfd_(eventfd(0,EFD_NONBLOCK)),wakechannel_(new Channel(this,wakeupfd_)),
                   timerfd_(createtimerfd(timetvl_)),timerchannel_(new Channel(this,timerfd_))
{
    wakechannel_->setreadcallback(std::bind(&EventLoop::handlewakeup,this));
    wakechannel_->enablereading();

    timerchannel_->setreadcallback(std::bind(&EventLoop::handletimer,this));
    timerchannel_->enablereading();
}

// 在析构函数中销毁ep_。
EventLoop::~EventLoop()
{
}

// 运行事件循环。
void EventLoop::run()                      
{
    threadid_ = syscall(SYS_gettid);
    std::vector<Channel *> channels;         // 等待监视的fd有事件发生。

    while (!stop_)        // 事件循环。
    {
        channels.clear();
        channels = ep_->loop(10*1000);

        if(channels.empty()) { epolltimeoutcallback_(this); }
        for (auto &ch:channels)
        {
            ch->handleevent();        // 处理epoll_wait()返回的事件。
        }
    }
}

 // 停止事件循环。
 void EventLoop::stop()                    
 {
    stop_=true;
    wakeup();       // 唤醒事件循环，如果没有这行代码，事件循环将在下次闹钟响时或epoll_wait()超时时才会停下来。
 }

// 把channel添加/更新到红黑树上，channel中有fd，也有需要监视的事件。
void EventLoop::updatechannel(Channel *ch)                        
{
    ep_->updatechannel(ch);
}

 // 从黑树上删除channel。
 void EventLoop::removechannel(Channel *ch)                       
 {
    ep_->removechannel(ch);
 }


// 设置epoll_wait()超时的回调函数。
void EventLoop::setepolltimeoutcallback(std::function<void(EventLoop*)> fn)  
{
    epolltimeoutcallback_=fn;
}

// 判断当前线程是否为事件循环线程。
bool EventLoop::isinloopthread()   
{
    return threadid_==syscall(SYS_gettid); 
}
 // 把任务添加到队列中。
 void EventLoop::queueinloop(std::function<void()> fn)
 {
    {
        std::lock_guard<std::mutex> gd(mutex_);           // 给任务队列加锁。
        taskqueue_.push(fn);                                            // 任务入队。
    }
    wakeup();        // 唤醒事件循环。
 }

// 用eventfd唤醒事件循环线程。
 void EventLoop::wakeup()
 {
    uint64_t val = 1;
    write(wakeupfd_, &val, sizeof(val));
 }

 // 事件循环线程被eventfd唤醒后执行的函数。
 void EventLoop::handlewakeup()
 {
    uint64_t val;
    read(wakeupfd_,&val,sizeof(val));       // 从eventfd中读取出数据，如果不读取，eventfd的读事件会一直触发。

    std::function<void()> fn;

    std::lock_guard<std::mutex> gd(mutex_);           // 给任务队列加锁。

    // 执行队列中全部的发送任务。
    while (taskqueue_.size()>0)
    {
        fn=std::move(taskqueue_.front());    // 出队一个元素。
        taskqueue_.pop();                              
        fn();                                                    // 执行任务。
    }
 }

// 闹钟响时执行的函数。
void EventLoop::handletimer()                                                 
{
    // 重新计时。
    struct itimerspec timeout;                                // 定时时间的数据结构。
    memset(&timeout,0,sizeof(struct itimerspec));
    timeout.it_value.tv_sec = timetvl_;                             // 定时时间，固定为5，方便测试。
    timeout.it_value.tv_nsec = 0;
    timerfd_settime(timerfd_,0,&timeout,0);

    if (mainloop_) {}
        // printf("主事件循环的闹钟时间到了。\n");
    else
    {
        // printf("从事件循环的闹钟时间到了。\n"); 
        time_t now=time(0);         // 获取当前时间。
        for (auto it = conns_.begin(); it != conns_.end();)
        {
            if (it->second->timeout(now,timeout_)) 
            {
                timercallback_(it->first);             // 从TcpServer的map中删除超时的conn。
                {
                    std::lock_guard<std::mutex> gd(mtx_);
                    it = conns_.erase(it);               // 从EventLoop的map中删除超时的conn。
                }
            }
            else
                it++;
        }
    }
}

// 把Connection对象保存在conns_中。
void EventLoop::newconnection(spConnection conn)
{
    std::lock_guard<std::mutex> gd(mtx_);
    conns_[conn->fd()]=conn;
}

// 将被设置为TcpServer::removeconn()
void EventLoop::settimercallback(std::function<void(int)> fn)
{
    timercallback_=fn;
}

////////////////////////////////////////////////////////////////
////TCPServer

TcpServer::TcpServer(const std::string &ip,const uint16_t port,int threadnum)
                 :threadnum_(threadnum),mainloop_(new EventLoop(true)), acceptor_(mainloop_.get(),ip,port),threadpool_(threadnum_,"IO")
{
    mainloop_->setepolltimeoutcallback(std::bind(&TcpServer::epolltimeout,this,std::placeholders::_1));   // 设置timeout超时的回调函数。

    acceptor_.setnewconnectioncb(std::bind(&TcpServer::newconnection,this,std::placeholders::_1));

    // 创建从事件循环。
    for (int ii=0;ii<threadnum_;ii++)
    {
        subloops_.emplace_back(new EventLoop(false));              // 创建从事件循环，存入subloops_容器中。
        subloops_[ii]->setepolltimeoutcallback(std::bind(&TcpServer::epolltimeout,this,std::placeholders::_1));   // 设置timeout超时的回调函数。
        subloops_[ii]->settimercallback(std::bind(&TcpServer::removeconn,this,std::placeholders::_1));   // 设置清理空闲TCP连接的回调函数。
        threadpool_.addtask(std::bind(&EventLoop::run,subloops_[ii].get()));    // 在线程池中运行从事件循环。
    }
}

TcpServer::~TcpServer()
{
}

// 运行事件循环。
void TcpServer::start()          
{
    mainloop_->run();
}

 // 停止IO线程和事件循环。
 void TcpServer::stop()          
 {
    // 停止主事件循环。
    mainloop_->stop();
    printf("主事件循环已停止。\n");

    // 停止从事件循环。
    for (int ii=0;ii<threadnum_;ii++)
    {
        subloops_[ii]->stop();
    }
    printf("从事件循环已停止。\n");

    // 停止IO线程。
    threadpool_.stop();
    printf("IO线程池停止。\n");
 }

// 处理新客户端连接请求。
void TcpServer::newconnection(std::unique_ptr<Socket> clientsock)
{
    //spConnection conn=new Connection(mainloop_,clientsock);   
    // 把新建的conn分配给从事件循环。
    spConnection conn(new Connection(subloops_[clientsock->fd()%threadnum_].get(),std::move(clientsock)));   
    conn->setclosecallback(std::bind(&TcpServer::closeconnection,this,std::placeholders::_1));
    conn->seterrorcallback(std::bind(&TcpServer::errorconnection,this,std::placeholders::_1));
    conn->setonmessagecallback(std::bind(&TcpServer::onmessage,this,std::placeholders::_1,std::placeholders::_2));
    conn->setsendcompletecallback(std::bind(&TcpServer::sendcomplete,this,std::placeholders::_1));

    // printf ("new connection(fd=%d,ip=%s,port=%d) ok.\n",conn->fd(),conn->ip().c_str(),conn->port());

    {
        std::lock_guard<std::mutex> gd(mtx_);
        conns_[conn->fd()]=conn;            // 把conn存放到TcpSever的map容器中。
    }
    subloops_[conn->fd()%threadnum_]->newconnection(conn);       // 把conn存放到EventLoop的map容器中。
    // printf("TcpServer::newconnection() thread is %d.\n",syscall(SYS_gettid)); 

    if (newconnectioncb_) newconnectioncb_(conn);             // 回调EchoServer::HandleNewConnection()。
}

 // 关闭客户端的连接，在Connection类中回调此函数。 
 void TcpServer::closeconnection(spConnection conn)
 {
    if (closeconnectioncb_) closeconnectioncb_(conn);       // 回调EchoServer::HandleClose()。

    // printf("client(eventfd=%d) disconnected.\n",conn->fd());
    std::lock_guard<std::mutex> lock(mtx_);
    conns_.erase(conn->fd());        // 从map中删除conn。
 }

// 客户端的连接错误，在Connection类中回调此函数。
void TcpServer::errorconnection(spConnection conn)
{
    if (errorconnectioncb_) errorconnectioncb_(conn);     // 回调EchoServer::HandleError()。

    // printf("client(eventfd=%d) error.\n",conn->fd());
    std::lock_guard<std::mutex> lock(mtx_);
    conns_.erase(conn->fd());      // 从map中删除conn。
}

// 处理客户端的请求报文，在Connection类中回调此函数。
void TcpServer::onmessage(spConnection conn,std::string& message)
{
    /*
    // 在这里，将经过若干步骤的运算。
    message="reply:"+message;          // 回显业务。
                
    int len=message.size();                   // 计算回应报文的大小。
    std::string tmpbuf((char*)&len,4);  // 把报文头部填充到回应报文中。
    tmpbuf.append(message);             // 把报文内容填充到回应报文中。
                
    conn->send(tmpbuf.data(),tmpbuf.size());   // 把临时缓冲区中的数据发送出去。
    */
    if (onmessagecb_) onmessagecb_(conn,message);     // 回调EchoServer::HandleMessage()。
}

// 数据发送完成后，在Connection类中回调此函数。
void TcpServer::sendcomplete(spConnection conn)     
{
    // printf("send complete.\n");

    if (sendcompletecb_) sendcompletecb_(conn);     // 回调EchoServer::HandleSendComplete()。
}

// epoll_wait()超时，在EventLoop类中回调此函数。
void TcpServer::epolltimeout(EventLoop *loop)         
{
    // printf("epoll_wait() timeout.\n");

    if (timeoutcb_)  timeoutcb_(loop);           // 回调EchoServer::HandleTimeOut()。
}

void TcpServer::setnewconnectioncb(std::function<void(spConnection)> fn)
{
    newconnectioncb_=fn;
}

void TcpServer::setcloseconnectioncb(std::function<void(spConnection)> fn)
{
    closeconnectioncb_=fn;
}

void TcpServer::seterrorconnectioncb(std::function<void(spConnection)> fn)
{
    errorconnectioncb_=fn;
}

void TcpServer::setonmessagecb(std::function<void(spConnection,std::string &message)> fn)
{
    onmessagecb_=fn;
}

void TcpServer::setsendcompletecb(std::function<void(spConnection)> fn)
{
    sendcompletecb_=fn;
}

void TcpServer::settimeoutcb(std::function<void(EventLoop*)> fn)
{
    timeoutcb_=fn;
}

void TcpServer::removeconn(int fd)                 
{
    printf("TcpServer::removeconn() thread is %d.\n",syscall(SYS_gettid)); 
    {
        std::lock_guard<std::mutex> gd(mtx_);
        conns_.erase(fd);          // 从map中删除conn。
    }
}
///////////////////////////////////////////////////////
////Acceptor
Acceptor::Acceptor(EventLoop* loop,const std::string &ip,const uint16_t port)
                       :loop_(loop),servsock_(createnonblocking()),acceptchannel_(loop_,servsock_.fd())
{
    InetAddress servaddr(ip,port);             // 服务端的地址和协议。
    servsock_.setreuseaddr(true);
    servsock_.settcpnodelay(true);
    servsock_.setreuseport(true);
    servsock_.setkeepalive(true);
    servsock_.bind(servaddr);
    servsock_.listen();

    acceptchannel_.setreadcallback(std::bind(&Acceptor::newconnection,this));       
    acceptchannel_.enablereading();       // 让epoll_wait()监视servchannel的读事件。 
}

Acceptor::~Acceptor()
{
}

void Acceptor::newconnection()    // 处理新客户端连接请求。
{
    InetAddress clientaddr;
    std::unique_ptr<Socket> clientsock(new Socket(servsock_.accept(clientaddr)));

    clientsock->setipport(clientaddr.ip(),clientaddr.port());
    newconnectioncb_(std::move(clientsock));
}

void Acceptor::setnewconnectioncb(std::function<void(std::unique_ptr<Socket>)> fn)
{
    newconnectioncb_ = fn;
}


/////////////////////////////////////////////////////
////Connection
Connection::Connection(EventLoop* loop,std::unique_ptr<Socket> clientsock)
                   :loop_(loop),clientsock_(std::move(clientsock)),disconnect_(false),clientchannel_(new Channel(loop_,clientsock_->fd())) 
{
    // 为新客户端连接准备读事件，并添加到epoll中。
    //clientchannel_=new Channel(loop_,clientsock_->fd());   
    clientchannel_->setreadcallback(std::bind(&Connection::onmessage,this));
    clientchannel_->setclosecallback(std::bind(&Connection::closecallback,this));
    clientchannel_->seterrorcallback(std::bind(&Connection::errorcallback,this));
    clientchannel_->setwritecallback(std::bind(&Connection::writecallback,this));
    clientchannel_->useet();                 // 客户端连上来的fd采用边缘触发。
    clientchannel_->enablereading();   // 让epoll_wait()监视clientchannel的读事件
}

Connection::~Connection()
{
}

int Connection::fd() const                              // 返回客户端的fd。
{
    return clientsock_->fd();
}

std::string Connection::ip() const                   // 返回客户端的ip。
{
    return clientsock_->ip();
}

uint16_t Connection::port() const                  // 返回客户端的port。
{
    return clientsock_->port();
}

void Connection::closecallback()                    // TCP连接关闭（断开）的回调函数，供Channel回调。
{
    disconnect_=true;
    clientchannel_->remove();                  // 从事件循环中删除Channel。
    closecallback_(shared_from_this());     // 回调TcpServer::closeconnection()。
}

void Connection::errorcallback()                    // TCP连接错误的回调函数，供Channel回调。
{
    disconnect_=true;
    clientchannel_->remove();                  // 从事件循环中删除Channel。
    errorcallback_(shared_from_this());     // 回调TcpServer::errorconnection()。
}

// 设置关闭fd_的回调函数。
void Connection::setclosecallback(std::function<void(spConnection)> fn)    
{
    closecallback_=fn;     // 回调TcpServer::closeconnection()。
}

// 设置fd_发生了错误的回调函数。
void Connection::seterrorcallback(std::function<void(spConnection)> fn)    
{
    errorcallback_=fn;     // 回调TcpServer::errorconnection()。
}

// 设置处理报文的回调函数。
void Connection::setonmessagecallback(std::function<void(spConnection,std::string&)> fn)    
{
    onmessagecallback_=fn;       // 回调TcpServer::onmessage()。
}

// 发送数据完成后的回调函数。
void Connection::setsendcompletecallback(std::function<void(spConnection)> fn)    
{
    sendcompletecallback_=fn;
}

// 处理对端发送过来的消息。
void Connection::onmessage()
{
    char buffer[1024];
    while (true)             // 由于使用非阻塞IO，一次读取buffer大小数据，直到全部的数据读取完毕。
    {    
        bzero(&buffer, sizeof(buffer));
        ssize_t nread = read(fd(), buffer, sizeof(buffer));
        if (nread > 0)      // 成功的读取到了数据。
        {
            inputbuffer_.append(buffer,nread);      // 把读取的数据追加到接收缓冲区中。
        } 
        else if (nread == -1 && errno == EINTR) // 读取数据的时候被信号中断，继续读取。
        {  
            continue;
        } 
        else if (nread == -1 && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) // 全部的数据已读取完毕。
        {
            std::string message;

            while (true)             // 从接收缓冲区中拆分出客户端的请求消息。
            {
                if (inputbuffer_.pickmessage(message)==false) break;

                lastatime_=Timestamp::now();             // 更新Connection的时间戳。

                onmessagecallback_(shared_from_this(),message);       // 回调TcpServer::onmessage()处理客户端的请求消息。
            }
            break;
        } 
        else if (nread == 0)  // 客户端连接已断开。
        {  
            closecallback();                     // 回调Connection::closecallback()。
            break;
        }
    }
}

// 发送数据，不管在任何线程中，都是调用此函数发送数据。
void Connection::send(const char *data,size_t size)        
{
    if (disconnect_==true) {  printf("客户端连接已断开了，send()直接返回。\n"); return;}

    if (loop_->isinloopthread())   // 判断当前线程是否为事件循环线程（IO线程）。
    {
        // 如果当前线程是IO线程，直接调用sendinloop()发送数据。
        // printf("send() 在事件循环的线程中。\n");
        sendinloop(data,size);
    }
    else
    {
        // 如果当前线程不是IO线程，调用EventLoop::queueinloop()，把sendinloop()交给事件循环线程去执行。
        // loop_->queueinloop(std::bind(&Connection::sendinloop,this,std::string(data).data(),size));
        loop_->queueinloop([data = std::string(data),size,this]{
            this->outputbuffer_.appendwithsep(data.data(),size);
        this->clientchannel_->enablewriting();});
    }
}

// 发送数据，如果当前线程是IO线程，直接调用此函数，如果是工作线程，将把此函数传给IO线程去执行。
void Connection::sendinloop(const char *data,size_t size)
{
    // printf("%%%%%%%%%%%%3data::%s\n",data);
    outputbuffer_.appendwithsep(data,size);    // 把需要发送的数据保存到Connection的发送缓冲区中。
        // printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!Sendinloop:%d=====",syscall(SYS_gettid));
    // write(STDOUT_FILENO, outputbuffer_.data(), outputbuffer_.size());
    // printf("\n");
    clientchannel_->enablewriting();    // 注册写事件。
}


// 处理写事件的回调函数，供Channel回调。
void Connection::writecallback()                   
{
    int writen=::send(fd(),outputbuffer_.data(),outputbuffer_.size(),0);    // 尝试把outputbuffer_中的数据全部发送出去。
    if (writen>0) outputbuffer_.erase(0,writen);                                        // 从outputbuffer_中删除已成功发送的字节数。

    // 如果发送缓冲区中没有数据了，表示数据已发送完成，不再关注写事件。
    if (outputbuffer_.size()==0) 
    {
        clientchannel_->disablewriting();        
        sendcompletecallback_(shared_from_this());
    }
}

 // 判断TCP连接是否超时（空闲太久）。
 bool Connection::timeout(time_t now,int val)           
 {
    return now-lastatime_.toint()>val;    
 }

//////////////////////////////////////////////////////////////////////
////Buffer

Buffer::Buffer(uint16_t sep):sep_(sep)
{

}

Buffer::~Buffer()
{

}

// 把数据追加到buf_中。
void Buffer::append(const char *data,size_t size)             
{
    buf_.append(data,size);
}

 // 把数据追加到buf_中，附加报文分隔符。
 void Buffer::appendwithsep(const char *data,size_t size)  
 {
    if (sep_==0)             // 没有分隔符。
    {
        buf_.append(data,size);                    // 处理报文内容。
    }
    else if (sep_==1)     // 四字节的报头。
    {
        buf_.append((char*)&size,4);           // 处理报文长度（头部）。
        buf_.append(data,size);                    // 处理报文内容。
    }
    // 其它的代码请各位自己完善。
 }

// 从buf_的pos开始，删除nn个字节，pos从0开始。
void Buffer::erase(size_t pos,size_t nn)                             
{
    buf_.erase(pos,nn);
}

// 返回buf_的大小。
size_t Buffer::size()                                                            
{
    return buf_.size();
}

// 返回buf_的首地址。
const char *Buffer::data()                                                  
{
    return buf_.data();
}

// 清空buf_。
void Buffer::clear()                                                            
{
    buf_.clear();
}

// 从buf_中拆分出一个报文，存放在ss中，如果buf_中没有报文，返回false。
bool Buffer::pickmessage(std::string &ss)                           
{
    if (buf_.size()==0) return false;

    if (sep_==0)                  // 没有分隔符。
    {
        ss=buf_;
        buf_.clear();
    }
    else if (sep_==1)          // 四字节的报头。
    {
        int len;
        memcpy(&len,buf_.data(),4);             // 从buf_中获取报文头部。

        if (buf_.size()<len+4) return false;     // 如果buf_中的数据量小于报文头部，说明buf_中的报文内容不完整。

        ss=buf_.substr(4,len);                        // 从buf_中获取一个报文。
        buf_.erase(0,len+4);                          // 从buf_中删除刚才已获取的报文。
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////EchoServer

EchoServer::EchoServer(const std::string &ip,const uint16_t port,int iothreadnum,int workthreadnum):
                            tcpserver_(ip,port,iothreadnum),threadpool_(workthreadnum,"WORK")
{
    // 以下代码不是必须的，业务关心什么事件，就指定相应的回调函数。
    tcpserver_.setnewconnectioncb(std::bind(&EchoServer::HandleNewConnection, this, std::placeholders::_1));
    tcpserver_.setcloseconnectioncb(std::bind(&EchoServer::HandleClose, this, std::placeholders::_1));
    tcpserver_.seterrorconnectioncb(std::bind(&EchoServer::HandleError, this, std::placeholders::_1));
    tcpserver_.setonmessagecb(std::bind(&EchoServer::HandleMessage, this, std::placeholders::_1, std::placeholders::_2));
    tcpserver_.setsendcompletecb(std::bind(&EchoServer::HandleSendComplete, this, std::placeholders::_1));
    // tcpserver_.settimeoutcb(std::bind(&EchoServer::HandleTimeOut, this, std::placeholders::_1));
}

EchoServer::~EchoServer()
{

}

// 启动服务。
void EchoServer::Start()                
{
    tcpserver_.start();
}

 // 停止服务。
 void EchoServer::Stop()
 {
    // 停止工作线程。
    threadpool_.stop();
    printf("工作线程已停止。\n");

    // 停止IO线程（事件循环）。
    tcpserver_.stop();
 }

// 处理新客户端连接请求，在TcpServer类中回调此函数。
void EchoServer::HandleNewConnection(spConnection conn)    
{
    std::cout << "New Connection Come in." << std::endl;
    // printf("EchoServer::HandleNewConnection() thread is %d.\n",syscall(SYS_gettid));

    // 根据业务的需求，在这里可以增加其它的代码。
}

// 关闭客户端的连接，在TcpServer类中回调此函数。 
void EchoServer::HandleClose(spConnection conn)  
{
    std::cout << "EchoServer conn closed." << std::endl;

    // 根据业务的需求，在这里可以增加其它的代码。
}

// 客户端的连接错误，在TcpServer类中回调此函数。
void EchoServer::HandleError(spConnection conn)  
{
    std::cout << "EchoServer conn error." << std::endl;

    // 根据业务的需求，在这里可以增加其它的代码。
}

// 处理客户端的请求报文，在TcpServer类中回调此函数。
void EchoServer::HandleMessage(spConnection conn,std::string& message)     
{
    // printf("EchoServer::HandleMessage() thread is %d.\n",syscall(SYS_gettid));

    if( threadpool_.size() == 0) {
        OnMessage(conn,message);
    }
    else
        threadpool_.addtask(std::bind(&EchoServer::OnMessage,this,conn,message));
    
}
// 处理客户端的请求报文，用于添加给线程池。
void EchoServer::OnMessage(spConnection conn,std::string& message)     
{
    // printf("OnMessage: %d\n",syscall(SYS_gettid));
// 在这里，将经过若干步骤的运算。
message="reply:"+message;          // 回显业务。
conn->send(message.data(),message.size());   // 把数据发送出去。
    // printf("Echo send:%s\n",message.data());

}

// 数据发送完成后，在TcpServer类中回调此函数。
void EchoServer::HandleSendComplete(spConnection conn)     
{
    // std::cout << "Message send complete." << std::endl;

    // 根据业务的需求，在这里可以增加其它的代码。
}

/*
// epoll_wait()超时，在TcpServer类中回调此函数。
void EchoServer::HandleTimeOut(EventLoop *loop)         
{
    std::cout << "EchoServer timeout." << std::endl;

    // 根据业务的需求，在这里可以增加其它的代码。
}
*/
