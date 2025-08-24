#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // TCP_NODELAY需要包含这个头文件。
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

////timestamp
class Timestamp {
 private:
  time_t secsinceepoch_;  // 整数表示的时间（从1970到现在已逝去的秒数）。

 public:
  Timestamp();                       // 用当前时间初始化对象。
  Timestamp(int64_t secsinceepoch);  // 用一个整数表示的时间初始化对象。

  static Timestamp now();  // 返回当前时间的Timestamp对象。

  time_t toint() const;          // 返回整数表示的时间。
  std::string tostring() const;  // 返回字符串表示的时间，格式：yyyy-mm-dd hh24:mi:ss
};

////ThreadPool
class ThreadPool {
 private:
  std::vector<std::thread> threads_;             // 线程池中的线程。
  std::queue<std::function<void()>> taskqueue_;  // 任务队列。
  std::mutex mutex_;                             // 任务队列同步的互斥锁。
  std::condition_variable condition_;            // 任务队列同步的条件变量。
  std::atomic_bool stop_;         // 在析构函数中，把stop_的值设置为true，全部的线程将退出。
  const std::string threadtype_;  // 线程种类："IO"、"WORKS"
 public:
  // 在构造函数中将启动threadnum个线程，
  ThreadPool(size_t threadnum, const std::string &threadtype);

  // 把任务添加到队列中。
  void addtask(std::function<void()> task);

  // 获取线程池的大小。
  size_t size();

  void stop();

  // 在析构函数中将停止线程。
  ~ThreadPool();
};

////InetAddress
class InetAddress {
 private:
  sockaddr_in addr_;  // 表示地址协议的结构体。
 public:
  InetAddress();
  InetAddress(const std::string &ip,
              uint16_t port);           // 如果是监听的fd，用这个构造函数。
  InetAddress(const sockaddr_in addr);  // 如果是客户端连上来的fd，用这个构造函数。
  ~InetAddress();

  const char *ip() const;                // 返回字符串表示的地址，例如：192.168.150.128
  uint16_t port() const;                 // 返回整数表示的端口，例如：80、8080
  const sockaddr *addr() const;          // 返回addr_成员的地址，转换成了sockaddr。
  void setaddr(sockaddr_in clientaddr);  // 设置addr_成员的值。
};

// 创建一个非阻塞的socket。
int createnonblocking();

////Socket
class Socket {
 private:
  const int fd_;    // Socket持有的fd，在构造函数中传进来。
  std::string ip_;  // Listenfd存放监听，clientfd存放对端
  uint16_t port_;   // Listenfd存放监听，clientfd存放对端

 public:
  Socket(int fd);  // 构造函数，传入一个已准备好的fd。
  ~Socket();       // 在析构函数中，将关闭fd_。

  int fd() const;          // 返回fd_成员。
  std::string ip() const;  // 返回ip_成员。
  uint16_t port() const;   // 返回port_成员。
  void setipport(std::string ip, uint16_t port);
  void setreuseaddr(bool on = true);       // 设置SO_REUSEADDR选项。
  void setreuseport(bool on = true);       // 设置SO_REUSEPORT选项。
  void settcpnodelay(bool on = true);      // 设置TCP_NODELAY选项。
  void setkeepalive(bool on = true);       // 设置SO_KEEPALIVE选项。
  void bind(const InetAddress &servaddr);  // 服务端的socket将调用此函数。
  void listen(int nn = 128);               // 服务端的socket将调用此函数。
  int accept(InetAddress &clientaddr);     // 服务端的socket将调用此函数。
};

////Epoll
class Channel;
class Epoll {
 private:
  static const int MaxEvents = 100;  // epoll_wait()返回事件数组的大小。
  int epollfd_ = -1;                 // epoll句柄，在构造函数中创建。
  // 存放epoll_wait()返回事件的数组，在构造函数中分配内存
  epoll_event events_[MaxEvents];

 public:
  Epoll();                          // 在构造函数中创建了epollfd_。
  ~Epoll();                         // 在析构函数中关闭epollfd_。
  void updatechannel(Channel *ch);  // 把channel添加/更新到红黑树上
  void removechannel(Channel *ch);  // 从红黑树上删除channel。
  // 运行epoll_wait()，等待事件的发生，已发生的事件用vector容器返回。
  std::vector<Channel *> loop(int timeout = -1);
};

////Channel
class EventLoop;
class Channel {
 private:
  int fd_ = -1;  // Channel拥有的fd，Channel和fd是一对一的关系。
  EventLoop *loop_;  // Channel对应的事件循环，Channel与EventLoop是多对一的关系，一个Channel只对应一个EventLoop。
  bool inepoll_ = false;  // Channel是否已添加到epoll树上，如果未添加，epoll_ctl()用EPOLL_CTL_ADD，否则用EPOLL_CTL_MOD。
  uint32_t events_ = 0;  // fd_需要监视的事件。listenfd和clientfd需要监视EPOLLIN，clientfd还可能需要监视EPOLLOUT。
  uint32_t revents_ = 0;                 // fd_已发生的事件。
  std::function<void()> readcallback_;   // fd_读事件的回调函数。
  std::function<void()> closecallback_;  // 关闭fd_的回调函数，将回调Connection::closecallback()。
  std::function<void()> errorcallback_;  // fd_发生了错误的回调函数，将回调Connection::errorcallback()。
  std::function<void()> writecallback_;  // fd_写事件的回调函数，将回调Connection::writecallback()。
 public:
  Channel(EventLoop *loop_, int fd);  // 构造函数。
  ~Channel();                         // 析构函数。

  int fd();                      // 返回fd_成员。
  void useet();                  // 采用边缘触发。
  void enablereading();          // 让epoll_wait()监视fd_的读事件。
  void disablereading();         // 取消读事件。
  void enablewriting();          // 注册写事件。
  void disablewriting();         // 取消写事件。
  void disableall();             // 取消全部的事件。
  void setinepoll();             // 把inepoll_成员的值设置为true。
  void setrevents(uint32_t ev);  // 设置revents_成员的值为参数ev。
  void remove();                 // 从事件循环中删除Channel。
  bool inpoll();                 // 返回inepoll_成员。
  uint32_t events();             // 返回events_成员。
  uint32_t revents();            // 返回revents_成员。

  void handleevent();                               // 事件处理函数，epoll_wait()返回的时候，执行它。
  void setreadcallback(std::function<void()> fn);   // 设置fd_读事件的回调函数。
  void setclosecallback(std::function<void()> fn);  // 设置关闭fd_的回调函数。
  void seterrorcallback(std::function<void()> fn);  // 设置fd_发生了错误的回调函数。
  void setwritecallback(std::function<void()> fn);  // 设置写事件的回调函数。
};

////EventLoop
class Connection;
using spConnection = std::shared_ptr<Connection>;
class EventLoop {
 private:
  bool mainloop_;              // true-是主事件循环，false-是从事件循环。
  std::atomic_bool stop_;      // 初始值为false，如果设置为true，表示停止事件循环。
  int timetvl_;                // 闹钟时间间隔，单位：秒。。
  int timeout_;                // Connection对象超时的时间，单位：秒。
  std::unique_ptr<Epoll> ep_;  // 每个事件循环只有一个Epoll。
  std::function<void(EventLoop *)> epolltimeoutcallback_;  // epoll_wait()超时的回调函数。
  pid_t threadid_;                                         // 事件循环所在线程的id。
  std::queue<std::function<void()>> taskqueue_;  // 事件循环线程被eventfd唤醒后执行的任务队列。
  std::mutex task_mtx_;                          // 任务队列同步的互斥锁。
  int wakeupfd_;                                 // 用于唤醒事件循环线程的eventfd。
  std::unique_ptr<Channel> wakechannel_;         // eventfd的Channel。
  int timerfd_;                                  // 定时器的fd。
  std::unique_ptr<Channel> timerchannel_;        // 定时器的Channel。
  std::function<void(int)> timercallback_;  // 删除TcpServer中超时的Connection对象，将被设置为TcpServer::removeconn()
  std::map<int, spConnection> conns_;  // 存放运行在该事件循环上全部的Connection对象。
  std::mutex mtx_;                     // 保护conns_的互斥锁。

  // 1、在事件循环中增加map<int,spConnect>
  // 2、如果闹钟时间到了，遍历conns_，判断每个Connection对象是否超时。
  // 3、如果超时了，从conns_中删除Connection对象；
  // 4、还需要从TcpServer.conns_中删除Connection对象。
  // 5、TcpServer和EventLoop的map容器需要加锁。
  // 6、闹钟时间间隔和超时时间参数化。
 public:
  EventLoop(bool mainloop, int timetvl = 30, int timeout = 80);  // 在构造函数中创建Epoll对象ep_。
  ~EventLoop();                                                  // 在析构函数中销毁ep_。

  void run();   // 运行事件循环。
  void stop();  // 停止事件循环。

  void updatechannel(Channel *ch);  // 把channel添加/更新到红黑树上，channel中有fd，也有需要监视的事件。
  void removechannel(Channel *ch);                                    // 从黑树上删除channel。
  void setepolltimeoutcallback(std::function<void(EventLoop *)> fn);  // 设置epoll_wait()超时的回调函数。

  bool isinloopthread();  // 判断当前线程是否为事件循环线程。

  void queueinloop(std::function<void()> fn);  // 把任务添加到队列中。
  void wakeup();                               // 用eventfd唤醒事件循环线程。
  void handlewakeup();                         // 事件循环线程被eventfd唤醒后执行的函数。
  void handletimer();                          // 闹钟响时执行的函数。

  void newconnection(spConnection conn);               // 把Connection对象保存在conns_中。
  void removeconn(int fd);                             // 从map中移除conn
  void settimercallback(std::function<void(int)> fn);  // 将被设置为TcpServer::removeconn()
};

////Acceptor
class Acceptor {
 private:
  EventLoop *loop_;        // Acceptor对应的事件循环，在构造函数中传入。
  Socket servsock_;        // 服务端用于监听的socket，在构造函数中创建。
  Channel acceptchannel_;  // Acceptor对应的channel，在构造函数中创建。
  std::function<void(std::unique_ptr<Socket>)> newconnectioncb_;  // 回调TcpServer::newconnection()

 public:
  Acceptor(EventLoop *loop, const std::string &ip, const uint16_t port);
  ~Acceptor();

  void newconnection();  // 处理新客户端连接请求。

  // 设置处理新客户端连接请求的回调函数，将在创建Acceptor对象的时候（TcpServer类的构造函数中）设置。
  void setnewconnectioncb(std::function<void(std::unique_ptr<Socket>)> fn);
};

////Connection
class Connection : public std::enable_shared_from_this<Connection> {
 private:
  EventLoop *loop_;                         // Connection对应的事件循环，在构造函数中传入。
  std::unique_ptr<Socket> clientsock_;      // 与客户端通讯的Socket。
  std::unique_ptr<Channel> clientchannel_;  // Connection对应的channel，在构造函数中创建。
  Buffer inputbuffer_;                      // 接收缓冲区。
  Buffer outputbuffer_;                     // 发送缓冲区。
  std::atomic_bool disconnect_;             // 客户端连接是否已断开，如果已断开，则设置为true。
  std::mutex mtx_;
  Timestamp lastatime_;  // 时间戳，创建Connection对象时为当前时间，每接收到一个报文，把时间戳更新为当前时间。

  std::function<void(spConnection)> closecallback_;  // 关闭fd_的回调函数，将回调TcpServer::closeconnection()。
  std::function<void(spConnection)> errorcallback_;  // fd_发生了错误的回调函数，将回调TcpServer::errorconnection()。
  std::function<void(spConnection, std::string &)> onmessagecallback_;  // 处理报文，将回调TcpServer::onmessage()。
  std::function<void(spConnection)> sendcompletecallback_;  // 发送数据完成，将回调TcpServer::sendcomplete()。

 public:
  Connection(EventLoop *loop_, std::unique_ptr<Socket> clientsock);
  ~Connection();

  int fd() const;          // 返回客户端的fd。
  std::string ip() const;  // 返回客户端的ip。
  uint16_t port() const;   // 返回客户端的port。

  void onmessage();      // 处理对端发送过来的消息。
  void closecallback();  // TCP连接关闭（断开）的回调函数，供Channel回调。
  void errorcallback();  // TCP连接错误的回调函数，供Channel回调。
  void writecallback();  // 处理写事件的回调函数，供Channel回调。

  void setclosecallback(std::function<void(spConnection)> fn);  // 设置关闭fd_的回调函数。
  void seterrorcallback(std::function<void(spConnection)> fn);  // 设置fd_发生了错误的回调函数。
  void setonmessagecallback(std::function<void(spConnection, std::string &)> fn);  // 设置处理报文的回调函数。
  void setsendcompletecallback(std::function<void(spConnection)> fn);  // 发送数据完成后的回调函数。

  void send(const char *data, size_t size);  // 发送数据。
  void sendinloop(const char *data, size_t size);

  bool timeout(time_t now, int val);  // 判断TCP连接是否超时（空闲太久）。
};

////TcpServer
class Acceptor;
class Connection;
using spConnection = std::shared_ptr<Connection>;
class TcpServer {
 private:
  std::unique_ptr<EventLoop> mainloop_;  // 主事件循环。 祼指针 普通指针 原始指针 std::unique_ptr
  std::vector<std::unique_ptr<EventLoop>> subloops_;  // 存放从事件循环的容器。
  Acceptor acceptor_;                                 // 一个TcpServer只有一个Acceptor对象。
  int threadnum_;                                     // 线程池的大小，即从事件循环的个数。
  ThreadPool threadpool_;                             // 线程池。
  std::mutex mtx_;                                    // 删除conn的锁

  std::map<int, spConnection> conns_;                             // conn对象们
  std::function<void(spConnection)> newconnectioncb_;             // 回调EchoServer::HandleNewConnection()。
  std::function<void(spConnection)> closeconnectioncb_;           // 回调EchoServer::HandleClose()。
  std::function<void(spConnection)> errorconnectioncb_;           // 回调EchoServer::HandleError()。
  std::function<void(spConnection, std::string &)> onmessagecb_;  // 回调EchoServer::HandleMessage()。
  std::function<void(spConnection)> sendcompletecb_;              // 回调EchoServer::HandleSendComplete()。
  std::function<void(EventLoop *)> timeoutcb_;                    // 回调EchoServer::HandleTimeOut()。

 public:
  TcpServer(const std::string &ip, const uint16_t port, int threadnum = 3);
  ~TcpServer();

  void start();  // 运行事件循环。
  void stop();   // 停止IO线程和事件循环。

  void newconnection(std::unique_ptr<Socket> clientsock);  // 处理新客户端连接请求，在Acceptor类中回调此函数。
  void closeconnection(spConnection conn);  // 关闭客户端的连接，在Connection类中回调此函数。
  void errorconnection(spConnection conn);  // 客户端的连接错误，在Connection类中回调此函数。
  void onmessage(spConnection conn,
                 std::string &message);  // 处理客户端的请求报文，在Connection类中回调此函数。
  void sendcomplete(spConnection conn);  // 数据发送完成后，在Connection类中回调此函数。
  void epolltimeout(EventLoop *loop);    // epoll_wait()超时，在EventLoop类中回调此函数。

  void setnewconnectioncb(std::function<void(spConnection)> fn);
  void setcloseconnectioncb(std::function<void(spConnection)> fn);
  void seterrorconnectioncb(std::function<void(spConnection)> fn);
  void setonmessagecb(std::function<void(spConnection, std::string &message)> fn);
  void setsendcompletecb(std::function<void(spConnection)> fn);
  void settimeoutcb(std::function<void(EventLoop *)> fn);

  void removeconn(int fd);  // 删除conns_中的Connection对象，在EventLoop::handletimer()中将回调此函数。
};

////Buffer
class Buffer {
 private:
  std::string buf_;  // 用于存放数据。
  const uint16_t sep_;  // 0-无分隔符(固定长度、视频会议)；1-四字节的报头；2-"\r\n\r\n"分隔符（http协议）。

 public:
  Buffer(uint16_t sep = 1);
  ~Buffer();

  void append(const char *data, size_t size);         // 把数据追加到buf_中。
  void appendwithsep(const char *data, size_t size);  // 把数据追加到buf_中，附加报文分隔符。
  void erase(size_t pos, size_t nn);                  // 从buf_的pos开始，删除nn个字节，pos从0开始。
  size_t size();                                      // 返回buf_的大小。
  const char *data();                                 // 返回buf_的首地址。
  void clear();                                       // 清空buf_。
  bool pickmessage(std::string &ss);  // 从buf_中拆分出一个报文，存放在ss中，如果buf_中没有报文，返回false。
};

////EchoServer
class EchoServer {
 private:
  TcpServer tcpserver_;
  ThreadPool threadpool_;  // 工作线程池。

 public:
  EchoServer(const std::string &ip, const uint16_t port, int iothreadnum = 2, int workthreadnum = 0);
  ~EchoServer();

  void Start();  // 启动服务。
  void Stop();   // 停止服务。

  void HandleNewConnection(spConnection conn);  // 处理新客户端连接请求，在TcpServer类中回调此函数。
  void HandleClose(spConnection conn);          // 关闭客户端的连接，在TcpServer类中回调此函数。
  void HandleError(spConnection conn);          // 客户端的连接错误，在TcpServer类中回调此函数。
  void HandleMessage(spConnection conn, std::string &message);  // 处理客户端的请求报文，在TcpServer类中回调此函数。
  void HandleSendComplete(spConnection conn);  // 数据发送完成后，在TcpServer类中回调此函数。
  // void HandleTimeOut(EventLoop *loop);
  // epoll_wait()超时，在TcpServer类中回调此函数。
  void OnMessage(spConnection conn, std::string &message);  // 处理客户端的请求报文，用于添加给线程池。
};