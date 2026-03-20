#include "net.h"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace std;

void test_timestamp() {
    cout << "\n=== Test: Timestamp ===" << endl;
    
    Timestamp t1 = Timestamp::now();
    cout << "Current time: " << t1.tostring() << endl;
    
    sleep(2);
    Timestamp t2 = Timestamp::now();
    cout << "After 2 seconds: " << t2.tostring() << endl;
    
    assert(t2.toint() >= t1.toint() + 2);
    
    cout << "Timestamp test PASSED!" << endl;
}

void test_buffer() {
    cout << "\n=== Test: Buffer ===" << endl;
    
    Buffer buf(1);
    
    const char* msg1 = "Hello";
    buf.appendwithsep(msg1, strlen(msg1));
    
    const char* msg2 = "World";
    buf.appendwithsep(msg2, strlen(msg2));
    
    cout << "Buffer size after appending 2 messages: " << buf.size() << endl;
    
    string message;
    bool ret1 = buf.pickmessage(message);
    assert(ret1 == true);
    cout << "First message: " << message << endl;
    assert(message == "Hello");
    
    bool ret2 = buf.pickmessage(message);
    assert(ret2 == true);
    cout << "Second message: " << message << endl;
    assert(message == "World");
    
    bool ret3 = buf.pickmessage(message);
    assert(ret3 == false);
    cout << "No more messages (expected)" << endl;
    
    cout << "Buffer test PASSED!" << endl;
}

void test_inetaddress() {
    cout << "\n=== Test: InetAddress ===" << endl;
    
    InetAddress addr("127.0.0.1", 8080);
    
    cout << "IP: " << addr.ip() << endl;
    cout << "Port: " << addr.port() << endl;
    
    assert(string(addr.ip()) == "127.0.0.1");
    assert(addr.port() == 8080);
    
    cout << "InetAddress test PASSED!" << endl;
}

void test_threadpool() {
    cout << "\n=== Test: ThreadPool ===" << endl;
    
    ThreadPool pool(4, "TEST");
    
    atomic<int> counter(0);
    const int TASK_COUNT = 100;
    
    for (int i = 0; i < TASK_COUNT; ++i) {
        pool.addtask([&counter]() {
            counter++;
        });
    }
    
    sleep(2);
    
    cout << "Tasks completed: " << counter.load() << "/" << TASK_COUNT << endl;
    assert(counter.load() == TASK_COUNT);
    
    cout << "ThreadPool test PASSED!" << endl;
}

void test_buffer_sep0() {
    cout << "\n=== Test: Buffer with sep=0 (no separator) ===" << endl;
    
    Buffer buf(0);
    
    const char* data = "RawData";
    buf.appendwithsep(data, strlen(data));
    
    cout << "Buffer size: " << buf.size() << endl;
    assert(buf.size() == strlen(data));
    
    string message;
    bool ret = buf.pickmessage(message);
    assert(ret == true);
    cout << "Message: " << message << endl;
    assert(message == "RawData");
    assert(buf.size() == 0);
    
    cout << "Buffer (sep=0) test PASSED!" << endl;
}

void test_buffer_partial() {
    cout << "\n=== Test: Buffer with partial message ===" << endl;
    
    Buffer buf(1);
    
    int len = 10;
    buf.append((char*)&len, 4);
    buf.append("Hello", 5);
    
    string message;
    bool ret = buf.pickmessage(message);
    assert(ret == false);
    cout << "Partial message correctly not extracted" << endl;
    
    buf.append("World", 5);
    
    ret = buf.pickmessage(message);
    assert(ret == true);
    cout << "Complete message: " << message << endl;
    assert(message == "HelloWorld");
    
    cout << "Buffer (partial) test PASSED!" << endl;
}

int main() {
    cout << "========================================" << endl;
    cout << "     Core Module Unit Tests" << endl;
    cout << "========================================" << endl;
    
    try {
        test_timestamp();
        test_buffer();
        test_inetaddress();
        test_threadpool();
        test_buffer_sep0();
        test_buffer_partial();
        
        cout << "\n========================================" << endl;
        cout << "  All Core Tests PASSED!" << endl;
        cout << "========================================" << endl;
        
    } catch (const exception& e) {
        cerr << "Test failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
