#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <thread>

/**
 * @brief 优雅的终端UI库 - 用于毕业设计演示
 * 
 * 功能：
 * - 彩色输出（标题、成功、错误、警告、信息）
 * - 表格绘制（性能数据展示）
 * - 进度条（测试运行进度）
 * - 分割线（章节分隔）
 * - 菜单系统（交互式选择）
 * - 动画效果（加载动画）
 */
namespace TerminalUI {

// ===== ANSI颜色代码 =====
namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string BLACK   = "\033[30m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";
    
    // 高亮色
    const std::string BRIGHT_RED     = "\033[91m";
    const std::string BRIGHT_GREEN   = "\033[92m";
    const std::string BRIGHT_YELLOW  = "\033[93m";
    const std::string BRIGHT_BLUE    = "\033[94m";
    const std::string BRIGHT_MAGENTA = "\033[95m";
    const std::string BRIGHT_CYAN    = "\033[96m";
    
    // 背景色
    const std::string BG_BLACK   = "\033[40m";
    const std::string BG_RED     = "\033[41m";
    const std::string BG_GREEN   = "\033[42m";
    const std::string BG_YELLOW  = "\033[43m";
    const std::string BG_BLUE    = "\033[44m";
    const std::string BG_MAGENTA = "\033[45m";
    const std::string BG_CYAN    = "\033[46m";
    const std::string BG_WHITE   = "\033[47m";
    
    // 样式
    const std::string BOLD      = "\033[1m";
    const std::string DIM       = "\033[2m";
    const std::string UNDERLINE = "\033[4m";
    const std::string BLINK     = "\033[5m";
    const std::string REVERSE   = "\033[7m";
}

// ===== 符号 =====
namespace Symbol {
    const std::string CHECK      = "✓";
    const std::string CROSS      = "✗";
    const std::string ARROW      = "→";
    const std::string STAR       = "★";
    const std::string BULLET     = "•";
    const std::string CIRCLE     = "●";
    const std::string TRIANGLE   = "▶";
    const std::string DIAMOND    = "◆";
    const std::string HOURGLASS  = "⏳";
    const std::string ROCKET     = "🚀";
    const std::string CHART      = "📊";
    const std::string FIRE       = "🔥";
    const std::string TROPHY     = "🏆";
}

// ===== 基础输出函数 =====

inline void print_title(const std::string& title, char border = '=') {
    int width = 80;
    int padding = (width - title.length() - 2) / 2;
    
    std::cout << Color::BRIGHT_CYAN << Color::BOLD;
    std::cout << std::string(width, border) << "\n";
    std::cout << std::string(padding, ' ') << title << "\n";
    std::cout << std::string(width, border) << Color::RESET << "\n";
}

inline void print_section(const std::string& section) {
    std::cout << "\n" << Color::BRIGHT_YELLOW << Color::BOLD
              << "▶ " << section << Color::RESET << "\n\n";
}

inline void print_success(const std::string& msg) {
    std::cout << Color::BRIGHT_GREEN << Symbol::CHECK << " " << msg << Color::RESET << "\n";
}

inline void print_error(const std::string& msg) {
    std::cout << Color::BRIGHT_RED << Symbol::CROSS << " " << msg << Color::RESET << "\n";
}

inline void print_warning(const std::string& msg) {
    std::cout << Color::BRIGHT_YELLOW << "⚠ " << msg << Color::RESET << "\n";
}

inline void print_info(const std::string& msg) {
    std::cout << Color::BRIGHT_BLUE << "ℹ " << msg << Color::RESET << "\n";
}

inline void print_separator(char ch = '-', int width = 80) {
    std::cout << Color::DIM << std::string(width, ch) << Color::RESET << "\n";
}

inline void print_highlight(const std::string& msg) {
    std::cout << Color::BG_BLUE << Color::WHITE << Color::BOLD 
              << " " << msg << " " << Color::RESET << "\n";
}

// ===== 进度条 =====

class ProgressBar {
private:
    int total_;
    int current_;
    int bar_width_;
    
public:
    ProgressBar(int total, int bar_width = 50) 
        : total_(total), current_(0), bar_width_(bar_width) {}
    
    void update(int current) {
        current_ = current;
        display();
    }
    
    void increment() {
        current_++;
        display();
    }
    
    void display() {
        float progress = static_cast<float>(current_) / total_;
        int pos = static_cast<int>(bar_width_ * progress);
        
        std::cout << "\r[";
        for (int i = 0; i < bar_width_; ++i) {
            if (i < pos) std::cout << Color::BRIGHT_GREEN << "█" << Color::RESET;
            else if (i == pos) std::cout << Color::GREEN << "█" << Color::RESET;
            else std::cout << Color::DIM << "░" << Color::RESET;
        }
        std::cout << "] " << int(progress * 100.0) << "% (" 
                  << current_ << "/" << total_ << ")";
        std::cout.flush();
        
        if (current_ >= total_) {
            std::cout << " " << Color::BRIGHT_GREEN << Symbol::CHECK << Color::RESET << "\n";
        }
    }
};

// ===== 表格绘制 =====

class Table {
private:
    std::vector<std::string> headers_;
    std::vector<std::vector<std::string>> rows_;
    std::vector<int> col_widths_;
    
    void calculate_widths() {
        col_widths_.clear();
        for (size_t i = 0; i < headers_.size(); ++i) {
            int max_width = headers_[i].length();
            for (const auto& row : rows_) {
                if (i < row.size()) {
                    max_width = std::max(max_width, static_cast<int>(row[i].length()));
                }
            }
            col_widths_.push_back(max_width + 2); // padding
        }
    }
    
    void print_row_separator(char left, char mid, char right, char fill) {
        std::cout << Color::CYAN << left;
        for (size_t i = 0; i < col_widths_.size(); ++i) {
            std::cout << std::string(col_widths_[i], fill);
            if (i < col_widths_.size() - 1) std::cout << mid;
        }
        std::cout << right << Color::RESET << "\n";
    }
    
public:
    void set_headers(const std::vector<std::string>& headers) {
        headers_ = headers;
    }
    
    void add_row(const std::vector<std::string>& row) {
        rows_.push_back(row);
    }
    
    void print() {
        calculate_widths();
        
        // 顶部边框
        print_row_separator('┌', '┬', '┐', '─');
        
        // 表头
        std::cout << Color::CYAN << "│" << Color::RESET;
        for (size_t i = 0; i < headers_.size(); ++i) {
            std::cout << Color::BOLD << Color::BRIGHT_YELLOW 
                      << std::setw(col_widths_[i]) << std::left << headers_[i] 
                      << Color::RESET;
            std::cout << Color::CYAN << "│" << Color::RESET;
        }
        std::cout << "\n";
        
        // 表头分割线
        print_row_separator('├', '┼', '┤', '─');
        
        // 数据行
        for (const auto& row : rows_) {
            std::cout << Color::CYAN << "│" << Color::RESET;
            for (size_t i = 0; i < headers_.size(); ++i) {
                std::string value = (i < row.size()) ? row[i] : "";
                std::cout << std::setw(col_widths_[i]) << std::left << value;
                std::cout << Color::CYAN << "│" << Color::RESET;
            }
            std::cout << "\n";
        }
        
        // 底部边框
        print_row_separator('└', '┴', '┘', '─');
    }
    
    void clear() {
        rows_.clear();
    }
};

// ===== 菜单系统 =====

class Menu {
private:
    std::string title_;
    std::vector<std::pair<std::string, std::string>> options_; // <key, description>
    
public:
    Menu(const std::string& title) : title_(title) {}
    
    void add_option(const std::string& key, const std::string& description) {
        options_.push_back({key, description});
    }
    
    void display() {
        std::cout << "\n";
        print_title(title_, '═');
        
        for (size_t i = 0; i < options_.size(); ++i) {
            std::cout << "  " << Color::BRIGHT_CYAN << Color::BOLD 
                      << "[" << options_[i].first << "]" << Color::RESET
                      << "  " << options_[i].second << "\n";
        }
        
        std::cout << "\n" << Color::BRIGHT_YELLOW << "请选择: " << Color::RESET;
    }
    
    std::string get_choice() {
        std::string choice;
        std::cin >> choice;
        std::cin.ignore(1000, '\n'); // 清除输入缓冲
        return choice;
    }
};

// ===== 加载动画 =====

class Spinner {
private:
    std::vector<std::string> frames_ = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    int current_frame_ = 0;
    
public:
    void spin(const std::string& message) {
        std::cout << "\r" << Color::BRIGHT_CYAN 
                  << frames_[current_frame_] << " " << message << Color::RESET;
        std::cout.flush();
        current_frame_ = (current_frame_ + 1) % frames_.size();
    }
    
    void stop(const std::string& final_message) {
        std::cout << "\r" << Color::BRIGHT_GREEN << Symbol::CHECK 
                  << " " << final_message << Color::RESET << "\n";
    }
};

// ===== 倒计时 =====

inline void countdown(int seconds, const std::string& message) {
    for (int i = seconds; i > 0; --i) {
        std::cout << "\r" << Color::BRIGHT_YELLOW << message 
                  << " " << i << "s..." << Color::RESET;
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "\r" << std::string(message.length() + 10, ' ') << "\r";
    std::cout.flush();
}

// ===== 统计数据框 =====

inline void print_stat_box(const std::string& label, const std::string& value, 
                           const std::string& color = Color::BRIGHT_CYAN) {
    std::cout << color << "┃ " << Color::RESET 
              << std::setw(25) << std::left << label 
              << color << " │ " << Color::BOLD << value << Color::RESET << "\n";
}

inline void print_stat_panel(const std::string& title, 
                            const std::vector<std::pair<std::string, std::string>>& stats) {
    std::cout << "\n" << Color::BRIGHT_CYAN << "┏" << std::string(78, '━') << "┓\n";
    std::cout << "┃ " << Color::BOLD << Color::BRIGHT_YELLOW 
              << std::setw(76) << std::left << title 
              << Color::RESET << Color::BRIGHT_CYAN << " ┃\n";
    std::cout << "┣" << std::string(78, '━') << "┫" << Color::RESET << "\n";
    
    for (const auto& stat : stats) {
        print_stat_box(stat.first, stat.second);
    }
    
    std::cout << Color::BRIGHT_CYAN << "┗" << std::string(78, '━') << "┛" 
              << Color::RESET << "\n";
}

// ===== 横幅 =====

inline void print_banner() {
    std::cout << Color::BRIGHT_CYAN << R"(
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║        ____                  _               ____                         ║
    ║       |  _ \ ___  __ _  ___| |_ ___  _ __  |  _ \  ___ _ __ ___   ___   ║
    ║       | |_) / _ \/ _` |/ __| __/ _ \| '__| | | | |/ _ \ '_ ` _ \ / _ \  ║
    ║       |  _ <  __/ (_| | (__| || (_) | |    | |_| |  __/ | | | | | (_) | ║
    ║       |_| \_\___|\__,_|\___|\__\___/|_|    |____/ \___|_| |_| |_|\___/  ║
    ║                                                                           ║
    ║           高性能线程局部内存池 Reactor 网络库 - 交互式演示系统               ║
    ║                         毕业设计项目答辩演示                               ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
)" << Color::RESET << "\n";
}

// ===== 清屏 =====

inline void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// ===== 暂停等待用户 =====

inline void pause(const std::string& message = "按回车键继续...") {
    std::cout << "\n" << Color::DIM << message << Color::RESET;
    std::cin.get();
}

} // namespace TerminalUI
