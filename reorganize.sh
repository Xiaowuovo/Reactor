#!/bin/bash
# 项目目录重组脚本
# 自动创建目录结构并移动文件

echo "=========================================="
echo "  Reactor 项目目录重组"
echo "=========================================="
echo ""

# 创建新目录结构
echo "📁 创建目录结构..."
mkdir -p src
mkdir -p tests
mkdir -p tools
mkdir -p docs
mkdir -p output/data
mkdir -p output/logs
mkdir -p output/charts

echo "✓ 目录创建完成"
echo ""

# 移动源代码文件
echo "📦 移动源代码文件到 src/..."
mv -f net.h net.cpp src/ 2>/dev/null
mv -f MemoryPool.h MemoryPool.cpp src/ 2>/dev/null
mv -f BufferPool.h BufferPool.cpp src/ 2>/dev/null
mv -f TerminalUI.h src/ 2>/dev/null
echo "✓ 源代码移动完成"
echo ""

# 移动应用程序
echo "📦 移动应用程序到 src/..."
mv -f tmp.cpp src/server.cpp 2>/dev/null
mv -f client.cpp src/ 2>/dev/null
mv -f demo.cpp src/ 2>/dev/null
echo "✓ 应用程序移动完成"
echo ""

# 移动测试文件
echo "📦 移动测试文件到 tests/..."
mv -f test_mempool.cpp tests/ 2>/dev/null
mv -f test_core.cpp tests/ 2>/dev/null
mv -f test_network.cpp tests/ 2>/dev/null
echo "✓ 测试文件移动完成"
echo ""

# 移动工具脚本
echo "📦 移动工具脚本到 tools/..."
mv -f demo.sh tools/ 2>/dev/null
mv -f visualize_all.py tools/ 2>/dev/null
mv -f visualize_performance.py tools/ 2>/dev/null
mv -f run_full_test.sh tools/ 2>/dev/null
echo "✓ 工具脚本移动完成"
echo ""

# 移动文档
echo "📦 移动文档到 docs/..."
mv -f ARCHITECTURE.md docs/ 2>/dev/null
mv -f DESIGN.md docs/ 2>/dev/null
mv -f TESTING.md docs/ 2>/dev/null
mv -f DEMO_GUIDE.md docs/ 2>/dev/null
mv -f OPTIMIZATION_SUMMARY.md docs/ 2>/dev/null
mv -f FINAL_SUMMARY.md docs/ 2>/dev/null
echo "✓ 文档移动完成"
echo ""

# 删除过时文档
echo "🗑️  删除过时文档..."
rm -f 使用说明.txt 2>/dev/null
rm -f 毕设撰写指导说明书.md 2>/dev/null
rm -f PROJECT_STRUCTURE.md 2>/dev/null
rm -f README_DEMO.md 2>/dev/null
rm -f Makefile.backup 2>/dev/null
echo "✓ 过时文档已删除"
echo ""

# 使用新Makefile
echo "🔧 更新构建文件..."
if [ -f "Makefile.new" ]; then
    mv -f Makefile Makefile.old 2>/dev/null
    mv -f Makefile.new Makefile 2>/dev/null
    echo "✓ Makefile已更新"
fi
echo ""

# 移动CSV文件到output
echo "📊 整理输出文件..."
mv -f *.csv output/data/ 2>/dev/null
mv -f *.png output/charts/ 2>/dev/null
mv -f *.log output/logs/ 2>/dev/null
echo "✓ 输出文件已整理"
echo ""

echo "=========================================="
echo "✅ 目录重组完成！"
echo "=========================================="
echo ""
echo "新的项目结构："
echo "  src/        - 源代码"
echo "  tests/      - 测试代码"
echo "  tools/      - 工具脚本"
echo "  docs/       - 文档"
echo "  output/     - 输出文件"
echo ""
echo "下一步："
echo "  1. 查看新结构：tree 或 ls -la"
echo "  2. 阅读指南：cat QUICK_START.md"
echo "  3. 开始使用：make demo"
echo ""
