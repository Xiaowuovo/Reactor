#!/bin/bash
# 清理无用和重复文件

echo "🗑️  开始清理无用文件..."

# 删除重复的Makefile
rm -f Makefile.new Makefile.old Makefile.backup Makefile.final

# 删除过时的说明文档
rm -f 使用说明.txt
rm -f 毕设撰写指导说明书.md
rm -f PROJECT_STRUCTURE.md
rm -f README_DEMO.md
rm -f README_CN.md

# 删除临时和重组脚本（任务完成后不再需要）
rm -f reorganize.sh
rm -f CLEANUP_GUIDE.md
rm -f 执行指南.md

# 删除编译产物
rm -f *.o
rm -f src/*.o
rm -f tests/*.o

# 删除临时日志文件
rm -f *.log
rm -f test_report_*.log

echo "✅ 清理完成！"
echo ""
echo "保留的核心文件："
echo "  - src/        (源代码)"
echo "  - tests/      (测试代码)"
echo "  - tools/      (工具脚本)"
echo "  - docs/       (精简后的文档)"
echo "  - Makefile    (构建系统)"
echo "  - README.md   (项目说明)"
echo "  - QUICK_START.md (快速指南)"
