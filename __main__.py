"""python -m certcheck 入口。"""
import sys

try:
    from .certcheck import main
except ImportError:  # 直接在目录里运行时（namespace package 回退）
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from certcheck import main

if __name__ == "__main__":
    sys.exit(main())
