CROSS=x86_64-w64-mingw32

CXX=$(CROSS)-g++
CXXFLAGS=-D_WIN32_WINNT=0x0602 -DUNICODE

srcs := $(wildcard *.cpp)
objs := $(patsubst %.cpp,%.o,$(srcs))

Lsass_Shtinkering.exe: $(objs)
	$(CXX) -o $@ -static $^ -lntdll

.PHONY: clean
clean:
	rm -f $(objs) Lsass_Shtinkering.exe
