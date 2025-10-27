/*
 * 这个 C 头文件 (`/Users/hmini/prj/github/wireguard-linux-compat-1.0.20220627/src/version.h`) 的作用是定义 WireGuard 内核模块的版本号。
 *
 * 代码解释：
 * - `#ifndef WIREGUARD_VERSION`: 这是一个预处理器指令，检查 `WIREGUARD_VERSION` 这个宏是否尚未定义。
 * - `#define WIREGUARD_VERSION "1.0.20220627"`: 如果 `WIREGUARD_VERSION` 未定义，则将其定义为字符串 `"1.0.20220627"`。
 * - `#endif`: 结束 `#ifndef` 条件块。
 *
 * 这种结构确保了 `WIREGUARD_VERSION` 这个宏只被定义一次。该版本号可以在编译时或运行时用于显示信息或进行兼容性检查。
 */
#ifndef WIREGUARD_VERSION
#define WIREGUARD_VERSION "1.0.20220627"
#endif