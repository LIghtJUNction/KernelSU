# KernelSU 项目说明文档

## 项目简介

KernelSU 是一个用于增强 Linux 内核功能的项目。它通过添加各种钩子和管理功能，提供了对系统权限和安全策略的更细粒度控制。

## 文件结构

### 1. `ksu_hook.h`

该头文件定义了多个函数接口，用于处理不同的系统调用和事件。这些接口包括：

- `ksu_handle_faccessat`：处理文件访问权限检查。
- `ksu_handle_stat`：处理文件状态获取。
- `ksu_handle_vfs_read`：处理虚拟文件系统的读取操作。
- `ksu_handle_execveat`：处理执行文件的系统调用。
- `ksu_handle_input_handle_event`：处理输入事件。

### 2. `allowlist.c`

该文件实现了一个允许列表机制，用于管理哪些用户 ID (UID) 被允许执行特定操作。主要功能包括：

- 初始化默认配置文件。
- 从允许列表中移除特定 UID。
- 获取和设置应用程序配置文件。
- 检查 UID 是否应该卸载。

### 3. `core_hook.c`

该文件实现了核心钩子功能，用于拦截和处理各种系统事件。主要功能包括：

- 检查当前用户是否被允许执行特定操作。
- 设置用户组信息。
- 设置用户权限和能力。
- 处理安全策略。

## 使用方法

1. **编译和安装**：按照标准的 Linux 内核模块编译和安装方法进行操作。
2. **配置文件**：根据需要修改配置文件，以适应特定的安全策略和权限管理需求。
3. **加载模块**：使用 `insmod` 命令加载编译好的内核模块。

## 注意事项

- 确保在修改和加载内核模块之前，备份当前系统配置。
- 详细阅读每个文件中的注释，以理解各个函数和宏的具体作用。
- 测试环境中进行充分测试，确保不会对生产环境造成影响。

## 贡献

欢迎对 KernelSU 项目进行贡献。请遵循以下步骤：

1. Fork 本仓库。
2. 创建一个新的分支 (`git checkout -b feature-branch`)。
3. 提交你的修改 (`git commit -am 'Add new feature'`)。
4. 推送到分支 (`git push origin feature-branch`)。
5. 创建一个 Pull Request。

## 联系我们

如果有任何问题或建议，请通过 GitHub Issues 与我们联系。


/**
 * @file ksu.c
 * @brief KernelSU模块的实现文件
 *
 * 该文件包含了KernelSU模块的初始化、退出函数以及一些辅助函数的实现。
 * KernelSU是一个用于Android内核的超级用户管理模块。
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"

static struct workqueue_struct *ksu_workqueue;

/**
 * @brief 将工作项加入到KernelSU的工作队列中
 *
 * @param work 要加入的工作项
 * @return 如果成功加入队列，返回true；否则返回false
 */
bool ksu_queue_work(struct work_struct *work);

/**
 * @brief 处理execveat系统调用的兼容性
 *
 * @param fd 文件描述符指针
 * @param filename_ptr 文件名指针
 * @param argv 参数列表
 * @param envp 环境变量列表
 * @param flags 标志位
 * @return 处理结果
 */
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
                    void *argv, void *envp, int *flags);

/**
 * @brief 处理execveat系统调用的KernelSU特定逻辑
 *
 * @param fd 文件描述符指针
 * @param filename_ptr 文件名指针
 * @param argv 参数列表
 * @param envp 环境变量列表
 * @param flags 标志位
 * @return 处理结果
 */
extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
                    void *argv, void *envp, int *flags);

/**
 * @brief 处理execveat系统调用
 *
 * 该函数首先调用ksu_handle_execveat_ksud处理KernelSU特定逻辑，
 * 然后调用ksu_handle_execveat_sucompat处理兼容性逻辑。
 *
 * @param fd 文件描述符指针
 * @param filename_ptr 文件名指针
 * @param argv 参数列表
 * @param envp 环境变量列表
 * @param flags 标志位
 * @return 处理结果
 */
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
            void *envp, int *flags);

extern void ksu_sucompat_init();
extern void ksu_sucompat_exit();
extern void ksu_ksud_init();
extern void ksu_ksud_exit();

/**
 * @brief KernelSU模块的初始化函数
 *
 * 该函数在模块加载时被调用，负责初始化KernelSU模块的各个组件。
 *
 * @return 初始化结果
 */
int __init kernelsu_init(void);

/**
 * @brief KernelSU模块的退出函数
 *
 * 该函数在模块卸载时被调用，负责清理KernelSU模块的各个组件。
 */
void kernelsu_exit(void);

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);


## KCONFIG 文件

`KCONFIG` 文件定义了 KernelSU 模块的配置选项。以下是该文件的主要内容：

- `menu "KernelSU"`：定义了一个名为 KernelSU 的菜单。
- `config KSU`：定义了一个三态选项，用于启用 KernelSU 功能，依赖于 `OVERLAY_FS`，默认值为 `y`。
- `config KSU_DEBUG`：定义了一个布尔选项，用于启用 KernelSU 的调试模式，依赖于 `KSU`，默认值为 `n`。

## EXPORT_SYMBOL.TXT 文件

`EXPORT_SYMBOL.TXT` 文件列出了 KernelSU 模块中导出的符号。以下是该文件的主要内容：

- `register_kprobe`：用于注册 kprobe。
- `unregister_kprobe`：用于注销 kprobe。

/**
 * kprobe 是 Linux 内核中的一种调试机制，允许用户在内核函数的特定位置插入探针（probe）。
 * 这些探针可以在函数执行时捕获和记录信息，帮助开发者调试和分析内核行为。
 * 
 * 主要功能包括：
 * - 动态插入和移除探针
 * - 捕获函数入口和出口的参数和返回值
 * - 记录内核函数的执行路径
 * 
 * 使用 kprobe 可以在不修改内核源码的情况下，动态地监控和调试内核代码。
 */

/**
 * @file allowlist.c
 * @brief 该文件实现了一个允许列表（allowlist）系统，用于管理和控制应用程序的权限配置。
 *
 * 主要功能包括：
 * - 初始化和加载默认配置文件。
 * - 添加、删除和验证应用程序的权限配置。
 * - 持久化保存和加载允许列表。
 * - 显示当前的允许列表。
 * - 修剪无效的UID。
 *
 * 主要数据结构：
 * - `root_profile` 和 `non_root_profile`：分别表示root用户和非root用户的默认配置文件。
 * - `perm_data`：包含应用程序权限配置的结构体。
 * - `allow_list`：存储所有权限配置的链表。
 * - `allow_list_bitmap` 和 `allow_list_arr`：用于快速查找UID是否在允许列表中的位图和数组。
 *
 * 主要函数：
 * - `remove_uid_from_arr(uid_t uid)`：从数组中移除指定的UID。
 * - `init_default_profiles()`：初始化默认的root和非root配置文件。
 * - `ksu_show_allow_list()`：显示当前的允许列表。
 * - `ksu_get_app_profile(struct app_profile *profile)`：获取指定应用程序的权限配置。
 * - `ksu_set_app_profile(struct app_profile *profile, bool persist)`：设置应用程序的权限配置，并根据需要持久化保存。
 * - `__ksu_is_allow_uid(uid_t uid)`：检查指定的UID是否在允许列表中。
 * - `ksu_uid_should_umount(uid_t uid)`：检查指定的UID是否应该卸载模块。
 * - `ksu_get_root_profile(uid_t uid)`：获取指定UID的root配置文件。
 * - `ksu_get_allow_list(int *array, int *length, bool allow)`：获取允许列表中的所有UID。
 * - `do_save_allow_list(struct work_struct *work)`：将允许列表持久化保存到文件。
 * - `do_load_allow_list(struct work_struct *work)`：从文件加载允许列表。
 * - `ksu_prune_allowlist(bool (*is_uid_valid)(uid_t, char *, void *), void *data)`：修剪无效的UID。
 * - `persistent_allow_list()`：持久化保存允许列表。
 * - `ksu_load_allow_list()`：加载允许列表。
 * - `ksu_allowlist_init()`：初始化允许列表系统。
 * - `ksu_allowlist_exit()`：退出允许列表系统并释放资源。
 */

# SETUP.SH 脚本说明

此脚本用于设置或更新 KernelSU 环境，或清理之前脚本所做的修改。

## 用法

```sh
# 设置环境
./setup.sh --setup

# 更新环境
./setup.sh --update

# 清理环境
./setup.sh --clean
```

## 参数说明

- `--setup`：初始化并设置 KernelSU 环境。
- `--update`：更新 KernelSU 环境到最新版本。
- `--clean`：清理 KernelSU 环境，移除所有相关文件和配置。

## 示例

```sh
# 初始化 KernelSU 环境
./setup.sh --setup

# 更新 KernelSU 环境
./setup.sh --update

# 清理 KernelSU 环境
./setup.sh --clean
```

## 注意事项

- 在运行脚本之前，请确保具有相应的权限。
- 在生产环境中运行清理操作之前，请备份相关数据。


/*
 * SUCOMPAT.C 文件说明
 * 
 * 该文件实现了 su 兼容性功能，允许特定进程通过执行 'su' 命令获取 root 权限。
 * 
 * 包含的头文件：
 * - linux/dcache.h
 * - linux/security.h
 * - asm/current.h
 * - linux/cred.h
 * - linux/err.h
 * - linux/fs.h
 * - linux/kprobes.h
 * - linux/types.h
 * - linux/uaccess.h
 * - linux/version.h
 * - linux/sched/task_stack.h
 * - objsec.h
 * - allowlist.h
 * - arch.h
 * - klog.h
 * - ksud.h
 * - kernel_compat.h
 * 
 * 宏定义：
 * - SU_PATH: 定义 su 命令的路径
 * - SH_PATH: 定义 sh 命令的路径
 * 
 * 外部函数：
 * - escape_to_root(): 用于提升权限到 root
 * 
 * 内部函数：
 * - userspace_stack_buffer(): 将数据写入用户空间栈缓冲区
 * - sh_user_path(): 获取 sh 命令的用户空间路径
 * - ksud_user_path(): 获取 ksud 命令的用户空间路径
 * - ksu_handle_faccessat(): 处理 faccessat 系统调用
 * - ksu_handle_stat(): 处理 stat 系列系统调用
 * - ksu_handle_execveat_sucompat(): 处理 execveat 系统调用的 su 兼容性
 * - ksu_handle_execve_sucompat(): 处理 execve 系统调用的 su 兼容性
 * - ksu_handle_devpts(): 处理 devpts 相关操作
 * 
 * KPROBES 相关：
 * - sys_faccessat_handler_pre(): faccessat 系统调用的前置处理函数
 * - sys_newfstatat_handler_pre(): newfstatat 系统调用的前置处理函数
 * - sys_execve_handler_pre(): execve 系统调用的前置处理函数
 * - pts_unix98_lookup_pre(): pts_unix98_lookup 的前置处理函数
 * 
 * KPROBES 结构体：
 * - faccessat_kp: faccessat 系统调用的 kprobe
 * - newfstatat_kp: newfstatat 系统调用的 kprobe
 * - execve_kp: execve 系统调用的 kprobe
 * - pts_unix98_lookup_kp: pts_unix98_lookup 的 kprobe
 * 
 * 初始化和退出函数：
 * - ksu_sucompat_init(): 初始化 su 兼容性功能
 * - ksu_sucompat_exit(): 退出 su 兼容性功能
 */


/**
 * @file selinux.c
 * @brief SELinux相关功能的实现
 *
 * 这个文件实现了一些与SELinux相关的功能，包括转换域、设置SELinux的执行模式、获取当前任务的安全ID等。
 *
 * @includes
 * - selinux.h: SELinux相关的头文件
 * - objsec.h: 对象安全相关的头文件
 * - linux/version.h: Linux内核版本相关的头文件
 * - klog.h: 内核日志相关的头文件
 *
 * @defines
 * - KERNEL_SU_DOMAIN: 内核超级用户域的安全上下文
 * - DEVPTS_DOMAIN: devpts文件系统的安全上下文
 *
 * @functions
 * - transive_to_domain: 将当前任务转换到指定的安全域
 * - setup_selinux: 设置SELinux的安全域
 * - setenforce: 设置SELinux的执行模式
 * - getenforce: 获取SELinux的执行模式
 * - current_sid: 获取当前任务的安全ID（仅在内核版本低于5.10.0时定义）
 * - is_ksu_domain: 判断当前任务是否在超级用户域
 * - is_zygote: 判断给定的安全结构是否属于zygote域
 * - ksu_get_devpts_sid: 获取devpts文件系统的安全ID
 */


/**
 * @file throne_tracker.c
 * @brief 这个文件实现了一个用于跟踪和管理系统中APK包的内核模块。
 * 
 * 主要功能包括：
 * - 从APK路径中提取包名
 * - 通过遍历目录结构查找特定的APK包
 * - 管理和更新UID列表
 * - 确定和设置管理器UID
 * 
 * 主要结构体和函数：
 * - struct uid_data: 用于存储UID和包名的结构体
 * - struct data_path: 用于存储目录路径和深度的结构体
 * - struct apk_path_hash: 用于存储APK路径哈希值的结构体
 * - get_pkg_from_apk_path: 从APK路径中提取包名
 * - crown_manager: 设置管理器UID
 * - my_actor: 目录遍历回调函数
 * - search_manager: 搜索管理器APK包
 * - track_throne: 跟踪和管理系统中的APK包
 * - ksu_throne_tracker_init: 初始化函数
 * - ksu_throne_tracker_exit: 退出函数
 * 
 * 依赖的头文件：
 * - linux/err.h
 * - linux/fs.h
 * - linux/list.h
 * - linux/slab.h
 * - linux/string.h
 * - linux/types.h
 * - linux/version.h
 * - allowlist.h
 * - klog.h
 * - ksu.h
 * - manager.h
 * - throne_tracker.h
 * - kernel_compat.h
 */




/**
 * @file klog.h
 * @brief KernelSU 日志记录头文件
 *
 * 这个头文件定义了用于 KernelSU 日志记录的宏和配置。
 * 
 * - 包含了 <linux/printk.h> 头文件，用于内核日志记录功能。
 * - 如果已经定义了 pr_fmt 宏，则取消其定义，并重新定义 pr_fmt 宏，使其在日志消息前添加 "KernelSU: " 前缀。
 *
 * 这个文件的目的是为 KernelSU 提供统一的日志前缀，方便日志的过滤和识别。
 */























# KSUBOT.PY 中文说明文档

该脚本用于通过 Telegram 机器人将文件上传到指定的聊天中，并附带提交信息和工作流运行链接。

## 环境变量
- `BOT_TOKEN`: Telegram 机器人的令牌。
- `CHAT_ID`: 目标聊天的 ID。
- `MESSAGE_THREAD_ID`: 消息线程的 ID。
- `COMMIT_URL`: 提交的 URL。
- `COMMIT_MESSAGE`: 提交的信息。
- `RUN_URL`: 工作流运行的 URL。
- `TITLE`: 消息的标题。
- `VERSION`: 版本信息。

## 函数

### `get_caption()`
生成消息的标题和内容。如果消息长度超过 1024 字符，则仅返回提交的 URL。

### `check_environ()`
检查所有必要的环境变量是否已设置。如果任何一个变量未设置，则打印错误消息并退出程序。

### `main()`
主函数，执行以下步骤：
1. 检查环境变量。
2. 获取要上传的文件列表。
3. 使用 Telegram 机器人登录。
4. 生成消息标题和内容。
5. 将文件和消息发送到指定的聊天中。


