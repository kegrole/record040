# k8saudit

纯 Python 标准库实现的 Kubernetes 工作负载安全审计器。仓库内置一个最小
YAML 子集解析器（k8saudit/yamlmini.py），不依赖任何第三方包。

## 运行方式

    python -m unittest test_k8saudit -v
    python -m k8saudit.cli \
      --manifests demo/manifests \
      --rules demo/rules.yaml \
      --out out/report.json

第二条命令会在 out/report.json 写出完整报告，并在 stdout 打印一行摘要：
工作负载数、问题总数，以及按规则 ID 统计的命中分布。

## 支持的 YAML 子集

解析器基于缩进，刻意只覆盖清单与规则文件需要的语法：

- 嵌套映射（key: value）与块列表（- item），包括“列表里是映射”的
  容器/卷结构；
- 块标量：字面量 |（保留换行）与折叠 >（换行折叠为空格、空行保留为
  换行），支持 clip（默认）、strip（-）、keep（+）三种收尾；
- 单引号与双引号标量（双引号支持 \n、\t 等转义，单引号内两个单引号表示
  一个引号）；
- 行内流列表，如 capabilities: [SYS_ADMIN, NET_ADMIN] 与空列表 []；
- 整行注释与行尾注释；
- 多文档 --- 分隔（一个文件可放多份清单）；
- 标量类型：字符串、整数、浮点、布尔（true/false、yes/no）、空值
  （null、~、留空）。

不支持 YAML 锚点/别名、标签（!!）、行内映射 {}、多文档合并等高级特性。

## 工作负载与目标模型

支持 Deployment、StatefulSet、DaemonSet、Pod 四种 kind，自动从
spec.template.spec 或 spec 取出 Pod 模板，并展开为以下审计目标：

- pod：宿主命名空间、Pod 级 securityContext；
- container / init_container：普通容器与 init 容器，容器级
  securityContext 会与 Pod 级合并（容器级优先）；
- capability：每个容器 securityContext.capabilities.add 中的单项能力；
- volume：声明了 hostPath 的每个卷。

## 规则文件格式

规则完全由数据驱动，代码只提供通用算子，审计项集合没有写死在代码里。
删除一条规则，对应问题就不再报；修改 value，判定结论随之改变。

    rules:
      - rule: privileged                  # 报告中使用的稳定规则 ID
        description: 文字说明              # 可选的人类可读说明
        severity: high                    # 原样写入 finding 的严重级别
        scope: any_container              # 见下方 scope 取值
        path: securityContext.privileged  # 目标内的点分查找路径
        operator: equals                  # 见下方算子
        value: true                       # 期望值；可省略表示 null
        evidence: "container {context.container} ..."  # 证据模板

- scope：pod、container、init_container、any_container（同时匹配
  普通与 init 容器）、capability、volume，也支持写成 scope 列表；
- operator：equals、not_equals、in、not_in、contains、not_contains；
  路径不存在时值为 null，因此可以用 equals 配合 null 表达“字段缺失”；
- evidence：Python str.format_map 模板，可直接引用目标字段（如
  hostPath、capability、securityContext.runAsUser），也可用
  context.workload、context.container 等上下文；缺失字段渲染为空串。

## 内置审计项含义（demo/rules.yaml）

| 规则 ID | 审计点 | 说明 |
| --- | --- | --- |
| privileged | securityContext.privileged | 特权容器，基本等同于宿主 root |
| allow-privilege-escalation | allowPrivilegeEscalation | 允许子进程提升权限 |
| run-as-non-root-missing | runAsNonRoot | 未显式要求非 root 运行 |
| run-as-root-user | runAsUser | 显式以 UID 0 运行 |
| host-network / host-pid / host-ipc | hostNetwork/hostPID/hostIPC | 共享宿主命名空间 |
| hostpath-volume | volumes[].hostPath | 点名具体宿主路径（如 /var/run/docker.sock） |
| dangerous-capabilities | capabilities.add | 点名具体能力名（如 SYS_ADMIN），清单由规则中的 value 决定 |
| writable-root-filesystem | readOnlyRootFilesystem | 根文件系统非只读 |
| seccomp-profile-missing | seccompProfile.type | 未配置 seccomp 配置档 |

## 报告结构

out/report.json 顶层包含 summary 与 workload_reports。每条工作负载
报告固定包含 workload、kind、namespace、findings 四个字段；每条
finding 固定包含 rule、evidence、severity，其中 evidence 是带具体
路径/能力名/容器名的原文证据。

## 代码布局

- k8saudit/yamlmini.py：最小 YAML 子集解析器；
- k8saudit/manifest.py：扫描目录、加载四类工作负载；
- k8saudit/workload.py：合并 securityContext 并展开审计目标；
- k8saudit/rules.py：规则加载、通用算子与单条规则求值；
- k8saudit/report.py：聚合 findings、生成 JSON 报告与 stdout 摘要；
- k8saudit/cli.py 与 k8saudit/__main__.py：命令行入口；
- tests/test_k8saudit.py：unittest 测试；仓库根的 test_k8saudit.py
  是让 python -m unittest test_k8saudit -v 可直接运行的兼容入口。
