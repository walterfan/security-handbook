# Threat Modelling

## 威胁风险消除方法

先问自己四个问题

### 1. What are we working on?

什么系统, 什么应用, 什么业务, 要把限界上下文搞清楚

### 2. What can go wrong?

![file](https://www.fanyamin.com/wordpress/wp-content/uploads/2024/11/image-1731749702390.png)

### 3. What are we going to do about it?
  1. 定义业务和系统范围：
明确你的业务目标和系统的范围，了解系统的主要功能和组件

  2. 创建数据流图（DFD）：
制作一个数据流图，它展示了系统中数据流动的路径，包括输入、处理和输出过程。

  3. 识别实体和信任边界：
确定系统中的用户、数据、进程和其他实体，以及它们之间的信任关系。

  4. 应用 STRIDE 分类：
根据 STRIDE 模型的六个分类，逐一检查每个组件和数据流，识别可能的威胁

![file](https://www.fanyamin.com/wordpress/wp-content/uploads/2024/11/image-1731756653488.png)

  5. 评估威胁的可能性和影响：
对每个已识别的威胁进行风险评估，考虑其可能性和对系统的潜在影响。

  6. 设计缓解措施：
针对每个威胁设计缓解措施，这可能包括技术控制、流程改进或政策变更。

  7. 优先级排序：
根据威胁的风险等级和业务影响，对缓解措施进行优先级排序。
    按照 bug 的分级 S1(block issue) , S2(critical), ... 为以下威胁和漏洞报 security bug
  8. 实施控制措施：
实施选定的缓解措施，并确保它们不会对系统的其他部分产生负面影响。
    Fix  security bugs
  9. 验证和测试：
验证控制措施是否有效，并进行必要的测试以确保它们按预期工作。
    Verify the security bugs' solution
  10. 文档和沟通：
记录整个威胁建模过程和结果，与团队成员和利益相关者沟通，确保透明度和理解。
    Review this document, and get agreement for the security issue and solutioni
  11. 监控和迭代：
持续监控威胁环境的变化，并定期回顾和更新威胁模型。
    每个 sprint/release 前更新威胁模型

### 4. Did we do a good enough job?
  
  - 传输层: 启用 HTTPS, TLS, DTLS 和 SRTP
  - 应用层: 做好 3A , 防范威胁, 消除漏洞
  - ...
  
