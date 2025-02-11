# STRIDE
## 使用STRIDE启动威胁建模

在有了可用的系统描述之后，我们可以开始威胁建模，这也正是STRIDE开始发挥作用的时候。

STRIDE代表Spoofing（欺骗）、Tampering（篡改）、Repudiation（否认）、Information disclosure（信息泄露）、Denial of service（拒绝服务）和Elevation of privilege（权限提升）。它们代表了针对信息系统最常见的六种安全威胁类型，可以类似理解为ISO 14971中医疗器械所面临的危害（harm）。

STRIDE由微软的安全研究人员于1999年开发，是目前使用最广泛的结构化威胁建模技术之一

![file](https://www.fanyamin.com/wordpress/wp-content/uploads/2024/11/image-1731740133647.png)


### 1. Spoofing 欺骗
防止非法获取或者伪造帐号信息， 访问我们的系统
- 非认证的用户不可访问系统
- 非授权的用户不可访问没有权限的模块， 不能进行非授权的操作、

### 2. Tampering 篡改
防止篡改或损坏系统中的数据
- 数据在传输层要安全, 要使用 HTTPS, TLS, DTLS 或者 SRTP 进行加密传输

### 3. Repudiation 否认
防止不承认对系统的攻击或者误用
管理员以及用户的关键操作要可追溯

### 4. Information Disclosure 信息泄露
  - 配置文件中的帐户密码不可使用明文
  - PII (Personal Insensitive Information ) 安全
  - PII 在服务器的日志或数据库中不可随意存放   -  密码必须经过不可逆的哈希之后再存 
  - 个人的邮件, 电话等信息均不可存放在日志文件中, 只可以放在有访问限制的数据管理系统中
  - 不可泄露用户，医生及患者的个人隐私
  - 数据在应用层要有上述 “3A” 的保护

### 5. Denial of Service 拒绝服务
防止非法的攻击导致服务不可用, 相应的措施有
- 通过防火墙、安全访问区、访问控制列表和端口访问的设置防止未授权访问、篡改和拒绝服务（DoS）攻击
- 对于非法访问的错误请求实施 rate limit and block policy

### 6. Elevation of Priviledge 特权提升
- 未经授权提升权限级别
- 未经授权访问到敏感的信息