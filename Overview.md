# Overview Firewall
- [Overview Firewall](#overview-firewall)
  - [Types of Firewalls](#types-of-firewalls)
    - [Simple/Stateless Packet Filter Firewall](#simplestateless-packet-filter-firewall)
    - [Stateful Packet Filter Firewall](#stateful-packet-filter-firewall)
    - [Application-Level Firewall - Application-Proxy Gateways](#application-level-firewall---application-proxy-gateways)
    - [Next-Gen Firewall](#next-gen-firewall)
  - [Web Application Firewall](#web-application-firewall)
    - [Compare: NGFW and WAF](#compare-ngfw-and-waf)
  - [API Firewall](#api-firewall)
  - [Database firewall - MySQL Enterprise Firewall](#database-firewall---mysql-enterprise-firewall)
  - [Modesecurity](#modesecurity)
    - [Example - Pfsense](#example---pfsense)
    - [Example - OPNSense](#example---opnsense)
  - [Example](#example)

## Types of Firewalls

- Simple Packet Filter Firewall 
- Stateful Packet Filter Firewalls 
- Application-Proxy Gateways hay Application-Level Firewall
- Next Generation Firewalls 


### Simple/Stateless Packet Filter Firewall
- Kiểm tra gói tin qua firewall bằng cách so sánh nó với những nguyên tắt (rule) đã đươc đặt ra, để guyết định gói tin đó được cho phép hay bị từ chối.
- Source, Destination IP
- Protocol
- Source, Destination Port
=> Hoạt động chủ yếu cở Layer 2, 3

![](Image/Day018_Stateless_Firewall.png)


### Stateful Packet Filter Firewall
- Tính năng của Packet Filtering Firewall
- Có thêm phần lưu lại trang thái (stateful table)
- Stateful table
- Hoạt động ở layer 2,3,4
- Những khắc phục so với Simple Packet Filter Firewalls


![](Image/Day018_Statefull_Firewall.png)



### Application-Level Firewall - Application-Proxy Gateways
- Deep Packet Inspection: kiểm tra chi tiết gói tin nên có khả ngăn chặn các ứng dụng Instant Message, Peer to Peer,
- Có khả năng xác thực
- UserID và Password
- Hardware hoặc Software Token 
- Source Address
- Biometric

![](Image/Day018_Application_Firewall.png)

### Next-Gen Firewall 

1.	Xác định các ứng dụng (applications) bất kể là port, protocol, hay chiến thuật né tránh hoặc SSL 
2.	Xác định User bất kể IP address
3.	Khả năng hiển thị chi tiết và kiểm soát chính sách đối với quyền truy cập / chức năng của ứng dụng
4.	Bảo vệ trong thời gian thực chống lại các mối đe dọa được nhúng trên các ứng dụng
5.	Multi-gigabit, triển khai trực tuyến mà không làm giảm hiệu suất

Định nghĩa:
* Standard firewall capabilities like stateful inspection 
* Integrated intrusion prevention
* Application awareness and control to see and block risk apps
* Threat intelligence source
* Upgrade paths to include future information feeds
* Techniques to address evolving security threats


Security
* Deep packet inspection 
* Intrusion prevention 
* SSL Decryption 

Application Awareness 
* Fingerprint applications 
* Identify Users 
* Visualize traffic

Performance 
* High Throughput
* No latency
* Any size network 

Nguyên lý hoạt động
* Deploy
* Inbound
* Outbound

![](Image/Day018_Next_GEN_Firewall.png)


## Web Application Firewall 
Định nghĩa
- Filter, monitors and blocks HTTP/HTTPS traffic to and from a web application
- Sự khác biệt giữa WAF và tường lửa thông thường
Tại sao cần WAF
- Khi các công ty và users ngày càng phụ thuộc vào các ứng dụng web (Web Application), chẳng hạn như email dựa trên web hoặc chức năng e-Commerce, các cuộc tấn công nhằm vào lớp ứng dụng gây ra rủi ro lớn hơn cho năng suất và bảo mật. Do đó, WAF thật sự rất quan trọng nhằm bảo vệ khỏi các mối đe dọa liên quan đến bảo mật web.
- WAF bảo vệ bạn khỏi các cuộc tấn công độc hại, chẳng hạn như: 
  - SQL Injection: một công nghệ hack được sử dụng để trích xuất thông tin nhạy cảm từ database. 
  - Remote Code Execution: một kỹ thuật tấn công cho phép một người thực thi code từ xa sau khi user chấp nhận file độc hại. 
  - Cross-site scripting: khi script độc hại được đưa vào code của một trang web đáng tin cậy khác, sẽ cho phép dữ liệu nhạy cảm của user như cookie bị truy cập. 
- Những mối đe dọa này có thể xâm nhập và làm tê liệt trang web của bạn, làm giảm hiệu suất và khiến doanh nghiệp của bạn bị mất dữ liệu.
Top 10 OWASP
- Broken Access Control
  - moves up from the fifth position; 94% of applications were tested for some form of broken access control. The 34 Common Weakness Enumerations (CWEs) mapped to Broken Access Control had more occurrences in applications than any other category.

- Cryptographic Failures 
  - shifts up one position to #2, previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause. The renewed focus here is on failures related to cryptography which often leads to sensitive data exposure or system compromise.
- Injection 
  - slides down to the third position. 94% of the applications were tested for some form of injection, and the 33 CWEs mapped into this category have the second most occurrences in applications. Cross-site Scripting is now part of this category in this edition.
- Insecure Design 
  - is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to “move left” as an industry, it calls for more use of threat modeling, secure design patterns and principles, and reference architectures.
- Security Misconfiguration 
  - moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration. With more shifts into highly configurable software, it’s not surprising to see this category move up. The former category for XML External Entities (XXE) is now part of this category.
- Vulnerable and Outdated Components 
  - was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores.
- Identification and Authentication Failures 
  - was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping.
- Software and Data integrity Failures 
  - is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. Insecure Deserialization from 2017 is now a part of this larger category.
- Security Logging and Monitoring Failures 
  - was previously Insufficient Logging & Monitoring and is added from the industry survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn’t well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics.
- Server-Side Request Forgery SSRF
  - is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it’s not illustrated in the data at this time.


Cách Web Application Firewall hoạt động
- WAF được triển khai trước các ứng dụng web và phân tích lưu lượng HTTP – kiểm tra cả request GET và POST nhằm phát hiện và chặn bất kỳ thứ gì độc hại.
- Không giống như tường lửa (Firewall) thông thường chỉ đóng vai trò như một cổng an toàn giữa các server, WAF là một biện pháp bảo mật ứng dụng được đặt giữa Web Client và  Web Server.
- Các cuộc tấn công độc hại đến máy tính thường được tự động hóa. Những loại tấn công này rất khó phát hiện vì chúng thường được thiết kế để bắt chước giống lưu lượng truy cập của con người và không bị phát hiện.
- WAF thực hiện kiểm tra chi tiết mọi request và response đối với tất cả các dạng lưu lượng truy cập web phổ biến. Việc kiểm tra này giúp WAF xác định và chặn các mối đe dọa, ngăn chúng xâm nhập vào server.
Web Attack Damage 
- Loss of sensitive data
- Defaced Web Site
- Lost Business 
  - Web site blocked by search engines and AV software 
  - Loss of customer trust


Why we need to use WAF?


![](Image/Day018_Example_WAF.png)


![](Image/Day018_WAF_Flow.png)

### Compare: NGFW and WAF

NGFW and WAF
-  WAF (web application firewall):
   - A web application firewall (WAF) is a type of firewall that monitors, filters or blocks HTTP traffic to and from a web application. It differs from a normal firewall in that it can filter the content of specific web applications, whereas a network firewall protects traffic between servers. By inspecting HTTP traffic, a WAF protects web applications against attacks such as SQL injection, XSS and cross-site request forgery (CSRF).
   - It is usually aware of the user, the session and the application and knows the web applications behind it and the services they offer. The WAF can therefore be seen as an intermediary between the user and the application itself, which analyses all communications before they reach the application or the user. Traditional WAFs ensure that only permitted actions can be performed (depending on the security policy). For many organisations, WAFs are a reliable first line of defence for applications, especially to protect against the OWASP Top 10.
- NGFW (next generation firewall)
  - It monitors traffic going out to the Internet (via websites, email accounts and SaaS). In short, it protects the user (versus the web application). The NGFW enforces user-based policies and adds context to security policies, in addition to other functions such as URL filtering, anti-virus/anti-malware, and potentially, its own intrusion prevention systems (IPS). While the WAF is typically a reverse proxy (used by servers), the NGFW is typically a forward proxy (used by clients as a browser).
  - Traditional firewalls are divided into three functions: Filter, inspect and allow or disallow. While NGFW firewalls offer a range of additional protection such as detection and prevention of malware and DDoS attacks, WAFs offer protection against web threats (such as phishing hack attempts).



## API Firewall 

![](Image/Day018_API_Firewall.png)

- API firewall là một proxy nhanh và nhẹ để kiểm tra request và response API dựa trên các quy tắc của OpenAPI/Swagger. Nó được thiết kế để bảo vệ các RestAPI endpoint, trong môi trường cloud-native.
-  Cơ chế hoạt động: sử dụng các model security để cho phép các request và response đúng với những rule trong file định nghĩa (file rule) và từ chối mọi thứ không đúng yêu cầu
   -  Một request được gửi sẽ đi đến API Firewall trước
   -  Firewall dựa theo file định nghĩa để kiểm tra request này có hợp lệ hay không
   -  Nếu hợp lệ, sẽ được cho phép chuyển đến API hoặc Microservice để thực thi và nhận lại response
   -  Nếu không hợp lệ, sẽ bị từ chối (bị block hoặc log lại tùy vào chế độ hoạt động)
-  Một số tính năng
   -  Chặn các request sai định nghĩa/độc hại
   -  Ngăn chặn rò rỉ dữ liệu từ các response sai định nghĩa
   -  Phát hiện các Shadown API
- [ ] https://docs.42crunch.com/latest/content/concepts/api_firewall.htm
- [ ] Open Source API Firewall by Wallarm: https://github.com/wallarm/api-firewall

## Database firewall - MySQL Enterprise Firewall
•	MySQL Enterprise Edition includes MySQL Enterprise Firewall, an application-level firewall that enables database administrators to permit or deny SQL statement execution based on matching against lists of accepted statement patterns. This helps harden MySQL Server against attacks such as SQL injection or attempts to exploit applications by using them outside of their legitimate query workload characteristics.
•	Each MySQL account registered with the firewall has its own statement allowlist, enabling protection to be tailored per account. For a given account, the firewall can operate in recording, protecting, or detecting mode, for training in the accepted statement patterns, active protection against unacceptable statements, or passive detection of unacceptable statements. The diagram illustrates how the firewall processes incoming statements in each mode.


![](Image/Day018_Database_Firewall.png)

![](Image/Day018_SQL_Database_Firewall.png)


Multiple operating modes:
* Recording-Allow – exes queries & generates results for queries match an allowlist.
* Protecting-Block – blocks queries don’t match an allowlist.
* Detecting-Detect - exes queries don’t match an allowlist + notifies admins of policy violations.
* Tường lửa cơ sở dữ liệu (CSDL): là một loại WAF (thiết bị / phần mềm, ảo hóa) dùng giám sát CSDL để xác định và bảo vệ chống lại các cuộc tấn công nhắm đến CSDL (đánh cắp thông tin nhạy cảm trong CSDL) và kiểm tra hoạt động truy cập vào CSDL thông qua log. Nó có thể được triển khai in-line với máy chủ CSDL (ngay trước) / gần cổng mạng (bảo vệ nhiều CSDL trong nhiều máy chủ). Một số máy chủ CSDL hỗ trợ các agent có thể được cài đặt trong chính máy chủ CSDL để theo dõi các sự kiện CSDL cục bộ. Tường lửa dựa trên phần cứng hỗ trợ giám sát máy chủ / mạng mà không cần tải bổ sung thứ gì trên các máy chủ CSDL. Cả thiết bị phần cứng và tác nhân phần mềm có thể được triển khai để hoạt động đồng thời.
* MySQL Enterprise Firewall: là 1 plugin của MySQL Enterprise Edition. Chỉ cần tải MySQL Enterprise Edition về và enable plugin tường lửa là có thể sử dụng. Đây là tường lửa cấp ứng dụng với tính năng bảo vệ theo thời gian thực bằng cách giám sát, cảnh báo và ngăn chặn hoạt động tác động trái phép đến CSDL mà không có bất kỳ thay đổi nào với ứng dụng.


Các chế độ hoạt động:
* Ghi - Thực thi Các câu lệnh SQL được và tổng quát hóa để xây dựng 1 allowlist.
* Bảo vệ - Các câu lệnh SQL không khớp với allowlist bị chặn thực thi.
* Phát hiện - Các câu lệnh SQL không khớp với allowlist được thực thi và thông báo cho quản trị viên các hoạt động đáng ngờ.


Cơ chế hoạt động:
* Máy chủ MySQL nhận kết nối từ máy khách và các câu lệnh SQL. Nếu tường lửa được bật, nó sẽ nhận các câu truy vấn này và xem xét có chấp nhận câu lệnh hay không, dựa vào đó máy chủ sẽ thực thi câu lệnh hoặc trả về lỗi cho máy khách.       	
* Tường lửa sử dụng profile để xác định có cho phép thực thi câu lệnh hay không. Profile bao gồm:
  * Một allowlist: Mỗi tài khoản MySQL được đăng ký với tường lửa đều có allowlist riêng, cho phép bảo vệ được điều chỉnh cho phù hợp với từng tài khoản.
  * Chế độ hoạt động: ghi, bảo vệ / phát hiện, để huấn luyện cho allowlist các mẫu câu truy vấn hợp lệ, bảo vệ chủ động chống lại / phát hiện thụ động các truy vấn không hợp lệ.
  * Phạm vi áp dụng:
  * Dựa trên tài khoản: 1 profile - 1 tài khoản cụ thể.
  * Nhóm: nhiều tài khoản là thành viên, allowlist áp dụng như nhau cho tất cả các thành viên.

![](Image/Day018_Databse_Firewall_flow.png)


Tính năng:
* Chặn tấn công SQL Injection
* Phát hiện xâm nhập CSDL
* Giám sát mối đe dọa trong thời gian thực
* Chặn lưu lượng truy cập đáng ngờ
* Bảo vệ minh bạch
* Ghi log
* Tự học và xây dựng allowlist.
* Hiệu suất cao 


Deploy
* Vị trí đặt WAF 
  * Các thiết bị WAF cúng thường được đặt sau tường lửa mạng và trước máy chủ ứng dụng web. Việc đặt WAF được thực hiện sao cho tất cả các lưu lượng đến ứng dụng web cần qua WAF trước. Tuy nhiên, đôi khi cũng có ngoại lệ khi WAF chỉ được dung để giám sát cổng đang mở trên máy chỉ web. Ngoài ra, các chương trình WAF còn được cài đặt trực tiếp lên máy chỉ web và thực hiện các chức năng tương tự như các thiết bị WAF là giám sát các lưu lượng đến và ra khỏi ứng dụng web

## Modesecurity 
WAF and NGFW 
* What is the Difference Between Web Application Firewall (WAF) and Next-Generation Firewall (NGFW)?
  * Firewalls represent a crucial piece of technology that monitors and filters incoming or outgoing internet traffic with the ultimate goal of protecting against threats and preventing sensitive data leaks. Businesses and organizations rely on these devices to work consistently and reliably so that they can secure critical resources for infiltration.

  * There are many kinds of firewalls available, and each type has its own functionality and purpose. In this article, we will compare web application firewalls (WAFs) and next-generation firewalls (NGFWs), and then explore ways to include them as part of a comprehensive security solution.

* What Is a Web Application Firewall (WAF)?
  * A web application firewall (WAF) is a type of firewall that understands a higher protocol level (HTTP or Layer 7) of incoming traffic between a web application and the internet. It is able to detect and respond to malicious requests before they are accepted by web applications and web servers, thus giving businesses an extra layer of security.

  * When using WAFs to protect web applications, you typically define rules that either allow, block or monitor web requests based on certain criteria. For example, you can specify a rule that you need to block all incoming requests from a particular IP or only requests that contain specific HTTP headers or vulnerabilities. If you just want to monitor traffic, you can set up monitors that count certain endpoints. This flexibility allows security administrators to quickly record what is being requested and block unauthorized or unwanted requests when incidents and compromises occur.

  * Due to the fact that WAFs understand a higher level of traffic, they are able to block web application attacks (among other benefits). Many of these attacks are closely related to the OWASP Top 10 list, including cross-site scripting (XSS) attacks, SQL injection, denial-of-service (DoS), and the leakage of credentials or unsafe information.

* What Is an NGFW? 
  * A next-generation firewall (NGFW) is a type of application firewall that combines the best features of a traditional network firewall and a web application firewall. It typically acts as a firewall that blocks incoming requests by inspecting the network layer packets, but it also has additional inspection capabilities that unlock novel ways to block unwanted traffic on your private network.

  * Some of these capabilities relate to TLS inspection and termination, intrusion detection and prevention, threat intelligence, and the ability to configure advanced filtering rules based on the contents of the traffic or the URLs. The main benefit of this flexibility is that it allows security admins to handle more advanced scenarios and block more sophisticated threats that stem from coordinated attack vectors.

  * Now that you understand the fundamental concepts behind WAFs and NGFWs, we will explain their similarities and differences.

* The Similarities and Differences Between WAFs and NGFWs
  * It’s fair to say that there is a bit of overlap between WAFs and NGFWs. They both employ rules and policy engines to filter incoming traffic and act based on certain criteria. Both are easier to run these days, and depending on the vendor offering, you won’t need to purchase dedicated hardware to enjoy those features.

  * You might think that they overlap because they both work on application-layer protocols – Layer 7 in particular. That’s true. You can think of NGFWs as extensions of traditional firewalls with the added ability to process traffic from OSI Layers 3-4 and 7 and leverage that information to take action before it reaches an inner layer closer to the application.

  * Their key differences lie in their core responsibility models and overall capabilities. NGFWs capture more network traffic context so that they can prevent incoming attacks before they reach the network layer. They can also combine threat intelligence engines to assist in the decision-making process. WAFs, on the other hand, are confined to the application layer, so they specialize in preventing common web-based attacks like XSS and SQL injections. WAFs cannot be used as primary firewalls for your network, but they are ideal to protect your web applications exposed to the internet. 

* When to Use WAFs vs. NGFWs
  * You want to use web application firewalls (WAFs) for the following reasons:

    * They protect against attacks that are specific to the application layer. WAFs can inspect application-layer traffic, and they also have the ability to protect against common application-layer attacks. Examples include SQL injection, XSS, DDoS and others on the OWASP Top 10 list.

    * They can help you meet compliance requirements. For example, PCI DSS discusses how WAFs can help meet option 2 of requirement 6 in conjunction with secure coding practices.

    * Next-generation firewall (NGFW) solutions protect against both network- and application-wide attacks. Their key characteristics are:

    * They can monitor many layers (OSI 3-4 and 7). This gives them better context and insight into the type of attack. For example, they can determine which application each packet targets and put extra controls in place. Therefore, an NGFW can be used as a primary firewall.

    * They include sophisticated tools and features. NGFWs can leverage internal or external services in order to prevent attacks. For example, they can load threat intelligence data and automatically reconfigure rules based on new updates.

    * They can inspect SSL traffic. NGFWs can act as SSL termination proxies, so they can inspect incoming and outgoing encrypted traffic before it reaches its destination. You can read more about this feature in this related article.

  * Now that you have a fair idea of when to use a WAF versus a NGFW, let’s see how you can use them both to provide a comprehensive and in-depth defense solution.

* How Do WAFs and NGFWs Complement Each Other?
  * Given that WAFs are dedicated to protecting web application traffic, they represent the ideal option for protecting web servers. WAFs are not the ultimate solution when it comes to comprehensive security, though, so it’s best if you can combine them with NGFWs.

  * The ideal holistic defense strategy is to have a WAF configured to protect against the OWASP Top 10 attacks with an NGFW acting as a traditional network firewall that is able to detect and prevent certain attacks before they reach the WAF. Using advanced capabilities like IDS/IPS and threat modeling, NGFWs can filter out a massive percentage of attacks and leave the rest for the WAFs to tackle.

* What Customers Should Consider When Searching for a Web Application Security Solution
  * When searching for a web application security solution, you should consider several factors. First, you need a trusted and reliable vendor that offers a holistic set of tools and services for protecting your web applications. Palo Alto Networks is one such vendor that offers a comprehensive and easy-to-use set of firewalls, including NGFWs  and Web Application and API Security platform, which includes a built-in WAF.

  * Second, you need great documentation and excellent technical support. Developers and security admins rely on reference documentation so they can understand how to properly configure the firewalls that adhere to their security policies. Documentation needs to be up to date, accurate and easily accessible so any implementation of incoming requests can be done efficiently with minimal risk of misconfiguration. Palo Alto Networks docs site is a robust and easy-to-navigate developer documentation site with deep and detailed listings of the features, how to set them up, and version information for compatibility.




### Example - Pfsense 

![pfsense with LDAP](Image/Day018_pfsense_with_LDAP.png)
- abc lý thuyết
### Example - OPNSense 


:books: --> [Practices here](./Day027_Project_1_Part_1_Building_Firewall_Pfsense_OPNsense.md)



- Rock-soild FreeBSD - HardenedBSD 
  - FreeBSD: FreeBSD is a free and open source operating system
    - It is a Unix-like system
- Features and common deployments
  - 802.1Q virtual LAN (VLAN) support
  - Stateful inspection firewall
  - Traffic shaper
  - DHCP server and relay
  - DNS forwarder
  - Dynamic DNS (DDNS)
  - Intrusion Prevention System (IPS)
  - Forwarding caching proxy
  - Virtual Private Network (VPN)
  - Built-in reporting and monitoring tools
  - QoS
  - Two-Factor Authentication (2FA)
  - Open VPN
  - IPSec
  - High availability (CARP)
  - A captive portal 
  - Proxy 
  - A web filter 
  - IDPS
  - Netflow: https://www.youtube.com/watch?v=4hM-mrQ2rU0
- Install OPNsense -> [here](./Day027_Project_1_Part_1_Building_Firewall_Pfsense_OPNsense.md)
  - Versions and requirements
  - Downloading and installing OPNsense
  - Updates and plugins
  - SSH and CLI access
  - FreeBSD packages 
- Configuring an OPNsense Network
- System Configuration 
  - Managing users and groups 
  - External authentication 
  - Certificates - a brief introduction 
  - General settings 
  - Advanced settings 
  - Configuration backup
- Firewall
  - Stateful firewall
  - Packet Filter Firewall
  - Firewall aliases 
  - Firewall rules 
  - Fir troubleshooting
- Network Address Translation (NAT)
  - NAT concepts 
  - Port forwarding 
  - Outbound NAT 
  - One-to-one NAT



## Example 

![](Image/Day018_Example_architecture_network.png)
