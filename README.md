# 2019 Advanced Computer Networks Homework 3

## Rules

1. 請在 Ubuntu 18.04 下完成本次作業。
2. 請使用 C 或是 Python 語言完成本次作業，如果使用C語言實作，請提供 Makefile 來編譯你的程式。
3. 禁止抄襲任何人的作業。

4. 請將作業壓縮成 zip 或 tar 檔案，並於期限內上傳至中山網路大學<http://cu.nsysu.edu.tw/>，命名規則為 **"Student ID_TCPIP_HW３"** 。

    > Example : "D073040002_TCPIP_HW３"

5. 如果不遵守上述規則，作業以０分計算。
6. 有任何問題請 email 至 net_ta@net.nsysu.edu.tw，或於11:00 A.M. – 5:00 P.M. 到網路系統實驗室(F5018)詢問。

Deadline：2019/10/30(Wed.) 23:59

## Hint

It is important

1. structure of arp_packet in “arp.h”.
2. ioctl() and structure of ifreq.
3. htons() and ntohs().
4. Wireshark can help you know what the packet fields are.

## Motivation

To learn how to receive, build and send Ethernet packets. You will
know how ARP works by this homework.

## Part 1

Use the main.c which is included in attachment to make an ARP packet capture program.

In order to make program in a common format, please refer to "arp.h" when you do this homework.

You can consult your book on page 170 for ARP packet format. Besides, you should implement the filter in this part as well.

### Request

Show usage when the command with insufficient or excessive parameters. You need to validate IP and MAC address format.

You also need to show error message when the program isn’t executedby superuser privileges.

Use `./arp - help` to show all commands.

Use `./arp - l - a` command to show all of the ARP packets.

Use `./arp - l <ip address>` command to implement the filter work. Thus, it should show specific ARP packets.

## Part 2

Send an ARP request and receive the ARP reply to analyze the packet and find the MAC address of the specific IP.

Generally, we usually find the MAC address by cleaning the ARP cache, pinging the IP, capturing the packets with something like Wireshark and analyze the packet by yourself.

In this part, you should do the same thing by programming.

### Request

Fill an ARP request packet and send it by broadcast to query the MAC address of the specific IP address.

If the IP is offline, you might not find its MAC address, so you have to check the connection before your homework executed.

You can use ifconfig on Linux or ipconfig /all on Windows to check the MAC address of the computer.

Also, you have to install the Wireshark to reconfirm your packets sent and received.

If you obey the order of the homework part, you can use the filter ARP list of the part 1 to detect whether the request packet which part 2 sends is sent successfully or not.

## Part 3

Make an ARP daemon, it can reply a MAC address when it receive specific IP address.

### Request

You CANNOT use example IP (140.117.171.172) when you test your homework.

Please check out the notice first when you start third part, it is very important.

When program receive an ARP request for 140.117.171.172 (this is example IP), send a 00:11:22:33:44:55 reply.

You can use another computer and ping 140.117.171.172 (this is

example IP), it will send an ARP request packet. Your program will send an ARP reply in the same time. (If it’s not work, you can clear your ARP cache first.)

You can use Wireshark tool to capture the packet you made. There have two ARP packets, one is from true target (70:f3:95:1b:8c:55), another is fake (00:11:22:33:44:55).

## Notice

1. In the Part 2 and Part 3, TAs will use Wireshark to verify the ARP reply you made, so make sure your ARP format is as same as the above picture.

2. The packets you send should fully follow the ARP packet standard, every filed should be correct and not be empty.

    > The above example is not correct, because of missing target IP address.

3. ARP spoofing is illegal! Do not attack device of others!

4. You should build an ARP spoofing target by yourself. For the above example, spoofing target is 140.117.171.172.

5. This homework require superuser privileges, so you should build your own Ubuntu Linux 18.04 by yourself, we will not provide server’s superuser privileges.

6. In order to make program in a common format, please make your input as follow:

    `./arp –help`

    `./arp –l –a`

    `./arp –l <filter_ip_address>`

    `./arp –q <query_ip_address >`

    `./arp <fake_mac_address> <target_ip_address>`
