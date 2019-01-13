/*
 * @Author: yu.tongqing 
 * @Date: 2019-01-13 10:05:36 
 * @Last Modified by: yu.tongqing
 * @Last Modified time: 2019-01-13 13:52:36
 */
#ifndef _PCAP_READER_H_
#define _PCAP_READER_H_

#include <string>
#include <memory>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include "net_header.h"

class rtp_packet
{
public:
    std::string data;
    rtp_header_t header;
};

class pcap_reader
{
public:
    pcap_reader(std::string& filename);
    ~pcap_reader();
    std::shared_ptr<rtp_packet> get_next_rtp(const char* src_ip, const char* dst_ip, const u_short src_port, const u_short dst_port);
private:
    pcap_t* m_pcap_handler;
};

#endif