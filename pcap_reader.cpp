/*
 * @Author: yu.tongqing 
 * @Date: 2019-01-13 10:09:27 
 * @Last Modified by: yu.tongqing
 * @Last Modified time: 2019-01-13 13:57:48
 */

#include "pcap_reader.h"

pcap_reader::pcap_reader(std::string& filename)
{
    char error[100];
    m_pcap_handler = pcap_open_offline(filename.c_str(), error);
    if(!m_pcap_handler)
    {
        printf("open file error: %s\n", error);
    }
}

pcap_reader::~pcap_reader()
{
    if(m_pcap_handler)
    {
        pcap_close(m_pcap_handler);
    }
}

std::shared_ptr<rtp_packet> pcap_reader::get_next_rtp(const char* src_ip, const char* dst_ip, const u_short src_port, const u_short dst_port)
{
    const unsigned char *p_packet_content = NULL;
    struct pcap_pkthdr protocol_header;

    //get next packet
    while(p_packet_content = pcap_next(m_pcap_handler, &protocol_header))
    {
        if(p_packet_content && protocol_header.caplen > sizeof(eth_header_t))
        {
            const unsigned char* p = p_packet_content;
            u_short ip_type = 0;

            //process ethernet header
            const eth_header_t* eth_h = (const eth_header_t*) p;
            p += sizeof(eth_header_t);
            //printf("eth src %2x:%2x:%2x:%2x:%2x:%2x, dst %2x:%2x:%2x:%2x:%2x:%2x, type %u\n",
            //eth_h->src[0], eth_h->src[1], eth_h->src[2], eth_h->src[3], eth_h->src[4], eth_h->src[5],
            //eth_h->dst[0], eth_h->dst[1], eth_h->dst[2], eth_h->dst[3], eth_h->dst[4], eth_h->dst[5],
            //eth_h->type);

            ip_type = eth_h->type;

            if(ip_type != TYPE_IPV4)
            {
                continue;
            }

            //process ipv4 header
            const ip_header_t* ip_h = (const ip_header_t*) p;
            p += sizeof(ip_header_t);
            char src[100];
            char dst[100];
            snprintf(src, sizeof(src), "%u.%u.%u.%u", ip_h->saddr.byte1, ip_h->saddr.byte2, ip_h->saddr.byte3, ip_h->saddr.byte4);
            snprintf(dst, sizeof(dst), "%u.%u.%u.%u", ip_h->daddr.byte1, ip_h->daddr.byte2, ip_h->daddr.byte3, ip_h->daddr.byte4);
            //printf("ip src %s, dst %s, type: %u\n", src, dst, ip_h->proto);
            if(strcmp(src, src_ip) || strcmp(dst, dst_ip))
            {
                continue;
            }

            //process udp header
            if(ip_h->proto != TYPE_UDP)
            {
                continue;
            }
            const udp_header_t* udp_h = (const udp_header_t*) p;
            p += sizeof(udp_header_t);
            if(src_port != ntohs(udp_h->sourport) || dst_port != ntohs(udp_h->destport))
            {
                continue;
            }
            
            //process rtp
            const rtp_header_t* rtp_h = (const rtp_header_t*) p;
            p += sizeof(rtp_header_t);

            std::shared_ptr<rtp_packet> rtp_packet_ptr(new rtp_packet);
            rtp_packet_ptr->header = *rtp_h;
            rtp_packet_ptr->header.seq = ntohs(rtp_h->seq);
            rtp_packet_ptr->header.timestamp = ntohl(rtp_h->timestamp);
            rtp_packet_ptr->data = std::string((const char*)p, (size_t)ntohs(udp_h->length) - sizeof(rtp_header_t));

            return rtp_packet_ptr;
        }
    }
    return NULL;
}