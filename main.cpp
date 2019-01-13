/*
 * @Author: yu.tongqing 
 * @Date: 2019-01-13 10:03:30 
 * @Last Modified by: yu.tongqing
 * @Last Modified time: 2019-01-13 18:12:49
 */

#include "pcap_reader.h"
#include "codec.h"

int main(int argc, const char* argv[])
{
    if(argc < 6)
    {
        printf("usage: %s pcap_file src_ip dst_ip src_port dst_port\n", argv[0]);
        return 1;
    }

    std::shared_ptr<rtp_packet> rtp;
    std::shared_ptr<rtp_packet> last_rtp;
    std::shared_ptr<codec> c;
    std::string filename(argv[1]);
    pcap_reader pr(filename);
    FILE* fp = fopen("out.pcm", "w");
    if(!fp)
    {
        printf("open file fail\n");
    }

    while(rtp = pr.get_next_rtp(argv[2], argv[3], atoi(argv[4]), atoi(argv[5])))
    {
        printf("get rtp packet, payload type: %u, seq: %u, timestamp: %u, data len: %lu\n",
        rtp->header.pt, rtp->header.seq, rtp->header.timestamp, rtp->data.size());

        c = codec::get_codec_by_payload_type(rtp->header.pt);
        if(!c)
        {
            printf("can not get codec for payload type: %u\n", rtp->header.pt);
            break;
        }

        std::string &&result = c->decode(std::string(""), rtp->data);
        fwrite(result.c_str(), 1, result.size(), fp);
        last_rtp = rtp;
    }
    fclose(fp);
    return 0;
}