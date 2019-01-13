/*
 * @Author: yu.tongqing 
 * @Date: 2019-01-13 10:03:30 
 * @Last Modified by: yu.tongqing
 * @Last Modified time: 2019-01-13 16:39:16
 */

#include "pcap_reader.h"
#include "codec.h"

int main(int argc, const char* argv[])
{
    std::string filename = "abc.pcap";
    pcap_reader pr(filename);
    std::shared_ptr<rtp_packet> rtp;
    std::shared_ptr<rtp_packet> last_rtp;
    std::shared_ptr<codec> c;
    FILE* fp = fopen("out.pcm", "w");
    if(!fp)
    {
        printf("open file fail\n");
    }
    while(rtp = pr.get_next_rtp("67.216.222.199", "172.20.10.9", 24326, 58374))
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