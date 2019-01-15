/*
 * @Author: yu.tongqing 
 * @Date: 2019-01-13 10:03:30 
 * @Last Modified by: yu.tongqing
 * @Last Modified time: 2019-01-13 19:30:51
 */

#include "pcap_reader.h"
#include "codec.h"

typedef struct wav_fmt_chunk
{
    char sub_chunk_id[4];
    u_int32_t sub_chunk_size;
    u_int16_t audio_format;
    u_int16_t num_channels;
    u_int32_t sample_rate;
    u_int32_t byte_rate;
    u_int16_t block_align;
    u_int16_t bits_per_sample;
} wav_fmt_chunk_t;

typedef struct wav_data_chunk
{
    u_int32_t sub_chunk_id[4];
    u_int32_t sub_chunk_size;
} wav_data_chunk_t;

typedef struct wav_header
{
    char chunk_id[4];
    u_int32_t chunk_size;
    char format[4];
    wav_fmt_chunk_t fmt_chunk;
    wav_data_chunk_t data_chunk;
}wav_header_t;

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
    FILE* fp = fopen("out.wav", "w");
    if(!fp)
    {
        printf("open file fail\n");
    }

    wav_header_t wav_h;
    fwrite((void*)&wav_h, 1, sizeof(wav_h), fp);//the space for wav header

    u_int32_t pcm_len = 0;
    u_int32_t sample_rate = 0;
    while(rtp = pr.get_next_rtp(argv[2], argv[3], atoi(argv[4]), atoi(argv[5])))
    {
        printf("get rtp packet, payload type: %u, seq: %u, timestamp: %u, data len: %lu\n",
        rtp->header.pt, rtp->header.seq, rtp->header.timestamp, rtp->data.size());

        c = codec::get_codec_by_payload_type(rtp->header.pt);
        sample_rate = c->get_sample_rate();
        if(!c)
        {
            printf("can not get codec for payload type: %u\n", rtp->header.pt);
            continue;
        }

        std::string &&result = c->decode(std::string(""), rtp->data);
        fwrite(result.c_str(), 1, result.size(), fp);
        pcm_len += result.size();
        last_rtp = rtp;
    }

    //set wav header
    memcpy(wav_h.chunk_id, "RIFF", 4);
    memcpy(wav_h.format, "WAVE", 4);
    wav_h.chunk_size = sizeof(wav_h) + pcm_len - 8;

    memcpy(wav_h.fmt_chunk.sub_chunk_id, "fmt ", 4);
    wav_h.fmt_chunk.sub_chunk_size = sizeof(wav_fmt_chunk_t) - 8;
    wav_h.fmt_chunk.audio_format = 1;
    wav_h.fmt_chunk.num_channels = 1;
    wav_h.fmt_chunk.sample_rate = sample_rate;
    wav_h.fmt_chunk.byte_rate = wav_h.fmt_chunk.sample_rate * 2;
    wav_h.fmt_chunk.block_align = 2;
    wav_h.fmt_chunk.bits_per_sample = 16;
    memcpy(wav_h.data_chunk.sub_chunk_id, "data", 4);
    wav_h.data_chunk.sub_chunk_size = pcm_len;

    fseek(fp, 0, SEEK_SET);
    fwrite((void*)&wav_h, 1, sizeof(wav_h), fp);//write wav header

    fclose(fp);
    return 0;
}