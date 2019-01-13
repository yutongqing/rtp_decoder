/*
 * @Author: yu.tongqing 
 * @Date: 2019-01-13 14:40:14 
 * @Last Modified by: yu.tongqing
 * @Last Modified time: 2019-01-13 17:24:45
 */

#include "codec.h"

std::unordered_map <unsigned short, std::shared_ptr<codec>> g_creator_map;
CODEC_BIND(opus_codec, 102)
CODEC_BIND(opus_codec, DEFAULT_CODEC_PT)

opus_codec::opus_codec()
{
    int error;
    m_opus_decoder = opus_decoder_create(48000, 1, &error);
    if(OPUS_OK != error)
    {
        printf("create opus decoder fail: %d\n", error);
        m_opus_decoder = NULL;
    }
}
opus_codec::~opus_codec()
{
    if(m_opus_decoder)
    {
        opus_decoder_destroy(m_opus_decoder);
    }
}

std::string opus_codec::decode(const std::string& last_packet, const std::string& packet)
{
    std::string result = "";
    if(!m_opus_decoder || packet.size() == 0)
    {
        return result;
    }
    int samples = opus_packet_get_samples_per_frame((const unsigned char*)packet.c_str(), 48000);
    char *pcm = (char*)malloc(samples*2);
    int status = opus_decode(m_opus_decoder, (const unsigned char*)packet.c_str(), packet.size(), (short*)pcm, samples, 0);
    if(status > 0)
    {
        result = std::string(pcm, (size_t)(status * 2));
    }
    free(pcm);
    return result;
}