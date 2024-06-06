#ifndef PACKET_H
#define PACKET_H

typedef struct
{
    uint8_t version;         /**< 4 bits version + 4 bits reserved for later use */
    uint8_t id;              /**< 4 bits class + 4 bits device ID */
    uint8_t iv[16];          /**< Initialization Vector */
    uint8_t encryptedData[]; /**< Encrypted data */
} lora_packet_t;

typedef struct {
    uint8_t dataType;        /**< 1 byte data type */
    uint16_t crc;            /**< CRC16 checksum */
    uint8_t data[];          /**< Data payload */
} data_t;

#endif // PACKET_H