#include "AES.h"
#include "CRC.h"
#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/rand.h>

typedef struct {
    uint8_t id;              /**< Device ID */
    uint8_t key[32];         /**< AES-256 key */
} device_t;

int main(void) {
    device_t devices[3] = {
        { .id = 0x01, .key = "01234567890123456789012345678901" },
        { .id = 0x02, .key = "abcdefabcdefabcdefabcdefabcdefab" },
        { .id = 0x03, .key = "12345678901234567890123456789012" }
    };

    device_t *device = &devices[0];

    uint8_t *key = (uint8_t*)device->key;
    uint8_t iv[16];

    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Could not create random bytes.\n");
        return 1;
    }

    uint8_t data[] = { 21, 37, (int8_t)(1050 - 1000) };
    int data_len = sizeof(data);

    uint16_t crc = crc16((uint8_t*)data, data_len);
    printf("CRC: %04x\n", crc);

    data_t *packetData = malloc(sizeof(data_t) + data_len);

    packetData->dataType = 5;
    packetData->crc = crc;
    memcpy(packetData->data, data, data_len);

    int packet_size = sizeof(data_t) + data_len;

    uint8_t *ciphertext = malloc(packet_size);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation for ciphertext failed.\n");
        free(packetData);
        return 1;
    }

    uint8_t *decryptedtext = malloc(packet_size);
    if (!decryptedtext) {
        fprintf(stderr, "Memory allocation for decryptedtext failed.\n");
        free(packetData);
        free(ciphertext);
        return 1;
    }

    if (encrypt((uint8_t*)packetData, packet_size, key, iv, ciphertext)) {
        printf("Encryption succeeded.\n");
    } else {
        fprintf(stderr, "Encryption failed.\n");
        free(packetData);
        free(ciphertext);
        free(decryptedtext);
        return 1;
    }

    printf("Encrypted Data size: %d\n", packet_size);
    
    if (decrypt(ciphertext, packet_size, key, iv, decryptedtext)) {
        printf("Decryption succeeded.\n");

        data_t *decrypted_packet = (data_t*)decryptedtext;
        printf("Data Type: %d\n", decrypted_packet->dataType);
        printf("CRC: %04x\n", decrypted_packet->crc);
        printf("Temperature: %d\n", decrypted_packet->data[0]);
        printf("Humidity: %d\n", decrypted_packet->data[1]);
        printf("Pressure: %d\n", (int8_t)decrypted_packet->data[2] + 1000);

        int data_len = packet_size - sizeof(data_t);
        uint16_t decrypted_crc = crc16((uint8_t*)decrypted_packet->data, data_len);
        printf("Decrypted CRC: %04x\n", decrypted_crc);
    } else {
        fprintf(stderr, "Decryption failed.\n");
        free(packetData);
        free(ciphertext);
        free(decryptedtext);
        return 1;
    }

    free(packetData);
    free(ciphertext);
    free(decryptedtext);
    return 0;
}
