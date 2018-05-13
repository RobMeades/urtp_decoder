// urtp_decoder.cpp : Defines the entry point for the console application.

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

// Things to help with parsing filenames.
#define DIR_SEPARATORS "\\/"
#define EXT_SEPARATOR "."
#define OUTPUT_FILE_AUDIO_EXTENSION "raw"
#define OUTPUT_FILE_DESCRIPTION_EXTENSION "txt"

// Things to help with decoding a header.
#define SYNC_BYTE     0x5A
#define HEADER_LENGTH 14

// Sign extenders
#define SIGN_EXTEND_16_TO_32(s) if (s & 0x8000) {s |= 0xFFFF0000;}
#define SIGN_EXTEND_8_TO_32(s) if (s & 0x80) {s |= 0xFFFFFF00;}

// Struct to hold a decoded header.
typedef struct {
    int audioCodingScheme;
    unsigned int sequenceNumber;
    unsigned long long timestamp;
    unsigned int numBytesAudio;
} Header;

// The types of audio coding scheme.
typedef enum {
    PCM_SIGNED_16_BIT = 0,
    UNICAM_COMPRESSED_8_BIT = 1,
    MAX_AUDIO_CODING_SCHEMES
} AudioCodingScheme;

// Variable to hold a header.
Header gHeader;

// Hex table
static const char hexTable[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

// Convert a sequence of bytes into a hex string, returning the number
// of characters written. The hex string is NOT null terminated.
static int bytesToHexString(const unsigned char *pInBuf, int lenInBuf, char *pOutBuf, int lenOutBuf)
{
    int y = 0;

    for (int x = 0; (x < lenInBuf) && (y < lenOutBuf); x++) {
        pOutBuf[y] = hexTable[(pInBuf[x] >> 4) & 0x0f]; // upper nibble
        y++;
        if (y < lenOutBuf) {
            pOutBuf[y] = hexTable[pInBuf[x] & 0x0f]; // lower nibble
            y++;
        }
    }

    return y;
}

// Print the usage text.
static void printUsage(char *pExeName) {
    printf("\n%s: decode a file of URTP-encoded data, producing a description in text form and a\n", pExeName);
    printf("PCM file of the audio (signed 32 bit, little-endian if this is a PC, format).  Usage:\n");
    printf("    %s urtp_file <-o output_file>\n", pExeName);
    printf("where:\n");
    printf("    urtp_file is the URTP-encoded input file,\n");
    printf("    -o optionally specifies the name (without extension) for the output files (if not specified urtp_file\n");
    printf("       without its extension is used); if the output file exists it will be overwritten,\n");
    printf("For example:\n");
    printf("    %s encoded.urtp -o decoded\n\n", pExeName);
}

// Parse the input file and write to the output files.
// The URTP input format as as follows.  First there is a
// header:
//
// Byte  |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |
// --------------------------------------------------------
//  0    |               Sync byte = 0x5A                |
//  1    |              Audio coding scheme              |
//  2    |              Sequence number MSB              |
//  3    |              Sequence number LSB              |
//  4    |                Timestamp MSB                  |
//  5    |                Timestamp byte                 |
//  6    |                Timestamp byte                 |
//  7    |                Timestamp byte                 |
//  8    |                Timestamp byte                 |
//  9    |                Timestamp byte                 |
//  10   |                Timestamp byte                 |
//  11   |                Timestamp LSB                  |
//  12   |       Number of samples in datagram MSB       |
//  13   |       Number of samples in datagram LSB       |
// ...where:
//
// - Sync byte is always 0x5A, used to sync a frame over a
//   streamed connection (e.g. TCP).
// - Audio coding scheme is one of:
//   - PCM_SIGNED_16_BIT (0)
//   - UNICAM_COMPRESSED_8_BIT (1)
// - Sequence number is a 16 bit sequence number, incremented
//   on sending of each datagram.
// - Timestamp is a uSecond timestamp representing the moment
//   of the start of the audio in this datagram.
// - Number of bytes to follow is the size of the audio payload
//   the follows in this datagram.
//
// There are two audio coding schemes.  The default, and most
// efficient, is 8 bit UNICAM compression.  If UNICAM is not
// used, 16 bit RAW PCM is used.
//
// When the audio coding scheme is PCM_SIGNED_16_BIT,
// the payload is as follows:
//
// Byte  |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |
//--------------------------------------------------------
//  14   |                 Sample 0 MSB                  |
//  15   |                 Sample 0 LSB                  |
//  16   |                 Sample 1 MSB                  |
//  17   |                 Sample 1 LSB                  |
//       |                     ...                       |
//  N    |                 Sample M MSB                  |
//  N+1  |                 Sample M LSB                  |
//
// ...where the number of [big-endian] signed 16-bit samples
// is between 0 and 320, so 5120 bits, plus the 112 bits of
// header.
//
// When the audio coding scheme is UNICAM_COMPRESSED_8_BIT,
// the payload is as follows:
//
// Byte  |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |
//--------------------------------------------------------
//  14   |              Block 0, Sample 0                |
//  15   |              Block 0, Sample 1                |
//       |                   ...                         |
//  28   |              Block 0, Sample 14               |
//  29   |              Block 0, Sample 15               |
//  30   |     Block 0 shift   |     Block 1 shift       |
//  31   |              Block 1, Sample 0                |
//  32   |              Block 1, Sample 1                |
//       |                     ...                       |
//  45   |              Block 1, Sample 14               |
//  46   |              Block 1, Sample 15               |
//  47   |              Block 2, Sample 0                |
//  48   |              Block 2, Sample 1                |
//       |                   ...                         |
//  61   |              Block 2, Sample 14               |
//  62   |              Block 2, Sample 15               |
//  63   |     Block 2 shift   |     Block 3 shift       |
//  64   |              Block 3, Sample 0                |
//  65   |              Block 3, Sample 1                |
//       |                     ...                       |
//  78   |              Block 3, Sample 14               |
//  79   |              Block 3, Sample 15               |
//       |                     ...                       |
//  N    |              Block M, Sample 0                |
//  N+1  |              Block M, Sample 1                |
//       |                     ...                       |
//  N+14 |              Block M, Sample 14               |
//  N+15 |              Block M, Sample 15               |
//  N+16 |     Block M shift   |     Block M+1 shift     |
//  N+17 |            Block M+1, Sample 0                |
//  N+18 |            Block M+1, Sample 1                |
//       |                     ...                       |
//  N+31 |            Block M+1, Sample 14               |
//  N+32 |            Block M+1, Sample 15               |
//
// ...where the number of blocks is between 0 and 20, so 330
// bytes in total plus the 14 byte header.

// Decode a URTP header into the header global variable
static Header *decodeHeader(const unsigned char *pBuffer)
{
    Header *pHeader = NULL;

    // First byte must be the sync byte
    if (*pBuffer == SYNC_BYTE) {
        pBuffer++;
        pHeader = &gHeader;
        // Next byte is the audio coding scheme
        pHeader->audioCodingScheme = *pBuffer;
        pBuffer++;
        // Then two bytes of sequence number, MSB first
        pHeader->sequenceNumber = ((unsigned int) *pBuffer) << 8;
        pBuffer++;
        pHeader->sequenceNumber += (unsigned int) *pBuffer;
        pBuffer++;
        // Then 8 bytes of timestamp
        pHeader->timestamp = 0;
        for (int x = 7; x >= 0; x--) {
            pHeader->timestamp += ((unsigned long long) *pBuffer) << (x << 3);
            pBuffer++;
        }
        // And lastly two bytes giving the number of
        // bytes of audio payload to follow
        pHeader->numBytesAudio = ((unsigned int) *pBuffer) << 8;
        pBuffer++;
        pHeader->numBytesAudio += (unsigned int) *pBuffer;
    }

    return pHeader;
}

// Parse a PCM signed 16 bit audio payload.
static int parsePcmSigned16Bit(const unsigned char *pBuffer, int length, FILE *pAudioFile,  FILE *pDescriptionFile)
{
    int numSamples = 0;
    unsigned int sample = 0;
    char *pDescription = (char *) malloc(((length / 2) * 5) + 1); // Enough room for "0123 " for each sample and a terminator

    for (int x = 0; x < length; x++) {
        if (x & 1) {
            sample += *pBuffer;
            SIGN_EXTEND_16_TO_32(sample);
            fwrite(&sample, sizeof(sample), 1, pAudioFile);
            if (pDescription != NULL) {
                 // Masking is required as, if sample is greater than 0xFFFF, more than 4 digits will be printed
                sprintf(pDescription + (numSamples * 5), "%04x ", sample & 0xFFFF);
            }
            numSamples++;
        } else {
            sample = ((unsigned int) *pBuffer) << 8;
        }
        pBuffer++;
    }

    if (pDescription != NULL) {
        fprintf(pDescriptionFile, " 0x%s", pDescription);
        free(pDescription);
    }

    return numSamples;
}

// Parse a Unicam compressed 8 bit audio payload.
static int parseUnicamCompressed8Bit(const unsigned char *pBuffer, int length, FILE *pAudioFile,  FILE *pDescriptionFile)
{
    int numSamples = 0;
    unsigned int numBlocks = 0;
    unsigned int sample = 0;
    unsigned int block[16];
    int index = 0;
    unsigned char shiftNibbles = 0;
    char blockDescription[3 * 16 + 1]; // Enough room for "xx " for each sample and a terminator

    for (int x = 0; x < length; x++) {
        if (index < sizeof(block) / sizeof (block[0])) {
            // Collect the 16 samples of a block
            sample = *pBuffer;
            sprintf(&(blockDescription[index * 3]), "%02x ", sample);
            SIGN_EXTEND_8_TO_32(sample);
            block[index] = sample;
            index++;
            if ((index == sizeof(block) / sizeof (block[0])) && ((numBlocks & 1) == 1)) {
                // At the end of an odd block
                index = 0;
                // Write out the description of the block
                fprintf(pDescriptionFile, " 0x%s<< %2u |", blockDescription, (shiftNibbles >> 4) & 0x0F);
                // Multiple-up the odd block of 16 samples and write them to file
                for (int y = 0; y < sizeof(block) / sizeof (block[0]); y++) {
                    block[y] <<= shiftNibbles >> 4;
                }
                fwrite(block, sizeof(block), 1, pAudioFile);
                numSamples += sizeof(block) / sizeof (block[0]);
                numBlocks++;
            }
        } else if ((numBlocks & 1) == 0) {
            // At the shift nibbles just beyond the end of an even block
            shiftNibbles = *pBuffer;
            index = 0;
            // Write out the description of the even block
            fprintf(pDescriptionFile, " 0x%s<< %2u [0x%02x] ", blockDescription, shiftNibbles & 0x0F, shiftNibbles);
            // Multiple-up the even block of 16 samples and write them to file
            for (int y = 0; y < sizeof(block) / sizeof (block[0]); y++) {
                block[y] <<= shiftNibbles & 0x0F;
            }
            fwrite(block, sizeof(block), 1, pAudioFile);
            numSamples += sizeof(block) / sizeof (block[0]);
            numBlocks++;
        } else {
            // Shouldn't get here
            fprintf(pDescriptionFile, "!!!");
        }
        pBuffer++;
    }

    return numSamples;
}

// Parse the input file.
static int parse(FILE *pInputFile, FILE *pOutputDescriptionFile, FILE *pOutputAudioFile)
{
    int datagramsProcessed = 0;
    int numSamples = 0;
    unsigned char header[HEADER_LENGTH];
    char headerString[HEADER_LENGTH * 2];
    Header *pDecodedHeader = NULL;
    unsigned char *pPayload;
    int previousSequenceNumer = -1;

    // Look for a sync byte
    while (fread(header, 1, 1, pInputFile) == 1) {
        if (header[0] == SYNC_BYTE) {
            // If the sync byte is found, read the rest of the header
            if (fread(&(header[1]), sizeof(header) - 1, 1, pInputFile) == 1) {
                pDecodedHeader = decodeHeader(header);
                if (pDecodedHeader != NULL) {
                    fprintf(pOutputDescriptionFile, "0x%.*s [", bytesToHexString(header, sizeof (header), headerString, sizeof (headerString)),
                            headerString);
                    fprintf(pOutputDescriptionFile, "seq %010u%s, encoding 0x%02x%s, timestamp %020llu, %03u byte payload]",
                            pDecodedHeader->sequenceNumber, pDecodedHeader->sequenceNumber != previousSequenceNumer + 1 ? "!!!" : "",
                            pDecodedHeader->audioCodingScheme, pDecodedHeader->audioCodingScheme >= MAX_AUDIO_CODING_SCHEMES ? "!!!" : "",
                            pDecodedHeader->timestamp, pDecodedHeader->numBytesAudio);
                    previousSequenceNumer = pDecodedHeader->sequenceNumber;
                    // Got a header, deal with the audio payload
                    pPayload = (unsigned char *) malloc(pDecodedHeader->numBytesAudio);
                    if (pPayload != NULL) {
                        if (fread(pPayload, 1, pDecodedHeader->numBytesAudio, pInputFile) == pDecodedHeader->numBytesAudio) {
                            switch (pDecodedHeader->audioCodingScheme) {
                                case PCM_SIGNED_16_BIT:
                                    numSamples += parsePcmSigned16Bit(pPayload, pDecodedHeader->numBytesAudio, pOutputAudioFile, pOutputDescriptionFile);
                                break;
                                case UNICAM_COMPRESSED_8_BIT:
                                    numSamples += parseUnicamCompressed8Bit(pPayload, pDecodedHeader->numBytesAudio, pOutputAudioFile, pOutputDescriptionFile);
                                break;
                                default:
                                break;
                            }
                            fprintf(pOutputDescriptionFile, "\n");
                        } else {
                            fprintf(pOutputDescriptionFile, "Couldn't read all %d byte(s) of audio payload from the input file.\n",
                                    pDecodedHeader->numBytesAudio);
                        }
                        datagramsProcessed++;
                        free(pPayload);
                    } else {
                        fprintf(pOutputDescriptionFile, "Unable to allocate %d bytes(s) of memory for payload.\n",
                                pDecodedHeader->numBytesAudio);
                    }
                } else {
                    fprintf(pOutputDescriptionFile, "Invalid URTP header found.\n");
                }
            } else {
                fprintf(pOutputDescriptionFile, "Couldn't read all the URTP header from the input file.\n");
            }
        }
    }

    if (pDecodedHeader == NULL) {
        fprintf(pOutputDescriptionFile, "No valid URTP headers found.\n");
    }

    return datagramsProcessed;
}

// Entry point
int main(int argc, char* argv[])
{
    int retValue = -1;
    bool success = false;
    int x = 0;
    char *pExeName = NULL;
	char *pInputFileName = NULL;
    FILE *pInputFile = NULL;
	char *pOutputFileRootName = NULL;
	char *pOutputDescriptionFileName = NULL;
    FILE *pOutputDescriptionFile = NULL;
	char *pOutputAudioFileName = NULL;
    FILE *pOutputAudioFile = NULL;
    char *pChar;
    struct stat st = { 0 };

    // Find the exe name in the first argument
    pChar = strtok(argv[x], DIR_SEPARATORS);
    while (pChar != NULL) {
        pExeName = pChar;
        pChar = strtok(NULL, DIR_SEPARATORS);
    }
    if (pExeName != NULL) {
        // Remove the extension
        pChar = strtok(pExeName, EXT_SEPARATOR);
        if (pChar != NULL) {
            pExeName = pChar;
        }
    }
    x++;

    // Look for all the command line parameters
    while (x < argc) {
        // Test for input filename
        if (x == 1) {
            pInputFileName = argv[x];
        // Test for output file option
        } else if (strcmp(argv[x], "-o") == 0) {
            x++;
            if (x < argc) {
                pOutputFileRootName = argv[x];
            }
        }
        x++;
    }

    // Must have the mandatory command-line parameter
    if (pInputFileName != NULL) {
        success = true;
        // Open the input file
        pInputFile = fopen (pInputFileName, "rb");
        if (pInputFile == NULL) {
            success = false;
            printf("Cannot open input file %s (%s).\n", pInputFileName, strerror(errno));
        }
        // Point the output file root name at the input file name if we don't have one
        if (pOutputFileRootName == NULL) {
            pOutputFileRootName = pInputFileName;
        }
        // Create and open the output file names
        pChar = strtok(pOutputFileRootName, EXT_SEPARATOR);
        pOutputDescriptionFileName = (char *) malloc (strlen(pChar) + sizeof(OUTPUT_FILE_DESCRIPTION_EXTENSION) - 1 + sizeof(EXT_SEPARATOR) - 1 + 1);
        if (pOutputDescriptionFileName != NULL) {
            strcpy(pOutputDescriptionFileName, pOutputFileRootName);
            strcat(pOutputDescriptionFileName, EXT_SEPARATOR);
            strcat(pOutputDescriptionFileName, OUTPUT_FILE_DESCRIPTION_EXTENSION);
            pOutputDescriptionFile = fopen(pOutputDescriptionFileName, "w");
            if (pOutputDescriptionFile == NULL) {
                success = false;
                printf("Cannot open description output file %s (%s).\n", pOutputDescriptionFileName, strerror(errno));
            }
        } else {
            success = false;
            printf("Cannot allocate memory for output description file name.\n");
        }
        pOutputAudioFileName = (char *) malloc (strlen(pChar) + sizeof(OUTPUT_FILE_AUDIO_EXTENSION) - 1 + sizeof(EXT_SEPARATOR) - 1 + 1);
        if (pOutputAudioFileName != NULL) {
            strcpy(pOutputAudioFileName, pOutputFileRootName);
            strcat(pOutputAudioFileName, EXT_SEPARATOR);
            strcat(pOutputAudioFileName, OUTPUT_FILE_AUDIO_EXTENSION);
            pOutputAudioFile = fopen(pOutputAudioFileName, "wb");
            if (pOutputAudioFile == NULL) {
                success = false;
                printf("Cannot open audio output file %s (%s).\n", pOutputAudioFileName, strerror(errno));
            }
        } else {
            success = false;
            printf("Cannot allocate memory for output audio file name.\n");
        }
        if (success) {
            printf("Parsing file %s, writing description to %s and signed 32-bit PCM audio to %s.\n",
                   pInputFileName, pOutputDescriptionFileName, pOutputAudioFileName);
            x = parse(pInputFile, pOutputDescriptionFile, pOutputAudioFile);
            printf("Done: %d URTP datagram(s) processed.\n", x);
        } else {
            printUsage(pExeName);
        }
    } else {
        printUsage(pExeName);
    }

    if (success) {
        retValue = 0;
    }

    // Clean up
    if (pInputFile != NULL) {
        fclose(pInputFile);
    }
    if (pOutputDescriptionFile != NULL) {
        fclose(pOutputDescriptionFile);
    }
    if (pOutputAudioFile != NULL) {
        fclose(pOutputAudioFile);
    }
    if (pOutputDescriptionFileName != NULL) {
        free(pOutputDescriptionFileName);
    }
    if (pOutputAudioFileName != NULL) {
        free(pOutputAudioFileName);
    }

    return retValue;
}