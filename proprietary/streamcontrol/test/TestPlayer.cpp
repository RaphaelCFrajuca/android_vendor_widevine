/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#include <stdlib.h>
#include <unistd.h>
#include <termio.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <iostream>
#include <cstring>
#include <memory>

#include "WVStreamControlAPI.h"
#include "AndroidHooks.h"

#include "WVMDrmPlugin.h"
#include "drm/DrmInfoRequest.h"
#include "drm/DrmInfoStatus.h"
#include "drm/DrmConstraints.h"
#include "drm/DrmInfo.h"

#define AES_BLOCK_SIZE 16

using namespace std;
using namespace android;

#define DEFAULT_BLOCK_SIZE 16*1024
#define DEFAULT_PLAYBACK_BUFFER_SIZE 0*1024*1024
#define DEFAULT_START_TIME "now"
#define DEFAULT_DRM_URL "http://wstfcps005.shibboleth.tv/widevine/cypherpc/cgi-bin/GetEMMs.cgi"
#define DEFAULT_DRM_ACK_URL "http://wstfcps005.shibboleth.tv/widevine/cypherpc/cgi-bin/Ack.cgi"

#define SHOW_BITRATE 1

static void Terminate();


/**
 * Print command line options
 */
void PrintUsage(char *prog)
{
    printf("Usage: %s <options> url\n", prog);
    printf("       %s <options> -L filename\n", prog);
    printf("    -o output_file\n");
    printf("    -b block_size (default: %d)\n", DEFAULT_BLOCK_SIZE);
    printf("    -p playback_buffer_size (default: %d)\n", (int)DEFAULT_PLAYBACK_BUFFER_SIZE);
    printf("    -m print PTS -> media time\n");
    printf("    -s start_time (default: %s)\n", DEFAULT_START_TIME);
    printf("    -d drm_url\n");
    printf("    -L open filname on local file system\n");
    exit(-1);
}

static IDrmEngine *sDrmPlugin = NULL;
static void *sSharedLibHandle = NULL;
static bool sWVInitialized = false;

static struct termios termattr, save_termattr;
static int ttysavefd = -1;
static enum
{
    RESET, RAW, CBREAK
} ttystate = RESET;


/**
 ***************************************************************************
 *
 * set_tty_raw(), put the user's TTY in one-character-at-a-time mode.
 *
 * @returns 0 on success, -1 on failure.
 *
 *************************************************************************** */
int set_tty_raw(void)
{
    int i;

    i = tcgetattr(STDIN_FILENO, &termattr);
    if (i < 0)
    {
        printf("tcgetattr() returned %d for fildes=%d\n",i,STDIN_FILENO);
        perror("");
        return -1;
    }
    save_termattr = termattr;

    termattr.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    termattr.c_iflag &= ~(ICRNL | INPCK | ISTRIP | IXON); /* | BRKINT */
    termattr.c_cflag &= ~(CSIZE | PARENB);
    termattr.c_cflag |= CS8;
    /* termattr.c_oflag &= ~(OPOST); */

    termattr.c_cc[VMIN] = 0;  /* or 0 for some Unices;  see note 1 */
    termattr.c_cc[VTIME] = 0;

    i = tcsetattr(STDIN_FILENO, TCSANOW, &termattr);
    if (i < 0)
    {
        printf("tcsetattr() returned %d for fildes=%d\n",i,STDIN_FILENO);
        perror("");
        return -1;
    }

    ttystate = RAW;
    ttysavefd = STDIN_FILENO;

    return 0;
}

/**
 * @return time of day in milliseconds
 */
static uint64_t get_time_in_ms()
{
    uint64_t ms;
    timeval t;
    gettimeofday(&t, NULL);
    ms = (uint64_t)(t.tv_sec) * 1000;
    ms +=(uint64_t)(t.tv_usec) / 1000;
    return ms;
}

/**
 ***************************************************************************
 *
 * set_tty_cooked(), restore normal TTY mode. Very important to call
 *   the function before exiting else the TTY won't be too usable.
 *
 * @returns 0 on success, -1 on failure.
 *
 *************************************************************************** */
int set_tty_cooked(void)
{
    int i;

    if (ttystate != CBREAK && ttystate != RAW)
    {
        return 0;
    }
    i = tcsetattr(STDIN_FILENO, TCSAFLUSH, &save_termattr);
    if (i < 0)
    {
        return -1;
    }
    ttystate = RESET;
    return 0;
}

/**
 ***************************************************************************
 *
 * kb_getc(), if there's a typed character waiting to be read,
 *
 * @return character; else return 0.
 *
 *************************************************************************** */
unsigned char kb_getc(void)
{
    unsigned char ch;
    ssize_t size;

    size = read(STDIN_FILENO, &ch, 1);
    if (size == 0)
    {
        return 0;
    }
    else
    {
        return ch;
    }
}

static void PrintMessage(const char *msg)
{
    printf("%s", msg);
}

static void OpenDrmPlugin()
{
    const char *path = "/vendor/lib/drm/libdrmwvmplugin.so";
    sSharedLibHandle = dlopen(path, RTLD_NOW);
    if (sSharedLibHandle == NULL) {
        fprintf(stderr, "Can't open plugin: %s\n", path);
        Terminate();
    }

    typedef IDrmEngine *(*create_t)();
    create_t creator = (create_t)dlsym(sSharedLibHandle, "create");
    if (!creator) {
        fprintf(stderr, "Can't find create method\n");
        Terminate();
    }

    sDrmPlugin = (*creator)();

    if (sDrmPlugin->initialize(0) != DRM_NO_ERROR) {
        fprintf(stderr, "onInitialize failed!\n");
        Terminate();
    }
}

static void CloseDrmPlugin()
{
    if (sSharedLibHandle) {

        if (sDrmPlugin) {
            typedef IDrmEngine *(*destroy_t)(IDrmEngine *plugin);
            destroy_t destroyer = (destroy_t)dlsym(sSharedLibHandle, "destroy");

            if (destroyer) {
                (*destroyer(sDrmPlugin));
                sDrmPlugin = NULL;
            } else
                fprintf(stderr, "Can't find destroy method\n");
        }

        dlclose(sSharedLibHandle);
        sSharedLibHandle = NULL;
    }
}

static void AcquireRights(IDrmEngine *plugin, string url, string drmUrl,
                          bool isLocal)
{
    String8 mimeType("video/wvm");
    DrmInfoRequest rightsAcquisitionInfo(DrmInfoRequest::TYPE_RIGHTS_ACQUISITION_INFO, mimeType);

    int fdNum = -1;

    rightsAcquisitionInfo.put(String8("WVDRMServerKey"), String8(drmUrl.c_str()));
    rightsAcquisitionInfo.put(String8("WVAssetURIKey"), String8(url.c_str()));
    if (isLocal) {
        char fdStr[16];
        fdNum = open(url.c_str(), O_RDONLY);
        if (fdNum == -1) {
            fprintf(stderr, "unable to open local movie file %s for reading.\n",
                    url.c_str());
            close(fdNum);
            Terminate();
        }
        sprintf(fdStr, "%lu", (unsigned long)fdNum);
        rightsAcquisitionInfo.put(String8("FileDescriptorKey"), String8(fdStr));
    }
    rightsAcquisitionInfo.put(String8("WVDeviceIDKey"), String8("device1234"));
    rightsAcquisitionInfo.put(String8("WVPortalKey"), String8("OEM"));
    rightsAcquisitionInfo.put(String8("WVLicenseTypeKey"), String8("1"));

    // Get asset rights from DRM.  If it is necessary to
    // read file metadata to get the asset ID, this can take several seconds.
    DrmInfo *info = plugin->acquireDrmInfo(0, &rightsAcquisitionInfo);
    if (info == NULL) {
        fprintf(stderr, "acquireDrmInfo failed!\n");
        if (isLocal) {
            close(fdNum);
        }
        Terminate();
    }

    DrmInfoStatus *status = plugin->processDrmInfo(0, info);
    if (status == NULL || status->statusCode != DrmInfoStatus::STATUS_OK) {
        fprintf(stderr, "processDrmInfo failed!\n");
        if (isLocal) {
            close(fdNum);
        }
        Terminate();
    }

    if (plugin->checkRightsStatus(0, String8(url.c_str()), Action::DEFAULT) != RightsStatus::RIGHTS_VALID) {
        fprintf(stderr, "checkValidRights default action failed!\n");
        if (isLocal) {
            close(fdNum);
        }
        Terminate();
    }

    if (isLocal) {
        close(fdNum);
    }

    delete status;
    delete info;
}

static void Terminate()
{
    if (sWVInitialized)
        WV_Terminate();
    CloseDrmPlugin();
    exit(-1);
}

static void _cb1(char *a, unsigned long b)
{
    DrmBuffer buf(a, b);
    sDrmPlugin->initializeDecryptUnit(0, NULL, 0, &buf);
}

/**
 * Program entry pointer
 *
 * @return 0 for success, -1 for error
 */
int main( int argc, char *argv[] )
{
    int option;

    string url, outputFile, startTime = DEFAULT_START_TIME;
    unsigned long blockSize = DEFAULT_BLOCK_SIZE;
    unsigned long playbackBufferSize = DEFAULT_PLAYBACK_BUFFER_SIZE;
    bool ptsToMediaTime = false;
    string drmUrl = DEFAULT_DRM_URL;
    bool isLocal = false;

    _ah006(PrintMessage);

    while ((option = getopt(argc, argv, "o:b:p:s:mD:d:L")) != -1) {
        switch (option) {
        case 'o':
            outputFile = optarg;
           break;

        case 'b':
            if (sscanf(optarg, "%lu", &blockSize) != 1)
                PrintUsage(argv[0]);
            break;

        case 'p':
            if (sscanf(optarg, "%lu", &playbackBufferSize) != 1)
                PrintUsage(argv[0]);
            break;

        case 's':
            startTime = optarg;
            break;

        case 'm':
            ptsToMediaTime = true;
            break;

        case 'd':
            drmUrl = optarg;
            break;

        case 'L':
            isLocal = true;
            break;

        default:
            printf("unknown option: '%c'\n", option);
            PrintUsage(argv[0]);
        }
    }

    if ((argc - optind) != 1)
        PrintUsage(argv[0]);

    url = argv[optind];

    FILE *output = NULL;
    if (outputFile.size()) {
        output = fopen(outputFile.c_str(), "wb");
        if (!output) {
            fprintf(stderr, "unable to open output file %s for writing\n",
                    argv[2]);
            Terminate();
        }
    }

    // This turns off some verbose printing
    setenv("WV_SILENT", "true", 1);

    WVStatus status = WV_Initialize( NULL );

    if (status != WV_Status_OK) {
        fprintf(stderr, "ERROR: WV_Initialize returned status %d\n", (int)status);
        Terminate();
    } else
        sWVInitialized = true;

    // enable HTTP logging if you want to debug
    WV_SetLogging(WV_Logging_HTTP);

    OpenDrmPlugin();

    // if isLocal is true, the url param holds a local filesystem filename
    AcquireRights(sDrmPlugin, url, drmUrl, isLocal);

    _ah002(_cb1);

    /*
    status = WV_StartBandwidthCheck( url.c_str() );
    if (status != WV_Status_OK) {
        fprintf(stderr, "ERROR: WV_CheckBandwidth returned status %d\n", (int)status);
        Terminate();
    }

    unsigned long bandwidth;
    do {
        usleep(100000);

        // The idea here is the bandwidth check is done in the background while the GUI/OSD is
        // doing other things.  In this example, we just wait for the result.

        status = WV_GetBandwidthCheckStatus(&bandwidth);
    } while (status == WV_Status_Checking_Bandwidth);

    if (status == WV_Status_OK)
        cout << "Bandwidth check " << bandwidth << endl;
    else
        cout << "Bandwidth check failed: " << status << endl;
*/
    WVSession *session = 0;
    WVCredentials credentials;

    status = WV_Setup( session, url.c_str(), "RAW/RAW/RAW;destination=getdata", credentials);
    if (status != WV_Status_OK) {
        fprintf(stderr, "ERROR: WV_Setup returned status %d\n", (int)status);
        if (status == 408)
            fprintf(stderr, "TIMEOUT: Make sure your device is powered on and has a network connection\n");
        else if (status == 404)
            fprintf(stderr, "ASSET NOT FOUND: Make sure the URL you provided is correct\n");

        Terminate();
    }

    WVMacrovision macrovision;
    bool hdcp, cit;
    status = WV_Info_GetCopyProtection(session, &macrovision, &hdcp, &cit);
    switch (status) {
    case WV_Status_OK:
        printf("Copy protection: macrovison = %d, hdcp = %d, cit = %d\n", (int)macrovision, (int)hdcp, (int)cit);
        break;
    case WV_Status_Warning_Not_Available:
        printf("Warning: Copy protection info not yet available\n");
        status = WV_Status_OK;
        break;
    default:
        fprintf(stderr, "ERROR: WV_Info_GetCopyProtection returned status %d\n", (int)status);
        Terminate();
    }

    // Get audio and video config options
    WVAudioType audioType;
    unsigned short streamId;
    unsigned short profile;
    unsigned short numChannels;
    unsigned long sampleFrequency;
    unsigned long bitRate;
    WVVideoType videoType;
    unsigned short level;
    unsigned short width;
    unsigned short height;
    float pixelAspectRatio;
    float frameRate;

    WV_Info_GetAudioConfiguration(session, &audioType, &streamId, &profile, &numChannels, &sampleFrequency, &bitRate);
    printf("Audio type: %hu\n", audioType);
    printf("Audio stream ID: %hu\n", streamId);
    printf("Audio profile: %hu\n", profile);
    printf("Audio channels: %hu\n", numChannels);
    printf("Audio sampling freq: %lu\n", sampleFrequency);
    printf("Audio bit rate: %lu\n", bitRate);

    WV_Info_GetVideoConfiguration(session, &videoType, &streamId, &profile, &level, &width, &height, & pixelAspectRatio, &frameRate, &bitRate);
    printf("Video type: %hu\n", videoType);
    printf("Video stream ID: %hu\n", streamId);
    printf("Video profile: %hu\n", profile);
    printf("Video profile level: %hu\n", level);
    printf("Video width: %hu\n", width);
    printf("Video height: %hu\n", height);
    printf("Video pixel aspect ratio: %f\n", pixelAspectRatio);
    printf("Video frame rate: %f\n", frameRate);
    printf("Video bit rate: %lu\n", bitRate);

    float scale_used;
    startTime += "-";
    status = WV_Play( session, 1.0, &scale_used, startTime.c_str() );
    if (status != WV_Status_OK) {
        fprintf(stderr, "ERROR: WV_Play returned status %d\n", (int)status);
        Terminate();
    }

    auto_ptr<uint8_t> buffer(new uint8_t[blockSize]);
    size_t numBytes;

    // fill playback buffer as quickly as possible
    uint64_t bytesRead = 0;
    while (bytesRead < playbackBufferSize) {
        status = WV_GetData( session, buffer.get(), blockSize, &numBytes, 0  );
        switch (status) {
        case WV_Status_OK:
            break;
        case WV_Status_Warning_Download_Stalled:
        case WV_Status_Warning_Need_Key:
            fprintf(stderr, "WARNING: WV_GetData returned status %d\n", (int)status);
            usleep(100000);
            break;
        default:
            fprintf(stderr, "ERROR: WV_GetData returned status %d\n", (int)status);
            Terminate();
            break;
        }
        if (numBytes > 0) {
            if (output)
                fwrite(buffer.get(), numBytes, 1, output);
            bytesRead += numBytes;
            cout << "Read " << numBytes << "/" << bytesRead << " out of " << playbackBufferSize << endl;
        }
    }

    set_tty_raw();

#if SHOW_BITRATE
    unsigned long bitRates[32];
    size_t numBitRates;
    size_t curBitRate;
    if (WV_Info_GetAdaptiveBitrates(session, bitRates, sizeof(bitRates)/sizeof(uint32_t),
                                    &numBitRates, &curBitRate) == WV_Status_OK) {
        printf("Bit Rates: ");
        for (uint32_t idx = 0; idx < numBitRates; ++idx) {
            if (idx == curBitRate)
                printf("*%lu*  ", bitRates[idx]);
            else
                printf("%lu ", bitRates[idx]);
        }
        printf("\n");
    }
#endif

    string nptTime = WV_Info_GetTime(session);
    int hh, mm;
    float ss;
    sscanf(nptTime.c_str(), "%d:%d:%f", &hh, &mm, &ss);
    uint64_t startMs = (uint64_t)((hh * 3600000) + (mm * 60000) + (ss * 1000));
    uint64_t curMs = startMs;
    uint64_t lastMs = curMs;
    uint64_t baseTime = get_time_in_ms();
    int trickPlayRate = 1;

    bool quit = false;
    while (!quit) {
        uint64_t curTime = get_time_in_ms();
        uint64_t streamTimeRef = (trickPlayRate >= 0) ? (curMs - startMs) : (startMs - curMs);
        uint64_t clockRef = get_time_in_ms() - baseTime;
        if (trickPlayRate)
            clockRef *= trickPlayRate > 0 ? trickPlayRate : -trickPlayRate;
        if (clockRef > streamTimeRef) {
            // time for another pull
            status = WV_GetData( session, buffer.get(), blockSize, &numBytes, 0  );
            switch (status) {
            case WV_Status_OK:
                break;
            case WV_Status_End_Of_Media:
                printf("End of Media\n");
                if (trickPlayRate < 0) {
                    WV_Play( session, 1.0, &scale_used, "00:00:00-" );
                    trickPlayRate = 1;
                    startMs = curMs;
                    baseTime = curTime;
                } else
                    quit = true;
                break;
            case 1001:
                fprintf(stderr, "ERROR: WV_GetData returned status %d\n", (int)status);
                break;
            case WV_Status_Warning_Download_Stalled:
            case WV_Status_Warning_Need_Key:
                fprintf(stderr, "WARNING: WV_GetData returned status %d\n", (int)status);
                usleep(100000);
                break;
            default:
                fprintf(stderr, "ERROR: WV_GetData returned status %d\n", (int)status);
                Terminate();
                break;
            }
            if (numBytes > 0) {
                if (output)
                    fwrite(buffer.get(), numBytes, 1, output);
                bytesRead += numBytes;
                nptTime = WV_Info_GetTime(session);
                sscanf(nptTime.c_str(), "%d:%d:%f", &hh, &mm, &ss);
                curMs = (uint64_t)((hh * 3600000) + (mm * 60000) + (ss * 1000));
                if (curMs != lastMs) {
                    int64_t msDif = (trickPlayRate >= 0) ? (curMs - lastMs) : (lastMs - curMs);
                    if ((msDif < 0) || (msDif > 60000)) {
                        // discontinuity
                        startMs = curMs;
                        baseTime = curTime;
                        printf("Current time (skip): %s\n", nptTime.c_str());
                    } else if ((curMs / 1000) != (lastMs / 1000)) {
                        printf("Current time: %s\n", nptTime.c_str());
#if SHOW_BITRATE
                        if (WV_Info_GetAdaptiveBitrates(session, bitRates, sizeof(bitRates)/sizeof(uint32_t),
                                                        &numBitRates, &curBitRate) == WV_Status_OK) {
                            printf("Bit Rates: ");
                            for (uint32_t idx = 0; idx < numBitRates; ++idx) {
                                if (idx == curBitRate)
                                    printf("*%lu*  ", bitRates[idx]);
                                else
                                    printf("%lu ", bitRates[idx]);
                            }
                            printf("\n");
                        }
#endif
                    }
                    lastMs = curMs;
                }
            }
        }

        unsigned char kbhit = kb_getc();
        switch (kbhit) {
        case 'g':
            char seekTime[256];
            set_tty_cooked();
            printf("Go to time: ");
            if ((scanf("%s", seekTime) == 1) && (sscanf(seekTime, "%d:%d:%f", &hh, &mm, &ss) == 3)) {
                status = WV_Play(session, 1, &scale_used, string(seekTime) + "-");
                if (status != WV_Status_OK) {
                    fprintf(stderr, "ERROR: WV_Play returned status %d\n", (int)status);
                    Terminate();
                }
                startMs = curMs;
                baseTime = curTime;
            }
            set_tty_raw();
            break;

        case 't':
            set_tty_cooked();
            printf("Trick-play rate (now): ");
            if (scanf("%d", &trickPlayRate) == 1) {
                printf( "Got a trick play value of %d\n", trickPlayRate );
                if (trickPlayRate == 0)
                    trickPlayRate = 1;
                status = WV_Play(session, trickPlayRate, &scale_used, "now-");
                if (status != WV_Status_OK) {
                    fprintf(stderr, "ERROR: WV_Play returned status %d\n", (int)status);
                    Terminate();
                }
                startMs = curMs;
                baseTime = curTime;
            } else {
                printf( "did not get a rate\n" );
            }
            set_tty_raw();
            break;

        case 'p':
            set_tty_cooked();
            printf("PTS: ");
            uint64_t pts;
            if (scanf("%llu", (long long unsigned int*)& pts) == 1) {
                string mediaTime = WV_TimestampToMediaTime(session, pts, PTS);
                printf("Media Time: \"%s\"\n", mediaTime.c_str());
            }
            set_tty_raw();
            break;

        case 'x':
            quit = true;
            break;

        default:
            break;
        }

        usleep(1000);
    };

    WV_Teardown( session );
    WV_Terminate();

    CloseDrmPlugin();

    if (output)
        fclose(output);

    set_tty_cooked();

    return(0);
}
