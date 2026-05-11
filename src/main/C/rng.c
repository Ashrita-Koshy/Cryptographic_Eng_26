#include "rng.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "inc/hw_memmap.h"
#include "driverlib/sysctl.h"
#include "driverlib/adc.h"
#include "inc/hw_adc.h"
#include "inc/hw_aes.h"
#include "inc/hw_ints.h"
#include "driverlib/aes.h"

#define KEYLEN   32
#define BLOCKLEN 16
#define SEEDLEN  (KEYLEN + BLOCKLEN)   // 48
#define KEYLEN_32 KEYLEN / 4
#define BLOCKLEN_32 BLOCKLEN / 4

// drbg internal state
// updated to reflect expected array for AES hardware module - Nolan
// per TivaWare Peripheral Library Section 5
typedef struct {
    uint32_t key[KEYLEN_32];
    uint32_t v[BLOCKLEN_32];
    int     reseed_counter;
} CTR_DRBG_STATE;

static CTR_DRBG_STATE drbg;
static int drbg_initialized = 0;

// collect entropy from clock jitter for now
// this is just for host-side testing
// later this part can be replaced with the board-side entropy source
static uint8_t jitter_one_byte(void)
{    
    uint8_t byte = 0;
    // build one byte by collecting 8 lsb values
    int bit;
    uint32_t sample[1];
    
    for (bit = 0; bit < 8; bit++) {
        
        //Obtains a temperature reading from the ADC sensor - Nolan
        //reference section 4 of the peripheral library for API
        ADCProcessorTrigger(ADC0_BASE, 3);
        while (!ADCIntStatus(ADC0_BASE, 3, false));
        ADCIntClear(ADC0_BASE, 3);
        ADCSequenceDataGet(ADC0_BASE, 3, sample);

        // use the lsb of the timing difference
        byte |= ((uint8_t)(sample[0] & 1)) << bit;
    }

    return byte;
}

static void collect_entropy(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        uint8_t acc = 0;
        int k;
        // oversample 4 times and xor them together
        for (k = 0; k < 4; k++)
            acc ^= jitter_one_byte();
        buf[i] = acc;
    }
}

// increase v by 1 - Nolan
static void increment_v(uint32_t* v)
{
    int i;
    for (i = BLOCKLEN_32 - 1; i >= 0; i--) {
        if (++v[i] != 0)
            break;
    }
}

// ctr_drbg update
// makes new key and new v from current state + provided_data
static void ctr_drbg_update(const uint8_t* provided_data,
                            CTR_DRBG_STATE *ctx)
{
    uint8_t tmp[SEEDLEN];
    int pos = 0;
    // generate 48 bytes total using aes(key, v), aes(key, v+1), ...
    while (pos < SEEDLEN) {
        increment_v(ctx->v);
        uint32_t block[BLOCKLEN_32];
        AESDataProcess(AES_BASE, ctx->v, block, BLOCKLEN);
        memcpy(tmp + pos, block, BLOCKLEN);
        pos += BLOCKLEN;
    }

    // mix in provided_data with xor
    int i;
    for (i = 0; i < SEEDLEN; i++)
        tmp[i] ^= provided_data[i];
    // first 32 bytes become the new key
    memcpy(ctx->key, tmp, KEYLEN);

    //setting the key
    AESKey1Set(AES_BASE, ctx->key,  AES_CFG_KEY_SIZE_256BIT);
    
    // last 16 bytes become the new v
    memcpy(ctx->v, tmp + KEYLEN, BLOCKLEN);

    // clear temporary buffer
    memset(tmp, 0, sizeof(tmp));
}

// initialize drbg
// if entropy_input is null, collect entropy here for now
// entropy_input must point to at least 48 bytes if it is not null
// personalization must also point to at least 48 bytes if it is used
void randombytes_init()
{
    //setting the ADC peripheral for temp readins - Nolan - See Section 4 of TivaWare Peripheral Library Guide
    //usage is based on example provided from https://sites.google.com/site/luiselectronicprojects/tutorials/tiva-tutorials/tiva-adc/internal-temperature-sensor
    SysCtlPeripheralEnable(SYSCTL_PERIPH_ADC0);
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_ADC0)){
    }
    ADCSequenceConfigure(ADC0_BASE, 3, ADC_TRIGGER_PROCESSOR, 0);
    ADCSequenceStepConfigure(ADC0_BASE, 3, 0,
        ADC_CTL_TS | ADC_CTL_IE | ADC_CTL_END);
    ADCSequenceEnable(ADC0_BASE, 3);
    ADCIntClear(ADC0_BASE, 3);

    //setting the CCM peripheral for AES - Nolan - See Section 5 of TivaWare Peripheral Library Guide
    //usage is based on exampke provided in guide
    SysCtlPeripheralEnable(SYSCTL_PERIPH_CCM0);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_CCM0))
    {
    }
    AESReset(AES_BASE);
    AESConfigSet(AES_BASE, AES_CFG_DIR_ENCRYPT | AES_CFG_MODE_ECB | AES_CFG_KEY_SIZE_256BIT);
    
    uint8_t seed_material[SEEDLEN];

    // start from all-zero key and v
    memset(drbg.key, 0, KEYLEN);
    memset(drbg.v,   0, BLOCKLEN);
    //setting the key
    AESKey1Set(AES_BASE, drbg.key,  AES_CFG_KEY_SIZE_256BIT);

    collect_entropy(seed_material, SEEDLEN);


    // initialize internal drbg state from seed material
    ctr_drbg_update(seed_material, &drbg);

    // mark drbg as initialized
    drbg.reseed_counter = 1;
    drbg_initialized = 1;

    // clear temporary seed buffer
    memset(seed_material, 0, sizeof(seed_material));
}

// generate random bytes
int randombytes(unsigned char *buf, unsigned long long len)
{
    // fail if output buffer is null
    if (buf == NULL)
        return -1;

    // fail if drbg has not been initialized yet
    if ((!drbg_initialized || !SysCtlPeripheralReady(SYSCTL_PERIPH_ADC0) || !SysCtlPeripheralReady(SYSCTL_PERIPH_CCM0)))
        return -1;

    uint32_t block[BLOCKLEN_32];
    unsigned long long offset = 0;

    // keep generating 16-byte blocks until len is filled
    while (offset < len) {
        increment_v(drbg.v);
        //replaced with AES hardware mode - Nolan
        AESDataProcess(AES_BASE, drbg.v, block, BLOCKLEN);

        // copy either a full block or the remaining bytes
        unsigned long long chunk = len - offset;
        if (chunk > BLOCKLEN)
            chunk = BLOCKLEN;

        memcpy(buf + offset, block, (size_t)chunk);
        offset += chunk;
    }

    // update state after output for backtracking resistance
    uint8_t zeroes[SEEDLEN];
    memset(zeroes, 0, SEEDLEN);
    ctr_drbg_update(zeroes, &drbg);

    // count one more generate call
    drbg.reseed_counter++;

    // clear temporary block
    memset(block, 0, sizeof(block));
    return 0;
}
