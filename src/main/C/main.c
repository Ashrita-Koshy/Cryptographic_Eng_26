#include <stdint.h>
#include <stdbool.h>
#include "kem.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "driverlib/debug.h"
#include "driverlib/gpio.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#define USER_LED1  GPIO_PIN_0
#define USER_LED2  GPIO_PIN_1


//*****************************************************************************
//
// The error routine that is called if the driver library encounters an error.
//
//*****************************************************************************
#ifdef DEBUG
void
__error__(char *pcFilename, uint32_t ui32Line)
{
    while(1);
}
#endif

int
main(void)
{
    uint32_t ui32SysClock;

    //
    // Run from the PLL at 120 MHz.
    // Note: SYSCTL_CFG_VCO_240 is a new setting provided in TivaWare 2.2.x and
    // later to better reflect the actual VCO speed due to SYSCTL#22.
    //
    ui32SysClock = SysCtlClockFreqSet((SYSCTL_XTAL_25MHZ |
                                       SYSCTL_OSC_MAIN |
                                       SYSCTL_USE_PLL |
                                       SYSCTL_CFG_VCO_240), 120000000);

    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPION);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_GPION))
    {
    }
    GPIOPinTypeGPIOOutput(GPIO_PORTN_BASE, (USER_LED1|USER_LED2));
    SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER0);
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_TIMER0));
    TimerConfigure(TIMER0_BASE, TIMER_CFG_PERIODIC);
    TimerLoadSet(TIMER0_BASE, TIMER_A, 0xFFFFFFFF);
    TimerEnable(TIMER0_BASE, TIMER_A);
    uint32_t start = TimerValueGet(TIMER0_BASE, TIMER_A);
    KemKeyPair keys;
    if(ML_KEM_KeyGen(&keys) == 0){
        KemEncapsulation encaps;
        if(ML_KEM_Encaps(&encaps, keys.ek, PKE_PUB_KEY_LEN) == 0){
            KemDecapsulation decaps;
            if(ML_KEM_Decaps(&decaps, encaps.c, PKE_CIPHERTEX_LEN, keys.dk, KEM_DECAP_LEN) == 0){
                uint32_t end = TimerValueGet(TIMER0_BASE, TIMER_A);
                uint32_t total = start - end;
                if(memcmp(encaps.k,decaps.k,SECRET_LEN) == 0){
                    while(1){
                    GPIOPinWrite(GPIO_PORTN_BASE, (USER_LED1|USER_LED2), USER_LED1);
                    SysCtlDelay(ui32SysClock/6);
                    GPIOPinWrite(GPIO_PORTN_BASE, (USER_LED1|USER_LED2), USER_LED2);
                    SysCtlDelay(ui32SysClock/6);
                    }
                }
            }
        }
    }
    return 0;
}

