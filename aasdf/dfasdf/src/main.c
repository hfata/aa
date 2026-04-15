#include <stdio.h>
#include "MPC5674F_MVxA264.h"
#include "Exceptions.h"
#include "IntcInterrupts.h"
#include "uart.h"
#include "clock.h"


/*******************************************************************************
* Constants and macros
*******************************************************************************/

#define ETPUC0_pin 441 // PCR number
#define ETPUC1_pin 442

#define LED1_pin ETPUC0_pin
#define LED2_pin ETPUC1_pin

#define SHADOW_ROW_BASE     0x00FFC000UL
#define SHADOW_ROW_END      0x01000000UL
#define SHADOW_ROW_WORDS    ((SHADOW_ROW_END - SHADOW_ROW_BASE) / 4U)

#define BLOCK0_BASE         0x00000000UL
#define BLOCK0_END          0x00004000UL
#define BLOCK0_WORDS        ((BLOCK0_END - BLOCK0_BASE) / 4U)

#define SHADOW_PASSWORD0    0x00FFFDD8UL
#define SHADOW_PASSWORD1    0x00FFFDDCUL
#define SHADOW_CENSOR_WORD  0x00FFFDE0UL

#define SHADOW_UNLOCK_KEY   0xA1A11111UL
#define SHADOW_SLOCK_KEY    0xC3C33333UL
#define SHADOW_UNLOCK_DATA  0x000303FFUL
#define BLOCK0_SELECT       0x00000001UL

#define SHADOW_PASSWORD0_DATA 0xFEEDFACEUL
#define SHADOW_PASSWORD1_DATA 0xCAFEBEEFUL
#define SHADOW_CENSOR_DATA    0xBABABABAUL

#define RECOVERY_MAGIC        0x5AA55AA5UL
#define RECOVERY_IDLE         0x00000000UL
#define RECOVERY_RUNNING      0x11111111UL
#define RECOVERY_OK           0x22222222UL
#define RECOVERY_ERROR        0xEEEEEEEEUL

#if VLE_IS_ON == 1
#define TEMP_BLOCK0_RCHW      0x015A0000UL
#else
#define TEMP_BLOCK0_RCHW      0x005A0000UL
#endif

#define RAM_CODE __attribute__((section(".ram_code"))) __attribute__((noinline))
#define RECOVERY_STATE __attribute__((section(".recovery_state")))


/*******************************************************************************
* Function prototypes
*******************************************************************************/

static void FMPLL_init(void);
static void DisableWatchdog(void);
static void GPIO_init(void);
static void HW_init(void);

void ShadowFlashReprogram(void);
extern __asm void shadow_recovery_entry(void);


/*******************************************************************************
* Recovery buffers
*******************************************************************************/

static RECOVERY_STATE unsigned int gRecoveryMagic;
static RECOVERY_STATE unsigned int gRecoveryResult;
static RECOVERY_STATE unsigned int gRecoveryEntry;
static RECOVERY_STATE unsigned int gShadowBackup[SHADOW_ROW_WORDS];
static RECOVERY_STATE unsigned int gBlock0Backup[BLOCK0_WORDS];


/*******************************************************************************
* Local functions
*******************************************************************************/

static void HW_init(void)
{
    DisableWatchdog();
    FMPLL_init();

    /* set round robin for all slaves */
    XBAR.SGPCR0.B.ARB = 1;
    XBAR.SGPCR1.B.ARB = 1;
    XBAR.SGPCR2.B.ARB = 1;
    XBAR.SGPCR6.B.ARB = 1;
    XBAR.SGPCR7.B.ARB = 1;
}


static void DisableWatchdog(void)
{
    /*
    REM Disable Watchdog Timers
    REM MCM SWT New SWT in MPC56xx devices
    mm.l $fff38000 $ff00000A
    REM e200 Core Watchdog Timer (all MPC55xx and MPC56xx devices)
    spr 340t 0
    */
    SWT.MCR.R = 0xFF00000A;

    asm
    {
        mfhid0  r11           /* Move from spr HID0 to r11 (copies HID0) */
        li      r12, 0xBFFF   /* Load immed. data of ~0x4000 to r12 */
        oris    r12, r12, 0xFFFF
        and     r11, r12, r11 /* OR r12 (~0x00004000) with r11 (HID0 value) */
        mthid0  r11           /* Move result to HID0 */

        lis     r12, 0x00
        mtspr   tcr, r12      /* clear SPR TCR register */
    }
}


static void FMPLL_init(void)
{
#if defined(CORE_CLOCK_264MHz)
    FMPLL.ESYNCR2.R = 0x00000002;
    FMPLL.ESYNCR1.R = 0x70040032;
    while (FMPLL.SYNSR.B.LOCK != 1) {};
    FMPLL.ESYNCR2.R = 0x00000001;
    printf("fsys = 264MHz\n\r");

#elif defined(CORE_CLOCK_200MHz)
    FMPLL.ESYNCR2.R = 0x00000002;
    FMPLL.ESYNCR1.R = 0x70040022;
    while (FMPLL.SYNSR.B.LOCK != 1) {};
    FMPLL.ESYNCR2.R = 0x00000001;
    printf("fsys = 200MHz\n\r");

#elif defined(CORE_CLOCK_150MHz)
    FMPLL.ESYNCR2.R = 0x00000005;
    FMPLL.ESYNCR1.R = 0x7003002C;
    while (FMPLL.SYNSR.B.LOCK != 1) {};
    FMPLL.ESYNCR2.R = 0x00000003;
    printf("fsys = 150MHz\n\r");
#else
    printf("FMPLL wasn't set properly - default 60MHz fsys used\n\r");
#endif
}


static void GPIO_init(void)
{
    // ETPUC0 and ETPUC1 - header:pin J24:1 and J24:2
    // it is needed to connect these signals to USER_LED (J5) by wire

    /* choose GPIO function */
    SIU.PCR[LED1_pin].B.PA  = 0;
    SIU.PCR[LED2_pin].B.PA  = 0;

    /* output buffer enable */
    SIU.PCR[LED1_pin].B.OBE = 1;
    SIU.PCR[LED2_pin].B.OBE = 1;
}


void RAM_CODE ShadowFlashReprogram(void)
{
    unsigned int i;

    asm
    {
        wrteei  0
        mbar    0
    }

    /*
     * This function always runs from SRAM. It is used both from main() and
     * from shadow_recovery_entry after a warm reset if reset happens after the
     * temporary block0 RCHW/reset-vector is written.
     */
    if (gRecoveryMagic != RECOVERY_MAGIC) {
        gRecoveryResult = RECOVERY_ERROR;
        while (1) {};
    }

    gRecoveryResult = RECOVERY_RUNNING;

    //unlock shadow block and low address space
    FLASH_A.LMLR.R = SHADOW_UNLOCK_KEY;
    FLASH_A.LMLR.R = SHADOW_UNLOCK_DATA;

    FLASH_A.SLMLR.R = SHADOW_SLOCK_KEY;
    FLASH_A.SLMLR.R = SHADOW_UNLOCK_DATA;

    /*
     * Step 1:
     * Erase block0 and plant a temporary RCHW + SRAM reset vector.
     * If any reset hits after this point, BAM can jump back to SRAM and this
     * same function can finish the shadow reprogramming sequence.
     */
    FLASH_A.LMSR.R = BLOCK0_SELECT;
    FLASH_A.MCR.B.ERS = 1;
    *(unsigned int*)BLOCK0_BASE = 0xFFFFFFFF;
    FLASH_A.MCR.B.EHV = 1;
    while (FLASH_A.MCR.B.DONE == 0) {};
    if (FLASH_A.MCR.B.PEG == 0) {
        gRecoveryResult = RECOVERY_ERROR;
        while (1) {};
    }
    FLASH_A.MCR.B.EHV = 0;
    FLASH_A.MCR.B.ERS = 0;
    FLASH_A.LMSR.R = 0;

    FLASH_A.MCR.B.PGM = 1;
    *(unsigned int*)BLOCK0_BASE       = TEMP_BLOCK0_RCHW;
    *(unsigned int*)(BLOCK0_BASE + 4) = gRecoveryEntry;
    FLASH_A.MCR.B.EHV = 1;
    while (FLASH_A.MCR.B.DONE == 0) {};
    if (FLASH_A.MCR.B.PEG == 0) {
        gRecoveryResult = RECOVERY_ERROR;
        while (1) {};
    }
    FLASH_A.MCR.B.EHV = 0;
    FLASH_A.MCR.B.PGM = 0;

    //erase shadow flash
    FLASH_A.MCR.B.ERS = 1;
    *(unsigned int*)SHADOW_ROW_BASE = 0xFFFFFFFF;
    FLASH_A.MCR.B.EHV = 1;
    while (FLASH_A.MCR.B.DONE == 0) {};
    if (FLASH_A.MCR.B.PEG == 0) {
        gRecoveryResult = RECOVERY_ERROR;
        while (1) {};
    }
    FLASH_A.MCR.B.EHV = 0;
    FLASH_A.MCR.B.ERS = 0;

    //confirm the shadow flash is erased
    for (i = SHADOW_ROW_BASE; i < SHADOW_ROW_END; i = i + 4)
    {
        if (*(unsigned int*)i != 0xFFFFFFFF)
        {
            gRecoveryResult = RECOVERY_ERROR;
            while (1) {};
        }
    }

    /*
     * Rebuild the full shadow row from SRAM backup so only the intended words
     * change and the remaining shadow content is preserved.
     */
    for (i = 0; i < SHADOW_ROW_WORDS; i = i + 2)
    {
        unsigned int addr = SHADOW_ROW_BASE + (i * 4);
        unsigned int data0 = gShadowBackup[i];
        unsigned int data1 = gShadowBackup[i + 1];

        if ((data0 == 0xFFFFFFFF) && (data1 == 0xFFFFFFFF))
            continue;

        FLASH_A.MCR.B.PGM = 1;
        *(unsigned int*)addr       = data0;
        *(unsigned int*)(addr + 4) = data1;
        FLASH_A.MCR.B.EHV = 1;
        while (FLASH_A.MCR.B.DONE == 0) {};
        if (FLASH_A.MCR.B.PEG == 0) {
            gRecoveryResult = RECOVERY_ERROR;
            while (1) {};
        }
        FLASH_A.MCR.B.EHV = 0;
        FLASH_A.MCR.B.PGM = 0;
    }

    //confirm the shadow flash content
    for (i = 0; i < SHADOW_ROW_WORDS; i++)
    {
        if (*(unsigned int*)(SHADOW_ROW_BASE + (i * 4)) != gShadowBackup[i])
        {
            gRecoveryResult = RECOVERY_ERROR;
            while (1) {};
        }
    }

    /*
     * Step 3:
     * Restore original block0 contents exactly as they were before the
     * censorship operation started.
     */
    FLASH_A.LMSR.R = BLOCK0_SELECT;
    FLASH_A.MCR.B.ERS = 1;
    *(unsigned int*)BLOCK0_BASE = 0xFFFFFFFF;
    FLASH_A.MCR.B.EHV = 1;
    while (FLASH_A.MCR.B.DONE == 0) {};
    if (FLASH_A.MCR.B.PEG == 0) {
        gRecoveryResult = RECOVERY_ERROR;
        while (1) {};
    }
    FLASH_A.MCR.B.EHV = 0;
    FLASH_A.MCR.B.ERS = 0;
    FLASH_A.LMSR.R = 0;

    for (i = 0; i < BLOCK0_WORDS; i = i + 2)
    {
        unsigned int addr = BLOCK0_BASE + (i * 4);
        unsigned int data0 = gBlock0Backup[i];
        unsigned int data1 = gBlock0Backup[i + 1];

        if ((data0 == 0xFFFFFFFF) && (data1 == 0xFFFFFFFF))
            continue;

        FLASH_A.MCR.B.PGM = 1;
        *(unsigned int*)addr       = data0;
        *(unsigned int*)(addr + 4) = data1;
        FLASH_A.MCR.B.EHV = 1;
        while (FLASH_A.MCR.B.DONE == 0) {};
        if (FLASH_A.MCR.B.PEG == 0) {
            gRecoveryResult = RECOVERY_ERROR;
            while (1) {};
        }
        FLASH_A.MCR.B.EHV = 0;
        FLASH_A.MCR.B.PGM = 0;
    }

    for (i = 0; i < BLOCK0_WORDS; i++)
    {
        if (*(unsigned int*)(BLOCK0_BASE + (i * 4)) != gBlock0Backup[i])
        {
            gRecoveryResult = RECOVERY_ERROR;
            while (1) {};
        }
    }

    gRecoveryMagic = 0;
    gRecoveryResult = RECOVERY_OK;

    /* reset so censorship takes effect immediately */
    SIU.SRCR.R = 0x00000001;
    while (1) {};
}


#pragma push
#pragma section code_type ".ram_code"
__asm void shadow_recovery_entry(void)
{
    nofralloc

    wrteei  0
    mbar    0
    addis   r13, r0, _ABS_SDA_BASE_@ha
    addi    r13, r13, _ABS_SDA_BASE_@l
    addis   r2, r0, _ABS_SDA2_BASE_@ha
    addi    r2, r2, _ABS_SDA2_BASE_@l
    addis   r1, r0, _stack_addr@ha
    addi    r1, r1, _stack_addr@l

    bl      ShadowFlashReprogram
shadow_recovery_hang:
    b       shadow_recovery_hang
}
#pragma pop


/*******************************************************************************
* Global functions
*******************************************************************************/

int main(void)
{
    vint32_t counter = 0;
    unsigned int i;

    /* Hardware initialization */
    HW_init();
    GPIO_init();

    printf("Erasing and programming of shadow flash started\r\n");

    /*
     * Backup everything before touching flash.
     * Shadow row backup preserves all shadow contents.
     * Block0 backup lets us temporarily plant a BAM reset vector to SRAM and
     * then restore the original boot block safely.
     */
    gRecoveryMagic = RECOVERY_MAGIC;
    gRecoveryResult = RECOVERY_IDLE;
    gRecoveryEntry = (unsigned int)shadow_recovery_entry;

    for (i = 0; i < SHADOW_ROW_WORDS; i++)
    {
        gShadowBackup[i] = *(unsigned int*)(SHADOW_ROW_BASE + (i * 4));
    }

    for (i = 0; i < BLOCK0_WORDS; i++)
    {
        gBlock0Backup[i] = *(unsigned int*)(BLOCK0_BASE + (i * 4));
    }

    /*
     * Hardcoded target requested by you:
     * password  = 0xFEED_FACE_CAFE_BEEF
     * censorship = 0xBABABABA
     */
    gShadowBackup[(SHADOW_PASSWORD0 - SHADOW_ROW_BASE) / 4] = SHADOW_PASSWORD0_DATA;
    gShadowBackup[(SHADOW_PASSWORD1 - SHADOW_ROW_BASE) / 4] = SHADOW_PASSWORD1_DATA;
    gShadowBackup[(SHADOW_CENSOR_WORD - SHADOW_ROW_BASE) / 4] = SHADOW_CENSOR_DATA;

    ShadowFlashReprogram();

    printf("Programming succesful\r\n");
    printf("Device is now censored with private password:\r\n");
    printf("0xFEED_FACE_CAFE_BEEF\r\n");
    printf("You can power-down the device\r\n");

    /* Loop forever */
    while (1)
    {
        /* delay */
        while (counter < 500000)
        {
            counter++;
        }
        counter = 0;

        /* toggle LED */
        SIU.GPDO[LED2_pin].R ^= 1;
    }
}
