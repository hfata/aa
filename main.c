
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


/*******************************************************************************
* Function prototypes
*******************************************************************************/

static void FMPLL_init(void);
static void DisableWatchdog(void);
static void GPIO_init(void);

void ShadowFlashReprogram(void);
                   

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
        mfhid0  r11		  	  /* Move from spr HID0 to r11 (copies HID0) */
        li      r12, 0xBFFF  /* Load immed. data of ~0x4000 to r12 */
        oris    r12, r12, 0xFFFF
        and     r11, r12, r11  /* OR r12 (~0x00004000) with r11 (HID0 value) */
        mthid0  r11          /* Move result to HID0 */

        lis     r12, 0x00
        mtspr   tcr, r12  /* clear SPR TCR register */
    }
}


static void FMPLL_init(void)
{
    #if defined(CORE_CLOCK_264MHz)
        FMPLL.ESYNCR2.R = 0x00000002;								
        FMPLL.ESYNCR1.R = 0x70040032;								
        while (FMPLL.SYNSR.B.LOCK != 1) {}; /* Wait for FMPLL to LOCK  */								
        FMPLL.ESYNCR2.R = 0x00000001;                  /* Fsys =264Mhz */								
        printf("fsys = 264MHz\n\r");
    
    #elif defined(CORE_CLOCK_200MHz)
        FMPLL.ESYNCR2.R = 0x00000002;								
        FMPLL.ESYNCR1.R = 0x70040022;								
        while (FMPLL.SYNSR.B.LOCK != 1) {}; /* Wait for FMPLL to LOCK  */								
        FMPLL.ESYNCR2.R = 0x00000001;                  /* Fsys =200Mhz */								
        printf("fsys = 200MHz\n\r");
    
    #elif defined(CORE_CLOCK_150MHz)
        FMPLL.ESYNCR2.R = 0x00000005;								
        FMPLL.ESYNCR1.R = 0x7003002C;								
        while (FMPLL.SYNSR.B.LOCK != 1) {}; /* Wait for FMPLL to LOCK  */								
        FMPLL.ESYNCR2.R = 0x00000003;                  /* Fsys =150Mhz */								
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


void ShadowFlashReprogram(void)
{
	unsigned int i;		

	//unlock shadow block
	FLASH_A.LMLR.R = 0xA1A11111;	//unlock register
	FLASH_A.LMLR.R = 0x000303FF;	//unlock shadow flash
	
	FLASH_A.SLMLR.R = 0xC3C33333;	//unlock register
	FLASH_A.SLMLR.R = 0x000303FF;	//unlock shadow flash
	
	//erase shadow flash
	FLASH_A.MCR.B.ERS = 1;
	*(unsigned int*)0x00FFC000 = 0xFFFFFFFF;	//interlock write - write any address in shadow block
	FLASH_A.MCR.B.EHV = 1;
	while(FLASH_A.MCR.B.DONE == 0){};
	FLASH_A.MCR.B.EHV = 0;
	FLASH_A.MCR.B.ERS = 0;	
	
	//confirm the shadow flash is erased
	for(i=0x00FFC000;i<0x00FFFFFF; i=i+4)
	{
		if(*(unsigned int*)i != 0xFFFFFFFF)
			while(1){};	//shadow flash not erased!
	}				
	
	//program shadow flash (restore default password and censoring information)
	FLASH_A.MCR.B.PGM = 1;	
	//program first 128bit page
	*(unsigned int*)0xFFFDD8 = 0xFEEDFACE;	// write data within 128bit programming page
	*(unsigned int*)0xFFFDDC = 0xCAFEBEEF;	// write data within 128bit programming page
	FLASH_A.MCR.B.EHV = 1;					// program page (words that were not written above will have default value 0xFFFF)
	while(FLASH_A.MCR.B.DONE == 0){};
	FLASH_A.MCR.B.EHV = 0;
	//program second 128bit page
	*(unsigned int*)0xFFFDE0 = 0x55AA55AA;	// write data within 128bit programming page
	//*(unsigned int*)0xFFFDE0 = 0xBABABABA;	// this censores the device	
	FLASH_A.MCR.B.EHV = 1;					// program page (words that were not written above will have default value 0xFFFF)
	while(FLASH_A.MCR.B.DONE == 0){};
	FLASH_A.MCR.B.EHV = 0;
	//end of program sequence
	FLASH_A.MCR.B.PGM = 0;
}


/*******************************************************************************
* Global functions
*******************************************************************************/

int main(void) 
{
    vint32_t counter = 0;

    /* Hardware initialization */
    HW_init();
    GPIO_init();	
  
    printf("Erasing and programming of shadow flash started\r\n");  
    
    ShadowFlashReprogram();
    
    printf("Programming succesful\r\n");
    printf("Device is now uncensored\r\n");
    printf("You can power-down the device\r\n");
                      
    /* Loop forever */
    while (1) 
    {
        /* delay */
        while(counter < 500000)
        {
            counter++;

        }  
        counter = 0;
        
        /* toggle LED */
        SIU.GPDO[LED2_pin].R ^= 1;   
    }

}

