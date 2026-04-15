/*******************************************************************************
* Freescale Semiconductor Inc.
* (c) Copyright 2010 Freescale Semiconductor, Inc.
* ALL RIGHTS RESERVED.
********************************************************************************
Services performed by FREESCALE in this matter are performed AS IS and without
any warranty. CUSTOMER retains the final decision relative to the total design
and functionality of the end product. FREESCALE neither guarantees nor will be
held liable by CUSTOMER for the success of this project.
FREESCALE DISCLAIMS ALL WARRANTIES, EXPRESSED, IMPLIED OR STATUTORY INCLUDING,
BUT NOT LIMITED TO, IMPLIED WARRANTY OF MERCHANTABILITY OR FITNESS FOR
A PARTICULAR PURPOSE ON ANY HARDWARE, SOFTWARE ORE ADVISE SUPPLIED 
TO THE PROJECT BY FREESCALE, AND OR NAY PRODUCT RESULTING FROM FREESCALE 
SERVICES. IN NO EVENT SHALL FREESCALE BE LIABLE FOR INCIDENTAL OR CONSEQUENTIAL 
DAMAGES ARISING OUT OF THIS AGREEMENT.
CUSTOMER agrees to hold FREESCALE harmless against any and all claims demands 
or actions by anyone on account of any damage, or injury, whether commercial,
contractual, or tortuous, rising directly or indirectly as a result 
of the advise or assistance supplied CUSTOMER in connection with product, 
services or goods supplied under this Agreement.
********************************************************************************
* File:             uart.c
* Owner:            b05111
* Version:          
* Date:             
* Classification:   General Business Information
* Brief:            terminal IO. implements CodeWarrior MSL library calls
*                   MSL_C library printf() output to MPC5676C's eSCI_A
********************************************************************************
* Detailed Description: 
* 
* implements CW MSL library function calls to implement printf() on eSCI_A
* header file UART.h is taken from the CW as is
* global functions defined in this module replace the ones from the library
* so finally we send printf() to eSCI_A
*
* ------------------------------------------------------------------------------
* Test HW:   XPC567XKIT516 - MPC5674ADAT516 Rev.C, MPC567XEVBFXMB Rev.B
* MCU:       PPC5674FMVYA264
* Terminal:  19200-8-no parity-1 stop bit-no flow control on eSCI_A
* Fsys:      264/200/150/60 MHz
*
********************************************************************************
Revision History:
0.0     Mar-04-2012     b05111  Initial Version
*******************************************************************************/

#include "MPC5674F_MVxA264.h"
#include "uart.h"
#include "clock.h"

/*******************************************************************************
* Global variables
*******************************************************************************/

/*******************************************************************************
* Constants and macros
*******************************************************************************/

/*******************************************************************************
* Local types
*******************************************************************************/

/*******************************************************************************
* Local function prototypes
*******************************************************************************/
static void Init_eSCI_A(void);
static void TransmitData(const char * pBuf, const uint32_t cnt);
static int32_t ReceiveData(char * const pBuf);

/*******************************************************************************
* Local variables
*******************************************************************************/

/*******************************************************************************
* Local functions
*******************************************************************************/ 

/*******************************************************************************
Function Name : Init_eSCI_A
Engineer      : b05111
Date          : Apr-19-2012
Parameters    : NONE
Modifies      : NONE
Returns       : NONE
Notes         : initializes MPC5674F's eSCI_A module for UART mode
Issues        : - expecting system clock is 264/200/150/60 MHz
                - clock.h must be included
*******************************************************************************/
static void Init_eSCI_A (void) 
{
	SIU.PCR[89].R = 0x400;      // Configure pad for primary func: TxDA
	SIU.PCR[90].R = 0x400;      // Configure pad for primary func: RxDA
	
	/* note: SBR = fsys/(16 * desired baudrate) < 8191 */

	ESCI_A.CR2.R = 0x2000;      // Module is enabled (default setting )
    
    /* assuming 264MHz sysclk i.e. fplatf = 132MHz */
    #if defined(CORE_CLOCK_264MHz) 
    ESCI_A.CR1.B.SBR = 430; // 19200 baud, 8 bits, no parity
    
    /* assuming 200MHz sysclk i.e. fplatf = 100MHz */
	#elif defined(CORE_CLOCK_200MHz)
	ESCI_A.CR1.B.SBR = 326; // 19200 baud, 8 bits, no parity
	
	/* assuming 150MHz sysclk i.e. fplatf = 75MHz */
	#elif defined(CORE_CLOCK_150MHz)
	ESCI_A.CR1.B.SBR = 244; // 19200 baud, 8 bits, no parity
	
	#else
	/* assuming 60 MHz - default fsys set by BAM that is 1.5 x fosc */
	ESCI_A.CR1.B.SBR = 98; // 19200 baud, 8 bits, no parity
	#endif

	ESCI_A.CR1.B.TE = 1;    // Tx enabled
	ESCI_A.CR1.B.RE = 1;    // Rx enabled	
    
}


/*******************************************************************************
Function Name : TransmitData
Engineer      : b05111
Date          : Apr-19-2012
Parameters    : pBuf - input string. won't be modified by the function
              : cnt  - input number of characters to be transmitted
Modifies      : NONE
Returns       : NONE
Notes         : Tx data on eSCI_A. polled mode. 
Issues        : NONE 
*******************************************************************************/
static void TransmitData(const char * const pBuf, const uint32_t cnt) 
{
    uint8_t	j = 0;                                 /* Dummy variable */
    for (j=0; j< cnt; j++) 
    {  /* Loop for character string */
    
        /* Wait for transmit data reg empty = 1 */
        while (ESCI_A.SR.B.TDRE == 0) {}       
        ESCI_A.SR.R = 0x80000000;              /* Clear TDRE flag */
        ESCI_A.DR.B.D = *(pBuf+j);          /* Transmit 8 bits Data */        
    }
}

/*******************************************************************************
Function Name : ReceiveData
Engineer      : b05111
Date          : Apr-19-2012
Parameters    : pBuf - address of a char where the received char is written to
                       the address (pBuf) doesn't change in the function
Modifies      : NONE
Returns       : NONE
Notes         : Rx data on eSCI_A. polled mode. 
Issues        : NONE 
*******************************************************************************/
static int32_t ReceiveData(char * const pBuf) 
{
    while (ESCI_A.SR.B.RDRF == 0) {}    /* Wait for receive data reg full = 1 */
    ESCI_A.SR.R = 0x20000000;           /* Clear RDRF flag */
    *pBuf = (char)ESCI_A.DR.B.D;               /* Read byte of Data*/  
    return 1;
}



/*******************************************************************************
* Global functions
*******************************************************************************/ 

/*
Methods called by MW MSL libraries to perform console IO:
*/

UARTError ReadUARTPoll(char* c) 
{
    if (ESCI_A.SR.B.RDRF == 0)
        return  kUARTNoData;  // return no data  
    else 
    {
        ESCI_A.SR.R = 0x20000000; // clear RDRF flag
        *c =(unsigned char) ESCI_A.DR.B.D; // read byte of Data
        return kUARTNoError;  // return no error
    }  
}


UARTError InitializeUART(UARTBaudRate baudRate)
{	
#pragma unused(baudRate)
	Init_eSCI_A();  
	return kUARTNoError; 
}

UARTError ReadUARTN(void * bytes, unsigned long length)
{ 
	unsigned long nchars = 0;
	while(  nchars < length)
	{
		int n = ReceiveData((char *)bytes+nchars);
		if(n<0) break;
		
		nchars += n;
	}; 
    return kUARTNoError; 
}

UARTError WriteUARTN(const void * bytes, unsigned long length)
{ 
	TransmitData ((const char * const)bytes,length);  
  	return kUARTNoError; 
}
