/******************************************************************************
* File Name: main.c
*
* Description: This is the source code for the PSoC 6 MCU Cryptography: AES 
* Demonstration Example for ModusToolbox.
*
* Related Document: See Readme.md
*
*******************************************************************************
* (c) 2019, Cypress Semiconductor Corporation. All rights reserved.
*******************************************************************************
* This software, including source code, documentation and related materials
* ("Software"), is owned by Cypress Semiconductor Corporation or one of its
* subsidiaries ("Cypress") and is protected by and subject to worldwide patent
* protection (United States and foreign), United States copyright laws and
* international treaty provisions. Therefore, you may use this Software only
* as provided in the license agreement accompanying the software package from
* which you obtained this Software ("EULA").
*
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software source
* code solely for use in connection with Cypress's integrated circuit products.
* Any reproduction, modification, translation, compilation, or representation
* of this Software except as specified above is prohibited without the express
* written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer of such
* system or application assumes all risk of such use and in doing so agrees to 
* indemnify Cypress against all liability.
*******************************************************************************/

#include "cy_pdl.h"
#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"
#include <string.h>

/*******************************************************************************
* Macros
********************************************************************************/
/* The input message size (inclusive of the string terminating character '\0').
 * Edit this macro to suit your message size */
#define MAX_MESSAGE_SIZE                    (100u)

#define ASCII_RETURN_CARRIAGE                (0x0D)

/* Size of the message block that can be processed by Crypto hardware for
 * AES encryption */
#define AES128_ENCRYPTION_LENGTH             (uint32_t)(16u)

#define AES128_KEY_LENGTH                      (uint32_t)(16u)

#define SCREEN_HEADER "\r\n__________________________________________________"\
                      "____________________________\r\n*\t\tCE220465 PSoC 6 "\
                    "Cryptography: AES Demonstration\r\n*\r\n*\tThis code"\
                    "example demonstrates encryption and decryption of data"\
                    "using\r\n*\tthe Advanced Encryption Scheme (AES) algorithm"\
                    " in PSoC 6 MCU.\r\n*\r\n*\tUART Terminal Settings: Baud Rate"\
                    "- 115200 bps, 8N1\r\n*"\
                    "\r\n__________________________________________________"\
                    "____________________________\r\n"

#define SCREEN_HEADER1 "\r\n\n__________________________________________________"\
                  "____________________________\r\n"

/* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
#define CLEAR_SCREEN         "\x1b[2J\x1b[;H"

/* Number of bytes per line to be printed on the UART terminal */
#define BYTES_PER_LINE                        (16u)

/*******************************************************************************
* Data type definitions
********************************************************************************/
/* Data type definition to track the state machine accepting the user message */
typedef enum
{
    MESSAGE_ENTER_NEW,
    MESSAGE_READY,
    MESSAGE_NOT_READY
}message_status_t;

/*******************************************************************************
* Function Prototypes
********************************************************************************/
void print_data(uint8_t* data, uint8_t len);
void encrypt_message(uint8_t* message, uint8_t size);
void decrypt_message(uint8_t* message, uint8_t size);

/*******************************************************************************
* Global Variables
********************************************************************************/
/* UART object used for reading character from terminal */
extern cyhal_uart_t cy_retarget_io_uart_obj;

/* Variables to hold the user message and the corresponding encrypted message */
CY_ALIGN(4) uint8_t message[MAX_MESSAGE_SIZE];
CY_ALIGN(4) uint8_t encrypted_msg[MAX_MESSAGE_SIZE];
CY_ALIGN(4) uint8_t decrypted_msg[MAX_MESSAGE_SIZE];

cy_stc_crypto_aes_state_t aesState;

/* Key used for AES encryption*/
CY_ALIGN(4) uint8_t AES_Key[AES128_KEY_LENGTH]={0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xFF,0xEE,\
                                     0xDD,0xCC,0xBB,0xAA,0xAA,0xBB,0xCC,0xDD,};

/*******************************************************************************
* Function Name: main
********************************************************************************
* Summary:
* Main function
*
* Parameters:
*  void
*
* Return:
*  int
*
*******************************************************************************/
int main(void)
{
    cy_rslt_t result, uart_result;

    /* Variable to track the status of the message entered by the user */
    message_status_t msgStatus = MESSAGE_ENTER_NEW;

    uint8_t msg_size = 0;

    bool uartStatus = false;

    /* Initialize the device and board peripherals */
    result = cybsp_init();

     /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();
    
    /* Initialize retarget-io to use the debug UART port */
    cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    printf(CLEAR_SCREEN);

    printf(SCREEN_HEADER);

    /* Enable the Crypto block */
    Cy_Crypto_Core_Enable(CRYPTO);

    for(;;)
    {
        switch(msgStatus)
        {
            case MESSAGE_ENTER_NEW:
                memset(message, 0, MAX_MESSAGE_SIZE);
                msg_size = 0;
                printf("\r\nEnter the message:\r\n");
                uart_result = cyhal_uart_getc(&cy_retarget_io_uart_obj, &message[msg_size], 1);
                msgStatus = MESSAGE_NOT_READY;
                break;

            case MESSAGE_NOT_READY:
                uartStatus = cyhal_uart_is_rx_active(&cy_retarget_io_uart_obj);
                if(!uartStatus && uart_result == CY_RSLT_SUCCESS)
                {
                    /* Check if the ENTER Key is pressed. If pressed, set the message
                     * status as MESSAGE_READY */
                    if(message[msg_size] == ASCII_RETURN_CARRIAGE)
                    {
                        message[msg_size]='\0';
                        msgStatus = MESSAGE_READY;
                    }
                    else
                    {
                        cyhal_uart_putc(&cy_retarget_io_uart_obj, message[msg_size]);
                        msg_size++;
                        /* Check if size of the message  exceeds MAX_MESSAGE_SIZE
                         * (inclusive of the string terminating character '\0')*/
                        if(msg_size > (MAX_MESSAGE_SIZE - 1))
                        {
                            printf("\r\n\nMessage length exceeds 100 characters!!!"\
                            " Please enter a shorter message\r\nor edit the macro MAX_MESSAGE_SIZE"\
                            " to suit your message size\r\n");
                            msgStatus = MESSAGE_ENTER_NEW;
                            break;
                        }
                    }
                }
                uart_result = cyhal_uart_getc(&cy_retarget_io_uart_obj, &message[msg_size], 1);
                break;

            case MESSAGE_READY:

                encrypt_message(message, msg_size);

                decrypt_message(message, msg_size);

                msgStatus = MESSAGE_ENTER_NEW;
                break;

            default:

                break;
        }
    }
}

/*******************************************************************************
* Function Name: print_data()
********************************************************************************
* Summary: Function used to display the data in hexadecimal format
*
* Parameters:
*  uint8_t* data - Pointer to location of data to be printed
*  uint8_t  len  - length of data to be printed
*
* Return:
*  void
*
*******************************************************************************/
void print_data(uint8_t* data, uint8_t len)
{
    char print[10];
    for(uint32 i=0; i < len; i++)
    {
        if((i % BYTES_PER_LINE) == 0)
        {
            printf("\r\n");
        }
        sprintf(print,"0x%02X ", *(data+i));
        printf("%s", print);
    }
    printf("\r\n");
}

/*******************************************************************************
* Function Name: encrypt_message
********************************************************************************
* Summary: Function used to encrypt the message.
*
* Parameters:
*  char * message - pointer to the message to be encrypted
*  uint8_t size   - size of message to be encrypted.
*
* Return:
*  void
*
*******************************************************************************/
void encrypt_message(uint8_t* message, uint8_t size)
{
    uint8_t AESBlock_count = 0;

    AESBlock_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ? \
                                                      (size/AES128_ENCRYPTION_LENGTH) \
                                                      : (1 + size/AES128_ENCRYPTION_LENGTH);

    /* Initializes the AES operation by setting key and key length */
    Cy_Crypto_Core_Aes_Init(CRYPTO, AES_Key, CY_CRYPTO_KEY_AES_128, &aesState);

    for(int i = 0; i < AESBlock_count ; i++)
    {
        /* Perform AES ECB Encryption mode of operation */
        Cy_Crypto_Core_Aes_Ecb(CRYPTO, CY_CRYPTO_ENCRYPT,\
        (encrypted_msg + AES128_ENCRYPTION_LENGTH * i),\
        (message + AES128_ENCRYPTION_LENGTH * i), &aesState);

        /* Wait for Crypto Block to be available */
        Cy_Crypto_Core_WaitForReady(CRYPTO);
    }

    printf("\r\n\nKey used for Encryption:\r\n");
    print_data(AES_Key, AES128_KEY_LENGTH);
    printf("\r\nResult of Encryption:\r\n");
    print_data((uint8_t*) encrypted_msg, AESBlock_count*AES128_ENCRYPTION_LENGTH);

    Cy_Crypto_Core_Aes_Free(CRYPTO, &aesState);
}

/*******************************************************************************
* Function Name: decrypt_message
********************************************************************************
* Summary: Function used to decrypt the message.
*
* Parameters:
*  char * message - pointer to the message to be decrypted
*  uint8_t size   - size of message to be decrypted.
*
* Return:
*  void
*
*******************************************************************************/
void decrypt_message(uint8_t* message, uint8_t size)
{
    uint8_t AESBlock_count = 0;

    AESBlock_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ? \
                                                      (size/AES128_ENCRYPTION_LENGTH) \
                                                      : (1 + size/AES128_ENCRYPTION_LENGTH);

    /* Initializes the AES operation by setting key and key length */
    Cy_Crypto_Core_Aes_Init(CRYPTO, AES_Key, CY_CRYPTO_KEY_AES_128, &aesState);

    /* Start decryption operation*/
    for(int i = 0; i < AESBlock_count ; i++)
    {
        /* Perform AES ECB Decryption mode of operation */
        Cy_Crypto_Core_Aes_Ecb(CRYPTO, CY_CRYPTO_DECRYPT,\
        (decrypted_msg + AES128_ENCRYPTION_LENGTH * i), \
        (encrypted_msg + AES128_ENCRYPTION_LENGTH * i), \
        &aesState);

        /* Wait for Crypto Block to be available */
        Cy_Crypto_Core_WaitForReady(CRYPTO);
    }

    decrypted_msg[size]='\0';
    /* Print the decrypted message on the UART terminal */
    printf("\r\nResult of Decryption:\r\n\n");
    printf("%s", decrypted_msg);
    printf("%s", SCREEN_HEADER1);

    Cy_Crypto_Core_Aes_Free(CRYPTO, &aesState);
}

/* [] END OF FILE */
