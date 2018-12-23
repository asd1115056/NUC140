#include <stdio.h>
#include <string.h>
#include "NUC1xx.h"
#include "DrvGPIO.h"
#include "DrvSYS.h"
#include "DrvSPI.h"
#include "RC522.h"



typedef  unsigned long	U32;

#define MAXRLEN 18
//------------------------------------------
// SCK��ʱ	���ڷ����ٶ�
//------------------------------------------
/*void delay_ns(U32 tem)
{
	U32 i;
	for(i=0;i<tem;i++)
	{
		__nop();
	}
}*/

//------------------------------------------
// �����һ��byte 
//------------------------------------------
unsigned char SPIRByte(void)
{
	unsigned long i=60000;
	
	SPI_TX0 = 0xff;	   //���������ַ
	SPI0->CNTRL.GO_BUSY=1;

	while(i--)
	{
		if(SPI0->CNTRL.GO_BUSY==0)
			break; //Check busy
	}
	return (uint8_t)SPI_RX0;	   //������Ҫ��ȡ������
} 
//------------------------------------------
// �д��һ��byte 
//------------------------------------------
unsigned char SPIWByte(unsigned char cData)
{
	unsigned long i=60000;

	while(SPI0->CNTRL.GO_BUSY); //Check busy
	SPI_TX0 = cData;
	SPI0->CNTRL.GO_BUSY=1; //Start TX and RX

	while(i--)
	{
		if(SPI0->CNTRL.GO_BUSY==0)
			break; //Check busy
	}
	return (uint8_t)SPI_RX0;

}                          
/////////////////////////////////////////////////////////////////////
//��    �ܣ�Ѱ��
//����˵��: req_code[IN]:Ѱ����ʽ
//                0x52 = Ѱ��Ӧ�������з���14443A��׼�Ŀ�
//                0x26 = Ѱδ��������״̬�Ŀ�
//          pTagType[OUT]����Ƭ���ʹ���
//                0x4400 = Mifare_UltraLight
//                0x0400 = Mifare_One(S50)
//                0x0200 = Mifare_One(S70)
//                0x0800 = Mifare_Pro(X)
//                0x4403 = Mifare_DESFire
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdRequest(unsigned char req_code,unsigned char *pTagType)
{
	int8_t status;  
	unsigned int  unLen;
	unsigned char ucComMF522Buf[MAXRLEN]; 

	ClearBitMask(Status2Reg,0x08); //���MFCrypto1Onλ����λ����ָʾ�MFCrypto1��.��Ϊ��������֤��ȷ����1
	WriteRawRC(BitFramingReg,0x07);//���һ�ֽ����ݴ���8λ
	SetBitMask(TxControlReg,0x03); //���TX1��TX2
 
	ucComMF522Buf[0] = req_code; //request���� PICC_REQIDL 0x26/PICC_REQALL 0x52

	status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,1,ucComMF522Buf,&unLen);
	if ((status == MI_OK) && (unLen == 0x10)) //�ж�״̬�Ƿ�ɹ�������λ����Ϊ16λ
	{    
		*pTagType     = ucComMF522Buf[0]; //���ؿ�Ƭ����1
		*(pTagType+1) = ucComMF522Buf[1]; //���ؿ�Ƭ����2
	}
	else
	{   status = MI_ERR;   } //���򷵻ش���
   
	return status;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ�����ײ
//����˵��: pSnr[OUT]:��Ƭ���кţ�4�ֽ�
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////  
int8_t PcdAnticoll(unsigned char *pSnr)
{
    int8_t status;
    unsigned char i,snr_check=0;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 
    

    ClearBitMask(Status2Reg,0x08); //���RC522 MFCrypto1Onλ
    WriteRawRC(BitFramingReg,0x00); //���BitFramingReg�Ĵ���
    ClearBitMask(CollReg,0x80); //���н���λ��ͻ�����
 
    ucComMF522Buf[0] = PICC_ANTICOLL1; //PICC_ANTICOLL1   0x93   //����ײ
    ucComMF522Buf[1] = 0x20; //?

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,2,ucComMF522Buf,&unLen);

    if (status == MI_OK)
    {
    	 for (i=0; i<4; i++)
         {   
             *(pSnr+i)  = ucComMF522Buf[i]; //��ȡ���ص�4�ֽ����к�
             snr_check ^= ucComMF522Buf[i]; //���кż����ֽڵ���ǰ4byte�����ֵ
         }
         if (snr_check != ucComMF522Buf[i]) //������ֵ�Ƿ��뷵�ص�У��ֵ�Ƿ���ͬ
         {   status = MI_ERR;    }
    }
    
    SetBitMask(CollReg,0x80); //����valueaftercollλ
    return status;//����״̬
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ�ѡ����Ƭ
//����˵��: pSnr[IN]:��Ƭ���кţ�4�ֽ�
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdSelect(unsigned char *pSnr)
{
    int8_t status;
    unsigned char i;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 
    
    ucComMF522Buf[0] = PICC_ANTICOLL1;
    ucComMF522Buf[1] = 0x70; //����ײ������ŷ���0x70H�����select
    ucComMF522Buf[6] = 0;
    for (i=0; i<4; i++)
    {
    	ucComMF522Buf[i+2] = *(pSnr+i); //���鸽�Ͽ����к�
    	ucComMF522Buf[6]  ^= *(pSnr+i); //У���ֽ�
    }
    CalulateCRC(ucComMF522Buf,7,&ucComMF522Buf[7]); //��ucComMF522Buf����д��RC522.������RC522CRC16��У��ֵ
  
    ClearBitMask(Status2Reg,0x08);////���RC522 MFCrypto1Onλ

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,9,ucComMF522Buf,&unLen); //��CRCУ�������ݷ��͵�RC522
    
    if ((status == MI_OK) && (unLen == 0x18)) //
    {   status = MI_OK;  } 
    else
    {   status = MI_ERR;    }

    return status;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ���֤��Ƭ����
//����˵��: auth_mode[IN]: ������֤ģʽ
//                 0x60 = ��֤A��Կ
//                 0x61 = ��֤B��Կ 
//          addr[IN]�����ַ
//          pKey[IN]������
//          pSnr[IN]����Ƭ���кţ�4�ֽ�
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////               
int8_t PcdAuthState(unsigned char auth_mode,unsigned char addr,unsigned char *pKey,unsigned char *pSnr)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char i,ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = auth_mode; //����ģʽ
    ucComMF522Buf[1] = addr;//���ַ
    for (i=0; i<6; i++)
    {    ucComMF522Buf[i+2] = *(pKey+i);   } //�����ڼ�������
    for (i=0; i<4; i++)
    {    ucComMF522Buf[i+8] = *(pSnr+i);   }//�����ڼ������к� 
 //   memcpy(&ucComMF522Buf[2], pKey, 6); 
 //   memcpy(&ucComMF522Buf[8], pSnr, 4); 
    
    status = PcdComMF522(PCD_AUTHENT,ucComMF522Buf,12,ucComMF522Buf,&unLen);
    if ((status != MI_OK) || (!(ReadRawRC(Status2Reg) & 0x08)))
    {   status = MI_ERR;   }
    
    return status;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ���ȡM1��һ������
//����˵��: addr[IN]�����ַ
//          pData[OUT]�����������ݣ�16�ֽ�
//��    ��: �ɹ�����MI_OK
///////////////////////////////////////////////////////////////////// 
int8_t PcdRead(unsigned char addr,unsigned char *pData)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char i,ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_READ;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]); //����CRC16ֵ
   
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);
    if ((status == MI_OK) && (unLen == 0x90))
 //   {   memcpy(pData, ucComMF522Buf, 16);   }
    {
        for (i=0; i<16; i++)
        {    *(pData+i) = ucComMF522Buf[i];   }
    }
    else
    {   status = MI_ERR;   }
    
    return status;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ�д���ݵ�M1��һ��
//����˵��: addr[IN]�����ַ
//          pData[IN]��д������ݣ�16�ֽ�
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////                  
int8_t PcdWrite(unsigned char addr,unsigned char *pData)
{
   int8_t status;
    unsigned int  unLen;
    unsigned char i,ucComMF522Buf[MAXRLEN]; 
    
    ucComMF522Buf[0] = PICC_WRITE;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }
        
    if (status == MI_OK)
    {
        //memcpy(ucComMF522Buf, pData, 16);
        for (i=0; i<16; i++)
        {    ucComMF522Buf[i] = *(pData+i);   }
        CalulateCRC(ucComMF522Buf,16,&ucComMF522Buf[16]);

        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,18,ucComMF522Buf,&unLen);
        if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
        {   status = MI_ERR;   }
    }
    
    return status;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ����Ƭ��������״̬
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdHalt(void)
{
 //   int8_t status;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_HALT;
    ucComMF522Buf[1] = 0;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
  //  status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);
 	 PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    return MI_OK;
}

/////////////////////////////////////////////////////////////////////
//��MF522����CRC16����
//pIndata��������
//�������
/////////////////////////////////////////////////////////////////////
void CalulateCRC(unsigned char *pIndata,unsigned char len,unsigned char *pOutData)
{
    unsigned char i,n;
    ClearBitMask(DivIrqReg,0x04); //���CRCIrqλ
    WriteRawRC(CommandReg,PCD_IDLE);//RC522�������ģʽ
    SetBitMask(FIFOLevelReg,0x80);//���FIFO��дָ���Լ������־
    for (i=0; i<len; i++)
    {   WriteRawRC(FIFODataReg, *(pIndata+i));   } //������д��RC522
    WriteRawRC(CommandReg, PCD_CALCCRC); //������ʼ���㲢����CRC������
    i = 0xFF;
    do 
    {
        n = ReadRawRC(DivIrqReg); //��ȡ�Ĵ���
        i--;
    }
    while ((i!=0) && !(n&0x04));//����Ƿ����CRCIRQ�ж�
    pOutData[0] = ReadRawRC(CRCResultRegL);//��ȡCRC16У����ɺ�ĵ��ֽ�����
    pOutData[1] = ReadRawRC(CRCResultRegM);//��ȡCRC16У����ɺ�ĵ��ֽ�����
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ���λRC522
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdReset(void)
{
	DrvGPIO_SetBit(E_GPE, 5);
    DrvSYS_Delay(10);
	DrvGPIO_ClrBit(E_GPE, 5);;
    DrvSYS_Delay(10);
	DrvGPIO_SetBit(E_GPE, 5);;//��λ
    DrvSYS_Delay(10);
    WriteRawRC(CommandReg,PCD_RESETPHASE); //softreset
    DrvSYS_Delay(10);
    
    WriteRawRC(ModeReg,0x3D);            //��Mifare��ͨѶ��CRC��ʼֵ0x6363 	����������
    WriteRawRC(TReloadRegL,30);      //��ʱ����װ��8λ   0x1e    //��ʱ��
    WriteRawRC(TReloadRegH,0);		//��ʱ����װ��8λ  
    WriteRawRC(TModeReg,0x8D);	//tauto��λ����ʱ�����������ʵķ��ͽ���ʱ�Զ��������ڽ��յ���һ����Ч����λ��ֹͣ
								//�����λ��������Э��Ӱ�졣Tprescalser_Hi=0xd
    WriteRawRC(TPrescalerReg,0x3E);//Tprescaler_Lo=0x3e 
	
	WriteRawRC(TxAutoReg,0x40);//����Ҫ �������õ��Ʒ�ʽ
   
    return MI_OK;
}
//////////////////////////////////////////////////////////////////////
//����RC632�Ĺ�����ʽ 
//////////////////////////////////////////////////////////////////////
int8_t M500PcdConfigISOType(unsigned char type)
{
   if (type == 'A')                     //ISO14443_A //�ж�Э������
   { 
       ClearBitMask(Status2Reg,0x08); //���RC522 MFCrypto1Onλ

 /*     WriteRawRC(CommandReg,0x20);    //as default   
       WriteRawRC(ComIEnReg,0x80);     //as default
       WriteRawRC(DivlEnReg,0x0);      //as default
	   WriteRawRC(ComIrqReg,0x04);     //as default
	   WriteRawRC(DivIrqReg,0x0);      //as default
	   WriteRawRC(Status2Reg,0x0);//80    //trun off temperature sensor
	   WriteRawRC(WaterLevelReg,0x08); //as default
       WriteRawRC(ControlReg,0x20);    //as default
	   WriteRawRC(CollReg,0x80);    //as default
*/
       WriteRawRC(ModeReg,0x3D); //3F //��Mifare��ͨѶ��CRC��ʼֵ0x6363 	����������
/*	   WriteRawRC(TxModeReg,0x0);      //as default???
	   WriteRawRC(RxModeReg,0x0);      //as default???
	   WriteRawRC(TxControlReg,0x80);  //as default???

	   WriteRawRC(TxSelReg,0x10);      //as default???
   */
       WriteRawRC(RxSelReg,0x86);//84 �ڲ�ģ���źŵ��� RXwait=0x06Ϊ֡����ʱ��
 //      WriteRawRC(RxThresholdReg,0x84);//as default
 //      WriteRawRC(DemodReg,0x4D);      //as default

 //      WriteRawRC(ModWidthReg,0x13);//26
       WriteRawRC(RFCfgReg,0x7F);   //4F //�����źŵ����� 0x7Ϊ48db
	/*   WriteRawRC(GsNReg,0x88);        //as default???
	   WriteRawRC(CWGsCfgReg,0x20);    //as default???
       WriteRawRC(ModGsCfgReg,0x20);   //as default???
*/
   	   WriteRawRC(TReloadRegL,30);//tmoLength);// TReloadVal = 'h6a =tmoLength(dec) //��ʱ����װ��8λ   0x1e    //��ʱ��
	   WriteRawRC(TReloadRegH,0); //��ʱ���ظ�8λ   0x1e    //��ʱ��
       WriteRawRC(TModeReg,0x8D);//tauto��λ����ʱ�����������ʵķ��ͽ���ʱ�Զ��������ڽ��յ���һ����Ч����λ��ֹͣ
								//�����λ��������Э��Ӱ�졣Tprescalser_Hi=0xd
	   WriteRawRC(TPrescalerReg,0x3E);
	   

  //     PcdSetTmo(106);
	   DrvSYS_Delay(1000);
       PcdAntennaOn();
   }
   else{ return -1; }
   
   return MI_OK;
}
/////////////////////////////////////////////////////////////////////
//��    �ܣ���RC632�Ĵ���
//����˵����Address[IN]:�Ĵ�����ַ
//��    �أ�������ֵ
/////////////////////////////////////////////////////////////////////
unsigned char ReadRawRC(unsigned char Address)
{
    unsigned char ucAddr;
    unsigned char ucResult=0;

	SPI0->SSR.SSR = 1;
    ucAddr = ((Address<<1)&0x7E)|0x80;

	SPIWByte(ucAddr);
	ucResult=SPIRByte();

	SPI0->SSR.SSR = 0;
    return ucResult;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ�дRC632�Ĵ���
//����˵����Address[IN]:�Ĵ�����ַ
//          value[IN]:д���ֵ
/////////////////////////////////////////////////////////////////////
void WriteRawRC(unsigned char Address, unsigned char value)
{  
    unsigned char ucAddr;

	SPI0->SSR.SSR = 1;
    ucAddr = ((Address<<1)&0x7E);

	SPIWByte(ucAddr);
	SPIWByte(value);
	
	SPI0 ->SSR.SSR = 0;//SS
}
/////////////////////////////////////////////////////////////////////
//��    �ܣ���RC522�Ĵ���λ
//����˵����reg[IN]:�Ĵ�����ַ
//          mask[IN]:��λֵ
/////////////////////////////////////////////////////////////////////
void SetBitMask(unsigned char reg,unsigned char mask)  
{
    char tmp = 0x0;
    tmp = ReadRawRC(reg);
    WriteRawRC(reg,tmp | mask);  // set bit mask
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ���RC522�Ĵ���λ
//����˵����reg[IN]:�Ĵ�����ַ
//          mask[IN]:��λֵ
/////////////////////////////////////////////////////////////////////
void ClearBitMask(unsigned char reg,unsigned char mask)  
{
    char tmp = 0x0;
    tmp = ReadRawRC(reg);
    WriteRawRC(reg, tmp & ~mask);  // clear bit mask
} 

/////////////////////////////////////////////////////////////////////
//��    �ܣ�ͨ��RC522��ISO14443��ͨѶ
//����˵����Command[IN]:RC522������
//          pInData[IN]:ͨ��RC522���͵���Ƭ������
//          InLenByte[IN]:�������ݵ��ֽڳ���
//          pOutData[OUT]:���յ��Ŀ�Ƭ��������
//          *pOutLenBit[OUT]:�������ݵ�λ����
/////////////////////////////////////////////////////////////////////
int8_t PcdComMF522(unsigned char Command, 
                 unsigned char *pInData, 
                 unsigned char InLenByte,
                 unsigned char *pOutData, 
                 unsigned int  *pOutLenBit)
{
    int8_t status = MI_ERR;
    unsigned char irqEn   = 0x00;
    unsigned char waitFor = 0x00;
    unsigned char lastBits;
    unsigned char n;
    unsigned int i;
    switch (Command) //���ݲ�ͬ��������в�ͬ���ж�����
    {
        case PCD_AUTHENT:
			irqEn   = 0x12; //��������ж����󴫵ݵ�IRQ�ܽ�
			waitFor = 0x10; //�ж�ָʾ IdleIRq����λ
			break;
		case PCD_TRANSCEIVE:
			irqEn   = 0x77; //����TXIEn,RXIEn,IdleIEN,LoAlertIRN,ErrIEn,TimerIEn
			waitFor = 0x30; //�ж�ָʾ,RXIRq��IdleIRq����λ
			break;
		default:
			break;
    }
   
    WriteRawRC(ComIEnReg,irqEn|0x80);//��λIRqInvλ
    ClearBitMask(ComIrqReg,0x80); //IRQ�ܽſ�©���
    WriteRawRC(CommandReg,PCD_IDLE);//ȡ�����в�������վ����IDLEģʽ
    SetBitMask(FIFOLevelReg,0x80);//��λFlushBuffer���ڲ�FIFO�������Ķ���дָ���Լ��Ĵ���ErrReg��BufferOvfl��־λ�����
    
    for (i=0; i<InLenByte; i++)
    {   WriteRawRC(FIFODataReg, pInData[i]);    } //���վд��InLenByte��������
    WriteRawRC(CommandReg, Command);  //���վд����Ҫִ�е�����
   
    
    if (Command == PCD_TRANSCEIVE)           //�ж�����Ϊ���Ͳ���������
    {    SetBitMask(BitFramingReg,0x80);  }  //��λBitFramingReg_StartSendλ��������
    
    //i = 600;//����ʱ��Ƶ�ʵ���������M1�����ȴ�ʱ��25ms
	i = 4000;  //��ʱ
    do 
    {
        n = ReadRawRC(ComIrqReg); //��ѯ��վ���ж�
        i--;
    }
    while ((i!=0) && !(n&0x01) && !(n&waitFor));
	/*1.��i����0ʱ����ѭ��
	  2.������RC522��ʱ��,���Ҷ�ʱ��timer value�Ĵ���ֵ����0ʱ����ѭ��
	  3.1 �����ΪPCD_AUTHENT��PCD_TRANSCEIVʱ��ֱ������ѭ��
	  3.2 ������ΪPCD_AUTHENTʱ��ʱ�����ܼ���0.IdleIRq��λ,����ѭ��
	  3.3 ������ΪPCD_TRANSCEIVE RXIRq��IdleIRq��λ,����ѭ��.������һ����Ч���������ߴ������������ı���������ѭ��*/
    ClearBitMask(BitFramingReg,0x80); //�رշ���

    if (i!=0) //������ǳ�ʱ����
    {    
        if(!(ReadRawRC(ErrorReg)&0x1B)) //�жϴ����־�Ĵ������Ƿ����BufferOvfl,CollErr,ParityErr,ProtocolErr.
        {
            status = MI_OK; //���û�г�������������״̬����ΪMI_OK=0
            if (n & irqEn & 0x01)
            {   status = MI_NOTAGERR;   } //�ж��Ƿ�ʱ���߲���ָ��
            if (Command == PCD_TRANSCEIVE)
            {
               	n = ReadRawRC(FIFOLevelReg); //��ȡFIFO������ֽ���
              	lastBits = ReadRawRC(ControlReg) & 0x07;//��ѯ�������ֽڵ���Чλ��
                if (lastBits) //������һ�ֽ���ЧΪ0<lastBit<8
                {   *pOutLenBit = (n-1)*8 + lastBits;   } //�������ݵ�λ���ȵ���FIFO�ڽ��յ�����(n-1)*8�������һ�ֽ������ڵ���Чλ
                else //�������0�����һ�ֽ�����λ��Ч
                {   *pOutLenBit = n*8;   } //��Χ����ЧλΪFIFO�������ݵ���*8
                if (n == 0)  //���n=0��FIFO�ڲ�û������
                {   n = 1;    }
                if (n > MAXRLEN)//���n>��󻺳���
                {   n = MAXRLEN;   }//��n������󻺳���
                for (i=0; i<n; i++)
                {   pOutData[i] = ReadRawRC(FIFODataReg);    } //���FIFO������
            }
        }
        else//������ִ����־�򷵻ش���
        {   status = MI_ERR;   }
        
    }
   

    SetBitMask(ControlReg,0x80);           // stop timer now
    WriteRawRC(CommandReg,PCD_IDLE);    //RC522�������ģʽ
    return status; //����RC522�������״̬
}

/////////////////////////////////////////////////////////////////////
//��������  
//ÿ��������ر����շ���֮��Ӧ������1ms�ļ��
/////////////////////////////////////////////////////////////////////
void PcdAntennaOn(void)
{
    unsigned char i;
    i = ReadRawRC(TxControlReg);
    if (!(i & 0x03)) //��TX1��TX2
    {
        SetBitMask(TxControlReg, 0x03);
    }
}


/////////////////////////////////////////////////////////////////////
//�ر�����
/////////////////////////////////////////////////////////////////////
void PcdAntennaOff(void)
{
	ClearBitMask(TxControlReg, 0x03); //�ر�TX1��TX2
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ��ۿ�ͳ�ֵ
//����˵��: dd_mode[IN]��������
//               0xC0 = �ۿ�
//               0xC1 = ��ֵ
//          addr[IN]��Ǯ����ַ
//          pValue[IN]��4�ֽ���(��)ֵ����λ��ǰ
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////                 
int8_t PcdValue(unsigned char dd_mode,unsigned char addr,unsigned char *pValue)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 
    //unsigned char i;
	
    ucComMF522Buf[0] = dd_mode;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);//����CRC16�����浽������
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);//�����鷢�͵�FIFO�������տ����ص�����

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }
        
    if (status == MI_OK)
    {
        memcpy(ucComMF522Buf, pValue, 4);//�����ڴ�����
        //for (i=0; i<16; i++)
        //{    ucComMF522Buf[i] = *(pValue+i);   }
        CalulateCRC(ucComMF522Buf,4,&ucComMF522Buf[4]);
        unLen = 0;
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,6,ucComMF522Buf,&unLen);//��Ҫ�޸ĵ�Ǯ����CRC16ֵ������FIFO�����ؽ�������ݳ���
		if (status != MI_ERR)
        {    status = MI_OK;    }
    }
    
    if (status == MI_OK)
    {
        ucComMF522Buf[0] = PICC_TRANSFER;
        ucComMF522Buf[1] = addr;
        CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]); 
   
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

        if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
        {   status = MI_ERR;   }
    }
    return status;
}

/////////////////////////////////////////////////////////////////////
//��    �ܣ�����Ǯ��
//����˵��: sourceaddr[IN]��Դ��ַ
//          goaladdr[IN]��Ŀ���ַ
//��    ��: �ɹ�����MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdBakValue(unsigned char sourceaddr, unsigned char goaladdr)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_RESTORE;
    ucComMF522Buf[1] = sourceaddr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }
    
    if (status == MI_OK)
    {
        ucComMF522Buf[0] = 0;
        ucComMF522Buf[1] = 0;
        ucComMF522Buf[2] = 0;
        ucComMF522Buf[3] = 0;
        CalulateCRC(ucComMF522Buf,4,&ucComMF522Buf[4]);
 
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,6,ucComMF522Buf,&unLen);
		if (status != MI_ERR)
        {    status = MI_OK;    }
    }
    
    if (status != MI_OK)
    {    return MI_ERR;   }
    
    ucComMF522Buf[0] = PICC_TRANSFER;
    ucComMF522Buf[1] = goaladdr;

    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }

    return status;
}



