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
// SCK延时	调节发送速度
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
// 读慈胍桓鯾yte 
//------------------------------------------
unsigned char SPIRByte(void)
{
	unsigned long i=60000;
	
	SPI_TX0 = 0xff;	   //发送任意地址
	SPI0->CNTRL.GO_BUSY=1;

	while(i--)
	{
		if(SPI0->CNTRL.GO_BUSY==0)
			break; //Check busy
	}
	return (uint8_t)SPI_RX0;	   //返回需要读取的数据
} 
//------------------------------------------
// 列慈胍桓鯾yte 
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
//功    能：寻卡
//参数说明: req_code[IN]:寻卡方式
//                0x52 = 寻感应区内所有符合14443A标准的卡
//                0x26 = 寻未进入休眠状态的卡
//          pTagType[OUT]：卡片类型代码
//                0x4400 = Mifare_UltraLight
//                0x0400 = Mifare_One(S50)
//                0x0200 = Mifare_One(S70)
//                0x0800 = Mifare_Pro(X)
//                0x4403 = Mifare_DESFire
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdRequest(unsigned char req_code,unsigned char *pTagType)
{
	int8_t status;  
	unsigned int  unLen;
	unsigned char ucComMF522Buf[MAXRLEN]; 

	ClearBitMask(Status2Reg,0x08); //清除MFCrypto1On位，此位用于指示齅FCrypto1打开.改为在密码认证正确后置1
	WriteRawRC(BitFramingReg,0x07);//最后一字节数据传输8位
	SetBitMask(TxControlReg,0x03); //输出TX1，TX2
 
	ucComMF522Buf[0] = req_code; //request命令 PICC_REQIDL 0x26/PICC_REQALL 0x52

	status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,1,ucComMF522Buf,&unLen);
	if ((status == MI_OK) && (unLen == 0x10)) //判断状态是否成功，数据位长度为16位
	{    
		*pTagType     = ucComMF522Buf[0]; //返回卡片类型1
		*(pTagType+1) = ucComMF522Buf[1]; //返回卡片类型2
	}
	else
	{   status = MI_ERR;   } //否则返回错误
   
	return status;
}

/////////////////////////////////////////////////////////////////////
//功    能：防冲撞
//参数说明: pSnr[OUT]:卡片序列号，4字节
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////  
int8_t PcdAnticoll(unsigned char *pSnr)
{
    int8_t status;
    unsigned char i,snr_check=0;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 
    

    ClearBitMask(Status2Reg,0x08); //清除RC522 MFCrypto1On位
    WriteRawRC(BitFramingReg,0x00); //清除BitFramingReg寄存器
    ClearBitMask(CollReg,0x80); //所有接收位冲突后被清除
 
    ucComMF522Buf[0] = PICC_ANTICOLL1; //PICC_ANTICOLL1   0x93   //防冲撞
    ucComMF522Buf[1] = 0x20; //?

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,2,ucComMF522Buf,&unLen);

    if (status == MI_OK)
    {
    	 for (i=0; i<4; i++)
         {   
             *(pSnr+i)  = ucComMF522Buf[i]; //读取返回的4字节序列号
             snr_check ^= ucComMF522Buf[i]; //序列号检验字节等于前4byte的异或值
         }
         if (snr_check != ucComMF522Buf[i]) //检查异或值是否与返回的校验值是否相同
         {   status = MI_ERR;    }
    }
    
    SetBitMask(CollReg,0x80); //设置valueaftercoll位
    return status;//返回状态
}

/////////////////////////////////////////////////////////////////////
//功    能：选定卡片
//参数说明: pSnr[IN]:卡片序列号，4字节
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdSelect(unsigned char *pSnr)
{
    int8_t status;
    unsigned char i;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 
    
    ucComMF522Buf[0] = PICC_ANTICOLL1;
    ucComMF522Buf[1] = 0x70; //防冲撞后紧接着发送0x70H则进行select
    ucComMF522Buf[6] = 0;
    for (i=0; i<4; i++)
    {
    	ucComMF522Buf[i+2] = *(pSnr+i); //数组附上卡序列号
    	ucComMF522Buf[6]  ^= *(pSnr+i); //校验字节
    }
    CalulateCRC(ucComMF522Buf,7,&ucComMF522Buf[7]); //将ucComMF522Buf数组写入RC522.并返回RC522CRC16的校验值
  
    ClearBitMask(Status2Reg,0x08);////清除RC522 MFCrypto1On位

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,9,ucComMF522Buf,&unLen); //将CRC校验后的数据发送到RC522
    
    if ((status == MI_OK) && (unLen == 0x18)) //
    {   status = MI_OK;  } 
    else
    {   status = MI_ERR;    }

    return status;
}

/////////////////////////////////////////////////////////////////////
//功    能：验证卡片密码
//参数说明: auth_mode[IN]: 密码验证模式
//                 0x60 = 验证A密钥
//                 0x61 = 验证B密钥 
//          addr[IN]：块地址
//          pKey[IN]：密码
//          pSnr[IN]：卡片序列号，4字节
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////               
int8_t PcdAuthState(unsigned char auth_mode,unsigned char addr,unsigned char *pKey,unsigned char *pSnr)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char i,ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = auth_mode; //密码模式
    ucComMF522Buf[1] = addr;//块地址
    for (i=0; i<6; i++)
    {    ucComMF522Buf[i+2] = *(pKey+i);   } //数组内加入密码
    for (i=0; i<4; i++)
    {    ucComMF522Buf[i+8] = *(pSnr+i);   }//数组内加入序列号 
 //   memcpy(&ucComMF522Buf[2], pKey, 6); 
 //   memcpy(&ucComMF522Buf[8], pSnr, 4); 
    
    status = PcdComMF522(PCD_AUTHENT,ucComMF522Buf,12,ucComMF522Buf,&unLen);
    if ((status != MI_OK) || (!(ReadRawRC(Status2Reg) & 0x08)))
    {   status = MI_ERR;   }
    
    return status;
}

/////////////////////////////////////////////////////////////////////
//功    能：读取M1卡一块数据
//参数说明: addr[IN]：块地址
//          pData[OUT]：读出的数据，16字节
//返    回: 成功返回MI_OK
///////////////////////////////////////////////////////////////////// 
int8_t PcdRead(unsigned char addr,unsigned char *pData)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char i,ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_READ;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]); //计算CRC16值
   
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
//功    能：写数据到M1卡一块
//参数说明: addr[IN]：块地址
//          pData[IN]：写入的数据，16字节
//返    回: 成功返回MI_OK
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
//功    能：命令卡片进入休眠状态
//返    回: 成功返回MI_OK
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
//用MF522计算CRC16函数
//pIndata输入数据
//输出数据
/////////////////////////////////////////////////////////////////////
void CalulateCRC(unsigned char *pIndata,unsigned char len,unsigned char *pOutData)
{
    unsigned char i,n;
    ClearBitMask(DivIrqReg,0x04); //清除CRCIrq位
    WriteRawRC(CommandReg,PCD_IDLE);//RC522进入待机模式
    SetBitMask(FIFOLevelReg,0x80);//清除FIFO读写指针以及错误标志
    for (i=0; i<len; i++)
    {   WriteRawRC(FIFODataReg, *(pIndata+i));   } //将数据写入RC522
    WriteRawRC(CommandReg, PCD_CALCCRC); //发出开始计算并测试CRC的命令
    i = 0xFF;
    do 
    {
        n = ReadRawRC(DivIrqReg); //读取寄存器
        i--;
    }
    while ((i!=0) && !(n&0x04));//检查是否产生CRCIRQ中断
    pOutData[0] = ReadRawRC(CRCResultRegL);//读取CRC16校验完成后的低字节内容
    pOutData[1] = ReadRawRC(CRCResultRegM);//读取CRC16校验完成后的低字节内容
}

/////////////////////////////////////////////////////////////////////
//功    能：复位RC522
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////
int8_t PcdReset(void)
{
	DrvGPIO_SetBit(E_GPE, 5);
    DrvSYS_Delay(10);
	DrvGPIO_ClrBit(E_GPE, 5);;
    DrvSYS_Delay(10);
	DrvGPIO_SetBit(E_GPE, 5);;//复位
    DrvSYS_Delay(10);
    WriteRawRC(CommandReg,PCD_RESETPHASE); //softreset
    DrvSYS_Delay(10);
    
    WriteRawRC(ModeReg,0x3D);            //和Mifare卡通讯，CRC初始值0x6363 	发送器启动
    WriteRawRC(TReloadRegL,30);      //定时器重装低8位   0x1e    //定时器
    WriteRawRC(TReloadRegH,0);		//定时器重装高8位  
    WriteRawRC(TModeReg,0x8D);	//tauto置位，定时器在所有速率的发送结束时自动启动，在接收到第一个有效数据位后停止
								//如果该位清零则不受协议影响。Tprescalser_Hi=0xd
    WriteRawRC(TPrescalerReg,0x3E);//Tprescaler_Lo=0x3e 
	
	WriteRawRC(TxAutoReg,0x40);//必须要 用于设置调制方式
   
    return MI_OK;
}
//////////////////////////////////////////////////////////////////////
//设置RC632的工作方式 
//////////////////////////////////////////////////////////////////////
int8_t M500PcdConfigISOType(unsigned char type)
{
   if (type == 'A')                     //ISO14443_A //判断协议类型
   { 
       ClearBitMask(Status2Reg,0x08); //清除RC522 MFCrypto1On位

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
       WriteRawRC(ModeReg,0x3D); //3F //和Mifare卡通讯，CRC初始值0x6363 	发送器启动
/*	   WriteRawRC(TxModeReg,0x0);      //as default???
	   WriteRawRC(RxModeReg,0x0);      //as default???
	   WriteRawRC(TxControlReg,0x80);  //as default???

	   WriteRawRC(TxSelReg,0x10);      //as default???
   */
       WriteRawRC(RxSelReg,0x86);//84 内部模拟信号调制 RXwait=0x06为帧保护时间
 //      WriteRawRC(RxThresholdReg,0x84);//as default
 //      WriteRawRC(DemodReg,0x4D);      //as default

 //      WriteRawRC(ModWidthReg,0x13);//26
       WriteRawRC(RFCfgReg,0x7F);   //4F //接收信号的增益 0x7为48db
	/*   WriteRawRC(GsNReg,0x88);        //as default???
	   WriteRawRC(CWGsCfgReg,0x20);    //as default???
       WriteRawRC(ModGsCfgReg,0x20);   //as default???
*/
   	   WriteRawRC(TReloadRegL,30);//tmoLength);// TReloadVal = 'h6a =tmoLength(dec) //定时器重装低8位   0x1e    //定时器
	   WriteRawRC(TReloadRegH,0); //定时器重高8位   0x1e    //定时器
       WriteRawRC(TModeReg,0x8D);//tauto置位，定时器在所有速率的发送结束时自动启动，在接收到第一个有效数据位后停止
								//如果该位清零则不受协议影响。Tprescalser_Hi=0xd
	   WriteRawRC(TPrescalerReg,0x3E);
	   

  //     PcdSetTmo(106);
	   DrvSYS_Delay(1000);
       PcdAntennaOn();
   }
   else{ return -1; }
   
   return MI_OK;
}
/////////////////////////////////////////////////////////////////////
//功    能：读RC632寄存器
//参数说明：Address[IN]:寄存器地址
//返    回：读出的值
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
//功    能：写RC632寄存器
//参数说明：Address[IN]:寄存器地址
//          value[IN]:写入的值
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
//功    能：置RC522寄存器位
//参数说明：reg[IN]:寄存器地址
//          mask[IN]:置位值
/////////////////////////////////////////////////////////////////////
void SetBitMask(unsigned char reg,unsigned char mask)  
{
    char tmp = 0x0;
    tmp = ReadRawRC(reg);
    WriteRawRC(reg,tmp | mask);  // set bit mask
}

/////////////////////////////////////////////////////////////////////
//功    能：清RC522寄存器位
//参数说明：reg[IN]:寄存器地址
//          mask[IN]:清位值
/////////////////////////////////////////////////////////////////////
void ClearBitMask(unsigned char reg,unsigned char mask)  
{
    char tmp = 0x0;
    tmp = ReadRawRC(reg);
    WriteRawRC(reg, tmp & ~mask);  // clear bit mask
} 

/////////////////////////////////////////////////////////////////////
//功    能：通过RC522和ISO14443卡通讯
//参数说明：Command[IN]:RC522命令字
//          pInData[IN]:通过RC522发送到卡片的数据
//          InLenByte[IN]:发送数据的字节长度
//          pOutData[OUT]:接收到的卡片返回数据
//          *pOutLenBit[OUT]:返回数据的位长度
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
    switch (Command) //根据不同的命令进行不同的中断设置
    {
        case PCD_AUTHENT:
			irqEn   = 0x12; //允许空闲中断请求传递到IRQ管脚
			waitFor = 0x10; //中断指示 IdleIRq被置位
			break;
		case PCD_TRANSCEIVE:
			irqEn   = 0x77; //允许TXIEn,RXIEn,IdleIEN,LoAlertIRN,ErrIEn,TimerIEn
			waitFor = 0x30; //中断指示,RXIRq和IdleIRq被置位
			break;
		default:
			break;
    }
   
    WriteRawRC(ComIEnReg,irqEn|0x80);//置位IRqInv位
    ClearBitMask(ComIrqReg,0x80); //IRQ管脚开漏输出
    WriteRawRC(CommandReg,PCD_IDLE);//取消所有操作，基站进入IDLE模式
    SetBitMask(FIFOLevelReg,0x80);//置位FlushBuffer，内部FIFO缓冲区的读和写指针以及寄存器ErrReg的BufferOvfl标志位被清除
    
    for (i=0; i<InLenByte; i++)
    {   WriteRawRC(FIFODataReg, pInData[i]);    } //向基站写入InLenByte长的数据
    WriteRawRC(CommandReg, Command);  //向基站写入需要执行的命令
   
    
    if (Command == PCD_TRANSCEIVE)           //判断命令为发送并接收数据
    {    SetBitMask(BitFramingReg,0x80);  }  //置位BitFramingReg_StartSend位启动发送
    
    //i = 600;//根据时钟频率调整，操作M1卡最大等待时间25ms
	i = 4000;  //延时
    do 
    {
        n = ReadRawRC(ComIrqReg); //查询基站的中断
        i--;
    }
    while ((i!=0) && !(n&0x01) && !(n&waitFor));
	/*1.当i减到0时跳出循环
	  2.当设置RC522定时器,并且定时器timer value寄存器值减到0时跳出循环
	  3.1 当命令不为PCD_AUTHENT、PCD_TRANSCEIV时，直接跳出循环
	  3.2 当命令为PCD_AUTHENT时定时器不能减到0.IdleIRq置位,跳出循环
	  3.3 当命令为PCD_TRANSCEIVE RXIRq和IdleIRq置位,跳出循环.即接收一个有效数据流或者处理过程中命令改变则跳出该循环*/
    ClearBitMask(BitFramingReg,0x80); //关闭发送

    if (i!=0) //如果不是超时跳出
    {    
        if(!(ReadRawRC(ErrorReg)&0x1B)) //判断错误标志寄存器中是否出现BufferOvfl,CollErr,ParityErr,ProtocolErr.
        {
            status = MI_OK; //如果没有出现上述错误，则状态变量为MI_OK=0
            if (n & irqEn & 0x01)
            {   status = MI_NOTAGERR;   } //判断是否超时或者操作指令
            if (Command == PCD_TRANSCEIVE)
            {
               	n = ReadRawRC(FIFOLevelReg); //读取FIFO保存的字节数
              	lastBits = ReadRawRC(ControlReg) & 0x07;//查询最后接收字节的有效位数
                if (lastBits) //如果最后一字节有效为0<lastBit<8
                {   *pOutLenBit = (n-1)*8 + lastBits;   } //返回数据的位长度等于FIFO内接收的数据(n-1)*8加上最后一字节数据内的有效位
                else //如果等于0则最后一字节所有位有效
                {   *pOutLenBit = n*8;   } //范围的有效位为FIFO接收数据的量*8
                if (n == 0)  //如果n=0则FIFO内部没有数据
                {   n = 1;    }
                if (n > MAXRLEN)//如果n>最大缓冲数
                {   n = MAXRLEN;   }//则n等于最大缓冲数
                for (i=0; i<n; i++)
                {   pOutData[i] = ReadRawRC(FIFODataReg);    } //输出FIFO的数据
            }
        }
        else//如果出现错误标志则返回错误
        {   status = MI_ERR;   }
        
    }
   

    SetBitMask(ControlReg,0x80);           // stop timer now
    WriteRawRC(CommandReg,PCD_IDLE);    //RC522进入待机模式
    return status; //返回RC522操作后的状态
}

/////////////////////////////////////////////////////////////////////
//开启天线  
//每次启动或关闭天险发射之间应至少有1ms的间隔
/////////////////////////////////////////////////////////////////////
void PcdAntennaOn(void)
{
    unsigned char i;
    i = ReadRawRC(TxControlReg);
    if (!(i & 0x03)) //打开TX1和TX2
    {
        SetBitMask(TxControlReg, 0x03);
    }
}


/////////////////////////////////////////////////////////////////////
//关闭天线
/////////////////////////////////////////////////////////////////////
void PcdAntennaOff(void)
{
	ClearBitMask(TxControlReg, 0x03); //关闭TX1和TX2
}

/////////////////////////////////////////////////////////////////////
//功    能：扣款和充值
//参数说明: dd_mode[IN]：命令字
//               0xC0 = 扣款
//               0xC1 = 充值
//          addr[IN]：钱包地址
//          pValue[IN]：4字节增(减)值，低位在前
//返    回: 成功返回MI_OK
/////////////////////////////////////////////////////////////////////                 
int8_t PcdValue(unsigned char dd_mode,unsigned char addr,unsigned char *pValue)
{
    int8_t status;
    unsigned int  unLen;
    unsigned char ucComMF522Buf[MAXRLEN]; 
    //unsigned char i;
	
    ucComMF522Buf[0] = dd_mode;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);//计算CRC16并保存到数组中
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);//将数组发送到FIFO，并接收卡返回的数据

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }
        
    if (status == MI_OK)
    {
        memcpy(ucComMF522Buf, pValue, 4);//拷贝内存内容
        //for (i=0; i<16; i++)
        //{    ucComMF522Buf[i] = *(pValue+i);   }
        CalulateCRC(ucComMF522Buf,4,&ucComMF522Buf[4]);
        unLen = 0;
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,6,ucComMF522Buf,&unLen);//需要修改的钱包和CRC16值发送至FIFO并返回结果和数据长度
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
//功    能：备份钱包
//参数说明: sourceaddr[IN]：源地址
//          goaladdr[IN]：目标地址
//返    回: 成功返回MI_OK
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



