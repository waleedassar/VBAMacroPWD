import os,sys,time,string
import struct
import hashlib
from random import randint



def IsHexChar(CharX):
    if CharX != "0" and CharX != "1" and CharX != "2" and CharX != "3" and CharX != "4" and CharX != "5" and CharX != "6" and CharX != "7" and CharX != "8" and CharX != "9" and CharX != "A" and CharX != "a" and CharX != "B" and CharX != "b" and CharX != "C" and CharX != "c" and CharX != "D" and CharX != "d" and CharX != "E" and CharX != "e" and CharX != "F" and CharX != "f":
        return True
    return False

def PrintHash(Hash):
    if Hash == "":
        return ""
    HashStr = ""
    HashLen = len(Hash)
    for i in range(0,HashLen):
        A = (hex(ord(Hash[i])).lower())[2:]
        if len(A) == 1:
            A = ("0" + A)
        HashStr += A
    return HashStr



def Hexify(contentX):
    if len(contentX)==0:
        print "Input content is empty\r\n"
        return ""
    else:
        Second = False
        SkipNext = False
        FinalStr = ""
        NewStr = ""
        for X in contentX:
            if SkipNext == True:
                SkipNext = False
                continue
            if IsHexChar(X)==True:
                SkipNext = True
                continue
            if Second == False:
                NewStr+=X
                Second = True
            else:
                NewStr+=X
                FinalStr += "\\x"
                FinalStr += NewStr
                NewStr = ""
                Second = False
        
        #print FinalStr + "\r\n"
        XXX = "\"" + FinalStr + "\""
        outputX =  eval(XXX)
        return outputX



def GetMyPrintables():
    Printables = string.printable
    NewPrintables = ""
    lenPrintables = len(Printables)
    for i in range(0,lenPrintables):
        if ord(Printables[i]) >= 9 and ord(Printables[i]) <= 13:
            pass
        else:
            NewPrintables += Printables[i]
    return NewPrintables

def GetHexDumpStr(XXX):
    Printables = GetMyPrintables()
    if XXX == "":
        return ""
    lenX = len(XXX)
    if lenX == 0:
        return ""
    NewConn = ""
    i = 0
    while i < lenX:
        XX = XXX[i]
        if Printables.find(XX)==-1:
            NewConn += "."
        else:
            NewConn += XX
        i = i + 1
    return NewConn

def HexDump(Binary,Size=2,Sep=" "):
    if Binary == "":
        return ""
    lenX = len(Binary)
    if lenX == 0:
        return ""
    i = 0
    FinalCon = ""
    RawCon = ""
    HexCon = ""
    StrCon = ""
    c = 0
    d = 0
    while i < lenX:
        X = Binary[i]
        RawCon += X
        XX = struct.unpack("B",X)[0]
        XXX = (hex(XX))[2:]
        if len(XXX)==1:
            XXX = "0" + XXX
        HexCon += XXX
        c = c + 1
        HexCon += Sep
        if c == 8:
            HexCon += Sep
            c = 0
        d = d + 1
        if d == 16 or i == lenX-1:
            StrCon = GetHexDumpStr(RawCon)
            if len(StrCon) < 16:
                ToAdd = 16 - len(StrCon)
                StrCon += (" "*ToAdd)
            RawCon = ""
            if len(HexCon) < 51:
                ToAdd = 51-len(HexCon)
                HexCon += (" "*ToAdd)
            FinalCon += HexCon
            HexCon = ""
            FinalCon += " "
            FinalCon += StrCon
            StrCon = ""
            FinalCon += "\r\n"
            d = 0
        i = i + 1
    return FinalCon


def GetNumberOfNulls(Input):
    if Input == "":
        return 0
    Num = 0;
    InputLen = len(Input)
    for i in range(0,InputLen):
        if Input[i] == "\x00":
            Num += 1
    return Num


#takes input of type string
#returns input without nulls
def EncodeNulls(Key):
    if Key == "":
        return ""
    Num = GetNumberOfNulls(Key)
    if Num == 0:
        return Key

    KK = ""
    KLen = len(Key)
    for i in range(0,KLen):
        if Key[i] == "\x00":
            KK += "\x01"
        else:
            KK += Key[i]
    return KK




def GetGrbit(Input):
    KeyNoNulls = 0xFFFFFFFF
    Num = GetNumberOfNulls(Input)
    if Num == 0:
        return KeyNoNulls
    InputLen = len(Input)
    for i in range(0,InputLen):
        if Input[i] == "\x00":
            X = 0xFFFFFFFF ^ (1 << i)
            #print hex(X)
            KeyNoNulls = KeyNoNulls & X
    return KeyNoNulls

def GetGrbitKey(Input):
    KeyNoNulls = GetGrbit(Input) & 0xF
    return KeyNoNulls



def CreateHashStructure(Pwd,Key):
    Struc = ""
    Struc += "\xFF"
    sKey = struct.pack("L",Key)
    All = Pwd + sKey
    m = hashlib.sha1()
    m.update( All )
    Hash = m.digest()
    GrbitKey = GetGrbitKey(sKey)
    GrbithashNull = GetGrbit(Hash)
    BothGrbits = (GrbithashNull << 4 | GrbitKey) & 0x00FFFFFF
    BothGrbits_ = struct.pack("L",BothGrbits)
    Struc += BothGrbits_[0]
    Struc += BothGrbits_[1]
    Struc += BothGrbits_[2]
    KeyNoNulls = EncodeNulls(sKey)
    Struc += KeyNoNulls
    PasswordHashNoNulls = EncodeNulls(Hash)
    Struc += PasswordHashNoNulls
    Struc += "\x00"
    if len(Struc) != 29:
        return ""
    return Struc


def GetIgnoredLengthCMG(Len):
    if Len < 22:
        return 0
    return (Len - 22) / 2

def GetSeed():
    return randint(0,0xFF) 

def GetSeedX(Len):
    Seed = 0
    while(1):
        Seed = randint(0,0xFF)
        if (Seed & 6) / 2 == Len:
            break
    return Seed


#returns CMG string
def EncodeCMG(Value,Seed):
    CMG = ""

    Data = struct.pack("L",Value)
    DataLen = len(Data)
    
    #print "Seed: " + hex(Seed)

    CMG += chr(Seed)


    VersionEnc = Seed ^ 2
    #print "VersionEnc: " + hex(VersionEnc)
    CMG += chr(VersionEnc)

    ProjId = "{00000000-0000-0000-0000-000000000000}"
    ProjIdLen = len(ProjId)
    ProjKey  = 0
    for i in range(0,ProjIdLen):
        ProjKey += ord(ProjId[i])
    ProjKey = ProjKey & 0xFF
     
    #print "ProjKey: " + hex(ProjKey)

    ProjKeyEnc = ProjKey ^ Seed
    #print "ProjKeyEnc: " + hex(ProjKeyEnc)
    CMG += chr(ProjKeyEnc)



    UnencryptedByte1  = ProjKey
    EncryptedByte1  = ProjKeyEnc
    EncryptedByte2 = VersionEnc

    IgnoredLength = (Seed & 6) / 2
    print "IgnoredLength: " + str(IgnoredLength)


    #IgnoredEnc
    ByteEnc = 0
    IgnoredEnc = ""
    for i in range(0,IgnoredLength):
        TempValue = 228 #Any Value
        ByteEnc = ( (TempValue) ^ (EncryptedByte2 + UnencryptedByte1) ) & 0xFF
        IgnoredEnc += chr(ByteEnc)
        EncryptedByte2 = EncryptedByte1
        EncryptedByte1  = ByteEnc
        UnencryptedByte1  = 228 #Any Value

    
    CMG += IgnoredEnc


    #DataLengthEnc
    DataLengthEnc = ""
    DataLen_ = struct.pack("L",DataLen)
    for i in range(0,4):
        ByteEnc = ((ord(DataLen_[i])) ^ (EncryptedByte2 + UnencryptedByte1)) & 0xFF
        DataLengthEnc += chr(ByteEnc)
        EncryptedByte2 = EncryptedByte1
        EncryptedByte1  = ByteEnc
        UnencryptedByte1  = ord(DataLen_[i])

    CMG += DataLengthEnc

    
    #DataEnc
    DataEnc = ""
    Data_ = Data

    for i in range(0,DataLen):
        ByteEnc = ((ord(Data_[i])) ^ (EncryptedByte2 + UnencryptedByte1)) & 0xFF
        DataEnc += chr(ByteEnc)
        EncryptedByte2 = EncryptedByte1
        EncryptedByte1  = ByteEnc
        UnencryptedByte1  = ord(Data_[i])

    CMG += DataEnc
    return CMG






argC = len(sys.argv)
if argC != 2 and argC != 3:
    print "Usage: EncodeCMG.py Value\r\n"
    print "Usage: EncodeCMG.py Value <required length>\r\n"
    sys.exit(-1)


if (sys.argv[1]).isdigit() == False:
    print "Integer value expected\r\n"
    sys.exit(-2)

Value = int(sys.argv[1],10)

Seed = GetSeed()

if argC == 3:
    ReqLength = int(sys.argv[2],10)
    if ReqLength < 22:
        print "Invalid input length, must be 22, 24, 26, and so on\r\n"
        sys.exit(-3)
    else:
        print GetIgnoredLengthCMG(ReqLength)
        Seed = GetSeedX(GetIgnoredLengthCMG(ReqLength))
        
    




CMG = EncodeCMG(Value,Seed)
print "CMG: " + PrintHash(CMG).upper()
print "Done"
