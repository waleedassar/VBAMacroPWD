import os,sys,time,string
import struct
import hashlib
import re
from random import randint
import zipfile


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



def ApplyNulls(K,Bitmap):
    if K == "":
        return ""
    
    KLen = len(K)
    KK = ""
    ii = 0
    for i in range(KLen,0,-1):
        Y = 1 << (i-1)
        if Bitmap & Y == 0:
            KK += "\x00"
        else:
            KK += K[ii]
        ii += 1
    return KK
            
    


    
#returns Password Hash Data Structure
def Decode(In,InLen):
    if In == "" or InLen == 0 or len(In) != InLen:
        return ""

    hxIN = Hexify(In)
    if hxIN == "":
        return ""
    hxLength = len(hxIN)
    if hxLength < 3:
        return ""
  
    Seed = ord(hxIN[0])
    print ">> Seed: " + hex(Seed)


    VersionEnc = ord(hxIN[1])
    print "VersionEnc: " + hex(VersionEnc)
    Version = Seed ^ VersionEnc
    print ">> Version: " + hex(Version)
    if Version != 2:
        print "Invalid version"
        return ""

    ProjKeyEnc = ord(hxIN[2])
    print "ProjKeyEnc: " + hex(ProjKeyEnc)
    ProjKey = Seed ^ ProjKeyEnc
    print ">> Project Key: " + hex(ProjKey)


    UnencryptedByte1  = ProjKey
    EncryptedByte1  = ProjKeyEnc
    EncryptedByte2 = VersionEnc

    IgnoredLength = (Seed & 6) / 2
    print ">> IgnoredLength: " + str(IgnoredLength)
    if IgnoredLength + 3 > hxLength:
        return ""
    Off = 3

    
    IgnoredEnc = hxIN[Off:Off+IgnoredLength]
    Off += IgnoredLength
    
    AllIgnored = []
    for X in IgnoredEnc:
        Byte = ( (ord(X) ) ^ ( (EncryptedByte2 + UnencryptedByte1) & 0xFF))
        EncryptedByte2 = EncryptedByte1
        EncryptedByte1 = ord(X)
        UnencryptedByte1 = Byte
        AllIgnored.append(Byte)
    print ">> Ignored: " + str(AllIgnored)
    
    Left = hxLength - Off
    #print Left
    if Left < 4:
        return ""
    
    Rest = hxIN[Off:]
    DataLengthEnc = Rest[0:4]
    DataEnc = Rest[4:]

    DataLength = 0
    
    ByteIndex = 0
    
    for ByteEnc  in DataLengthEnc:
        Byte = (  (ord(ByteEnc))   ^ ( (EncryptedByte2 + UnencryptedByte1)& 0xFF ))
        TempValue = int(pow(256, ByteIndex))
        #print TempValue
        #print type(TempValue)
        TempValue = TempValue * Byte
        DataLength += TempValue
        EncryptedByte2  = EncryptedByte1
        EncryptedByte1 = ord(ByteEnc) & 0xFF
        UnencryptedByte1 = Byte
        ByteIndex = ByteIndex + 1



    #print hex(DataLength)
    if DataLength != len(DataEnc):
        print "Invalid data length"
        return ""
    Data = ""
    for ByteEnc in DataEnc:
        Byte =  (  (ord(ByteEnc))    ^ ((EncryptedByte2 + UnencryptedByte1)& 0xFF )  )
        Data += chr(Byte)
        EncryptedByte2 = EncryptedByte1
        EncryptedByte1 = ord(ByteEnc) & 0xFF
        UnencryptedByte1 = Byte
    return Data






#return Key and Hash separated by :
def DecodeHashStructure(Struc):
    if Struc == "":
        return ""
    if len(Struc) != 29:
        return ""
    StrucLen = len(Struc)
    Reserved = ord(Struc[0])
    #print "Reserved: " + hex(Reserved)
    if Reserved != 0xFF:
        return ""

    A = Struc[1]
    B = Struc[2]
    C = Struc[3]
    
    BothGrbits = (struct.unpack("=L","\x00" + C + B + A)[0]) >> 8

    
    GrbitKey = ( ord(A) >> 4) & 0xF
    GrbitKey_Again = (BothGrbits >> 20) & 0xF
    #print "GrbitKey: " + hex(GrbitKey)
    #print "GrbitKey_Again: " + hex(GrbitKey_Again)

    GrbitHashNull  = BothGrbits & 0xFFFFF 
    #print "GrbitHashNull: " + hex(GrbitHashNull)

    KeyNoNulls = Struc[4:8]
    #print "KeyNoNulls: " + PrintHash(KeyNoNulls)

    Key = PrintHash(ApplyNulls(KeyNoNulls,GrbitKey))
    #print "Key: " + Key

    HashNoNulls = Struc[8:28]
    #print "HashNoNulls: " + PrintHash(HashNoNulls)
    Hash = PrintHash(ApplyNulls(HashNoNulls,GrbitHashNull))
    #print "Hash: " + Hash

    Terminator = ord(Struc[28:29])
    if Terminator != 0:
        return ""
    return Key + ":" + Hash

#Extract salt
def GetKey(Data):
    if Data == "":
        return ""
    Both_x = Data.split(":")
    if len(Both_x) == 0:
        return ""
    return Both_x[0]
    

#Extract Password Hash
def GetPasswordHash(Data):
    if Data == "":
        return ""
    Both_x = Data.split(":")
    if len(Both_x) < 2:
        return ""
    return Both_x[1]
    


def TestPassword(Pwd,Key,Hash):
    All = Pwd + Hexify(Key)
    m = hashlib.sha1()
    m.update( All )
    cHash = PrintHash(m.digest())
    if cHash.lower() == Hash.lower():
        return True
    return False


def ExtractOffice2007(inFile):
    if inFile == "":
        return 0
    filenameX,fileextX = os.path.splitext(inFile)
    try:
        ZipZ = zipfile.ZipFile(inFile)
        ZipZ.extractall(filenameX)
        ZipZ.close()
        print "Zip file was successfully extracted to " + "\\" + filenameX +"\\"
    except:
        print "Zip file is corrupt"
        return 0
    return 1


def GetOffice2007VbaBin(inFile):
    if inFile == "":
        return ""
    ret = ExtractOffice2007(inFile)
    if ret == 0:
        return ""
    filenameX,fileextX = os.path.splitext(inFile)
    dirX = filenameX
    for fYf in os.listdir(dirX):
        tgt = dirX + "\\" + fYf
        if os.path.isfile(tgt)==False and os.path.exists(tgt + "\\vbaproject.bin")==True:
            return tgt + "\\vbaproject.bin"
    return ""

def IsOffice2007(inFile):
    if inFile == "":
        return False

    if os.path.getsize(inFile) < 4:
        return False
    
    fInZ = open(inFile,"rb")
    fConZ = fInZ.read(4)
    fInZ.close()

    if fConZ[0]!="P" or fConZ[1]!="K":
        return False

    mjv = fConZ[2]
    mnv = fConZ[3]

    v1 = (mjv == "\x03" and mnv == "\x04")
    v2 = (mjv == "\x05" and mnv == "\x06")
    v3 = (mjv == "\x07" and mnv == "\x08")
    if v1 == False and v2 == False and v3 == False:
        return False
    return True



#################################################

argC = len(sys.argv)
if argC != 3:
    print "Usage: CrackDPB.py File.doc passwordlist.txt\r\n"
    sys.exit(-1)

inF = sys.argv[1]
if os.path.exists(inF) == False:
    print "Input file does not exist\r\n"
    sys.exit(-2)


Office2007 = False
VbaBinFile = ""

if IsOffice2007(inF) == True:
    Office2007 = True


if Office2007 == True:
    VbaBinFile = GetOffice2007VbaBin(inF) #Will also extract zip contents
    if VbaBinFile == "":
        print "VbaProject.bin was not found in input Office2007 file\r\n"
        sys.exit(-3)
    inF = VbaBinFile




fDoc = open(inF,"rb")
inDoc = fDoc.read()
fDoc.close()







fList = open(sys.argv[2],"r")
Lines = fList.readlines()
fList.close()

if inDoc.find("DPB=") == -1:
    print "DPB value was not found in " + sys.argv[1] + "\r\n"
    sys.exit(-2)

III = re.findall("DPB=\"([0-9a-zA-Z]{72,})\"",inDoc,re.IGNORECASE)
All =  III[0]
if All == "":
    print "Found DPB value is empty\r\n"
    sys.exit(-3)


print "DPB: " + All



Input = All
InputLength = len(Input)

Data = Decode(Input,InputLength)
if Data == "":
    print "DPB value has no hash\r\n"
    sys.exit(-4)
else:
    print HexDump(Data)
    KeyNHash = DecodeHashStructure(Data)
    #print KeyNHash
    Key = GetKey(KeyNHash)
    print "Key: " + Key
    Hash = GetPasswordHash(KeyNHash)
    print "Hash: " + Hash
    #Start cracking here
    PassFound = False
    for Line in Lines:
        if TestPassword(Line.rstrip(),Key,Hash) == True:
            print "Password: " + Line
            PassFound = True

    if PassFound == False:
        print "Password not found, please provide another password list\r\n"
    

print "Done"
