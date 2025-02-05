import argparse, os.path
import binascii
from dataclasses import dataclass

parser = argparse.ArgumentParser(description='Hash extraction program from RAR files')
parser.add_argument('pathToFile', type=str, help='The path to the RAR file')
parser.add_argument('pathToOutFile', type=str, nargs='?', default="None", help='The path to write the hash to the file')

@dataclass
class StructArchV3:
    encryptType: int
    salt: bytes
    fileCRC: bytes
    compSize: int
    uncompSize: int
    fileBytes: bytes

# CONSTANTS
HEADER_END_ARCH = 5
HEADER_ARCH_V3 = 0x73
HEADER_FILE = 0x74
HEADER_SUBBLOCK = 0x7a
HEADMAIN = 1
HEADCRYPT = 4
HEADFILE = 2
HEADSERVICE = 3
HFBEXTRA = 1
HFBDATA = 2
UTIME = 0x0002
CRC32 = 0x0004
CRYPTPSWCHECK = 1
SIZE_PSWCHECK_CSUM = 4
EXTRACRYPT = 0x01
SIZE_HEADER_ARCH_V3 = 13
SIZE_SALT50 = 16
SIZE_SALT30 = 8
SIZE_PSWCHECK = 8
SIZE_INITV = 16
UINT16_SIZE = 2
UINT32_SIZE = 4
BLOCK_FTIME_SIZE = 4
BLOCK_UNP_VER_SIZE = 1
BLOCK_METHOD_SIZE = 1

magic_bytes_rar3 = b'\x52\x61\x72\x21\x1A\x07\x00'
magic_bytes_rar5 = b'\x52\x61\x72\x21\x1A\x07\x01\x00'
magic_bytes_sfx = b'\x4D\x5A'
# ---------

class HashCatRarExtractor(object):
    def __init__(self, pathToFile):

        self.__pathToFile = pathToFile
        self.__fileSize = 0
        self.__startPosition = 0

    def IsSupported(self):

        bytesArray = self.__ReadFileToByte(0, len(magic_bytes_rar5))

        if len(bytesArray) == 0:
            raise Exception(f'File {self.__pathToFile} does not exist!')

        if bytesArray != magic_bytes_rar5:
            bytesArray = self.__ReadFileToByte(0, len(magic_bytes_rar3))
        else:
            return [True, 5]

        if bytesArray != magic_bytes_rar3:
            bytesArray = self.__ReadFileToByte(0, len(magic_bytes_sfx))
        else:
            return [True, 3]

        if bytesArray == magic_bytes_sfx:
            print('Please wait, the archive version is being determined ....')

            if self.__DetermineVersionArchive(0, magic_bytes_rar5) == True:
                return [True, 5]
            elif self.__DetermineVersionArchive(0, magic_bytes_rar3) == True:
                return [True, 3]

        print(f'File {self.__pathToFile} is not RAR archive!')
        return [False, 0]

    def __ReadFileToByte(self, offset, blockSize):

        if self.__fileSize == 0:
            self.__fileSize = self.__GetFileSize()

        bytesArray = []

        if self.__fileSize > 0 and (offset + blockSize) <= self.__fileSize:

            try:
                fileHandler = open(self.__pathToFile, 'rb')
                fileHandler.seek(offset)
                bytesArray = fileHandler.read(blockSize)
                fileHandler.close()

            except Exception:
                raise Exception('Error reading the file!')

        return bytesArray

    def RecordFile(self, pathToOutFile, hash):

        if not(os.path.exists(pathToOutFile)):
            raise Exception('The file cannot be written, the specified path does not exist!')

        try:
            fileHandler = open(pathToOutFile + "ExtractedHash.txt", 'w')
            fileHandler.write(hash)
            fileHandler.close()

        except Exception:
            raise Exception('File recording error!')

    def __GetFileSize(self):

        if os.path.exists(self.__pathToFile) == True:
            return os.path.getsize(self.__pathToFile)

        return 0

    def __DetermineVersionArchive(self, offset, magic_bytes):

        if len(magic_bytes) == 0:
            return False
        else:
            blockSize = len(magic_bytes)

        i = offset

        while (i + len(magic_bytes_rar5)) < self.__fileSize:

            bytesArray = self.__ReadFileToByte(i, blockSize)

            if len(bytesArray) == 0:
                raise Exception('Error reading the file!')

            if bytesArray != magic_bytes:
                i += offset + len(magic_bytes_rar5)

            else:
                self.__startPosition = i
                return True

        return False

    def __ReadExtraFieldBlock(self, offset, sizeExtraField, typeHeader):

        counterBytes = 0
        rBytes = 0
        flag = [0]
        encryptVersion = [0]
        fieldSize = [0]
        fieldType = [0]
        lg2Count = [0]
        leftBytes = sizeExtraField[0]

        rBytes = self.__ReadVInt(offset, fieldSize)

        if rBytes == 0 or rBytes > 3:
            return "None"
        else:
            counterBytes += rBytes
            leftBytes -= rBytes

        if ((leftBytes - fieldSize[0]) < 0):
            return "None"
        else:
            leftBytes -= fieldSize[0]

        rBytes = self.__ReadVInt(offset + counterBytes, fieldType)

        if (rBytes == 0):
            return "None"
        else:
            counterBytes += rBytes

        if (typeHeader[0] == HEADFILE) or (typeHeader[0] == HEADSERVICE):

            if(fieldType[0] == EXTRACRYPT):
                rBytes = self.__ReadVInt(offset + counterBytes, encryptVersion)

                if (rBytes == 0):
                    return "None"
                else:
                    counterBytes += rBytes

                rBytes = self.__ReadVInt(offset + counterBytes, flag)

                if (rBytes == 0):
                    return "None"
                else:
                    counterBytes += rBytes

                if ((flag[0] & EXTRACRYPT) == 0):
                    return "None"

                rBytes = self.__ReadVInt(offset + counterBytes, lg2Count)

                if (rBytes == 0 or lg2Count[0] >= 24):
                    return "None"
                else:
                    counterBytes += rBytes

                salt = self.__ReadFileToByte(offset + counterBytes, SIZE_SALT50)

                if len(salt) > 0:
                    counterBytes += SIZE_SALT50
                else:
                    return "None"

                initv = self.__ReadFileToByte(offset + counterBytes, SIZE_INITV)

                if len(initv) > 0:
                    counterBytes += SIZE_INITV
                else:
                    return "None"

                psw = self.__ReadFileToByte(offset + counterBytes, SIZE_PSWCHECK)

                if len(psw) == 0:
                    return "None"

                return "$rar5${}${}${}${}${}${}".format(SIZE_SALT50, binascii.hexlify(salt).decode("ascii"),
                                                        lg2Count[0], binascii.hexlify(initv).decode("ascii"),
                                                        SIZE_PSWCHECK, binascii.hexlify(psw).decode("ascii"))

        return "None"

    def __ReadVInt(self, offset, result):

        limit = 0
        i = 0
        shift = 0
        limit = len(magic_bytes_rar5)

        while i <= limit:

            number = int.from_bytes(self.__ReadFileToByte(offset + i, 1), "little")
            conv = number & 0x7f
            result[0] = (result[0] + int(conv << shift))

            shift += 7
            i += 1

            if (number & 0x80) == 0:
                return i

        return 0

    def __ConvertInt8ToInt32(self, bytesArray):
        if (len(bytesArray) != UINT32_SIZE):
            return 0

        return (bytesArray[0] | (bytesArray[1] << 8) | (bytesArray[2] << 16) | (bytesArray[3] << 24))


    def __ConvertInt8ToInt16(self, bytesArray):
        if (len(bytesArray) != UINT16_SIZE):
            return 0

        return ((bytesArray[1] << 8) + bytesArray[0])

    def ExtractionHash(self, archive_version):

        offset = self.__startPosition
        blockSize = 0
        encryptType = -1
        i = 0

        if (archive_version == 3):
            blockSize = len(magic_bytes_rar3)

        elif (archive_version == 5):
            blockSize = len(magic_bytes_rar5)

        else:
            raise Exception('Unsupported archive version!')

        currentShift = offset + (blockSize - 1)
        numberOfReadBytes = 0

        hash = "None"
        mtime = 0
        dataCRC32 = 0

        archive = []

        while (i + blockSize) < self.__fileSize:

            typeHeader = [0]
            compSize = [0]
            uncompSize = [0]
            nameLen = [0]

            if archive_version == 5:

                sizeCurrHeader = [0]
                sizeExtraField = [0]
                flagHeader = [0]
                fileFlag = [0]
                fileAttributes = [0]
                compInfo = [0]
                hostOS = [0]
                encryptVersion = [0]
                encryptFlag = [0]
                lg2Count = [0]

                if i == 0:
                    crc32 = self.__ConvertInt8ToInt32(self.__ReadFileToByte(offset + blockSize, UINT32_SIZE))
                else:
                    crc32 = self.__ConvertInt8ToInt32(self.__ReadFileToByte(i, UINT32_SIZE))
                    currentShift = i

                if crc32 > 0 and i == 0:
                    i = (offset + blockSize) + UINT32_SIZE
                    currentShift += UINT32_SIZE

                elif crc32 > 0 and i > 0:
                    i += UINT32_SIZE
                    currentShift += UINT32_SIZE

                else:
                    raise Exception('Block CRC32 reading error!')

                counterBytes = self.__ReadVInt(i, sizeCurrHeader)

                if counterBytes > 0:
                    i += counterBytes
                    currentShift += counterBytes

                elif (sizeCurrHeader[0] == 0):
                    raise Exception('Block HeaderSize reading error!')

                counterBytes = self.__ReadVInt(i, typeHeader)

                if counterBytes > 0 or typeHeader[0] > 0:
                    i += counterBytes
                    currentShift += counterBytes

                else:
                    raise Exception('Block HeaderType reading error!')

                if typeHeader[0] == HEADER_END_ARCH:
                    return hash

                elif typeHeader[0] == HEADMAIN:
                    counterBytes = self.__ReadVInt(i, flagHeader)

                    if counterBytes > 0 or flagHeader[0] > 0:
                        i += counterBytes
                    else:
                        raise Exception('Block HeaderFlag reading error!')

                    if (flagHeader[0] & HFBEXTRA) != 0:
                        counterBytes = self.__ReadVInt(i, sizeExtraField)

                        if sizeExtraField[0] == 0:
                            raise Exception('Block SizeExtraField reading error!')
                        else:
                            i += counterBytes
                    else:
                        raise Exception('Block ExtraField reading error!')

                    i = currentShift + sizeCurrHeader[0]

                elif (typeHeader[0] == HEADFILE) or (typeHeader[0] == HEADSERVICE):

                    counterBytes = self.__ReadVInt(i, flagHeader)

                    if (counterBytes > 0) or (flagHeader[0] > 0):
                        i += counterBytes
                    else:
                        raise Exception('Block HeaderFlag reading error!')

                    if (flagHeader[0] & HFBEXTRA) != 0:
                        counterBytes = self.__ReadVInt(i, sizeExtraField)

                        if sizeExtraField == 0:
                            raise Exception('Block SizeExtraField reading error!')
                        else:
                            i += counterBytes

                    if (flagHeader[0] & HFBDATA) != 0:
                        counterBytes = self.__ReadVInt(i, compSize)

                        if (counterBytes == 0) or (compSize[0] == 0):
                            raise Exception('Block CompressionSize reading error!')
                        else:
                            i += counterBytes

                    counterBytes = self.__ReadVInt(i, fileFlag)

                    if counterBytes > 0:
                        i += counterBytes

                    if (fileFlag[0] == 0) and (typeHeader[0] != HEADSERVICE):
                        raise Exception('Block FileFlag reading error!')

                    counterBytes = self.__ReadVInt(i, uncompSize)

                    if counterBytes > 0 or uncompSize[0] > 0:
                        i += counterBytes
                    else:
                        raise Exception('Block UncompressSize reading error!')

                    counterBytes = self.__ReadVInt(i, fileAttributes)

                    if counterBytes > 0:
                        i += counterBytes

                    if (fileAttributes[0] == 0) and (typeHeader[0] != HEADSERVICE):
                        raise Exception('Block FileAttributes reading error!')

                    if (fileFlag[0] & UTIME) != 0:
                        mtime = self.__ConvertInt8ToInt32(self.__ReadFileToByte(i, UINT32_SIZE))

                        if (mtime == 0):
                            raise Exception('Block MTIME reading error!')
                        else:
                            i += UINT32_SIZE

                    if (fileFlag[0] & CRC32) != 0:
                        dataCRC32 = self.__ConvertInt8ToInt32(self.__ReadFileToByte(i, UINT32_SIZE))

                        if (dataCRC32 == 0):
                            raise Exception('Block DATACRC32 reading error!')
                        else:
                            i += UINT32_SIZE

                    counterBytes = self.__ReadVInt(i, compInfo)

                    if counterBytes > 0:
                        i += counterBytes

                    counterBytes = self.__ReadVInt(i, hostOS)

                    if counterBytes > 0:
                        i += counterBytes

                    counterBytes = self.__ReadVInt(i, nameLen)

                    if counterBytes > 0:
                        i += counterBytes

                    if sizeExtraField[0] > 0:
                        hash = self.__ReadExtraFieldBlock(i + nameLen[0], sizeExtraField, typeHeader)

                    if hash != "None":
                        return hash
                    else:
                        i = currentShift + sizeCurrHeader[0] + compSize[0]


                elif (typeHeader[0] == HEADCRYPT):

                    usePswCheck = 0

                    counterBytes = self.__ReadVInt(i + 1, encryptVersion)

                    if counterBytes > 0:
                        i += counterBytes + 1

                    if (encryptVersion[0] > 0):
                        raise Exception('Block ENCRYPT_VERSION reading error!')

                    counterBytes = self.__ReadVInt(i, encryptFlag)

                    if counterBytes > 0:
                        i += counterBytes

                    if (encryptFlag[0] & CRYPTPSWCHECK != 0):
                        usePswCheck = encryptFlag[0] & CRYPTPSWCHECK

                    counterBytes = self.__ReadVInt(i, lg2Count)

                    if counterBytes > 0:
                        i += counterBytes

                    if (lg2Count[0] > 24):
                        raise Exception('Block LG2_COUNT reading error!')

                    salt = self.__ReadFileToByte(i, SIZE_SALT50)

                    if len(salt) > 0:
                        i += SIZE_SALT50
                    else:
                        raise Exception('Block SIZE_SALT reading error!')

                    if (usePswCheck == 1):
                        psw = self.__ReadFileToByte(i, SIZE_PSWCHECK)

                        if len(psw) > 0:
                            i += SIZE_PSWCHECK
                        else:
                            raise Exception('Block SIZE_PSWCHECK reading error!')

                        checkSum = self.__ReadFileToByte(i, SIZE_PSWCHECK_CSUM)

                        if len(checkSum) > 0:
                            i += SIZE_PSWCHECK_CSUM
                        else:
                            raise Exception('Block SIZE_PSWCHECK_CSUM reading error!')

                        initv = self.__ReadFileToByte(i, SIZE_INITV)

                        if len(initv) > 0:
                            i += SIZE_INITV
                        else:
                            return "None"

                        return "$rar5${}${}${}${}${}${}".format(SIZE_SALT50, binascii.hexlify(salt).decode("ascii"),
                                                                 lg2Count[0], binascii.hexlify(initv).decode("ascii"),
                                                                SIZE_PSWCHECK, binascii.hexlify(psw).decode("ascii"))

                    i = currentShift + sizeCurrHeader[0]


            elif archive_version == 3:
                
                if i == 0:
                    crc16 = self.__ConvertInt8ToInt16(self.__ReadFileToByte(offset + blockSize, UINT16_SIZE))
                else:
                    crc16 = self.__ConvertInt8ToInt16(self.__ReadFileToByte(i, UINT16_SIZE))
                    currentShift = i

                if crc16 > 0 and i == 0:
                    i = (offset + blockSize) + UINT16_SIZE
                    currentShift = blockSize

                elif crc16 > 0 and i > 0:
                    i += UINT16_SIZE

                else:
                    raise Exception('Block CRC16 reading error!')

                counterBytes = self.__ReadVInt(i, typeHeader)

                if counterBytes > 0 and typeHeader[0] > 0:
                    i += counterBytes

                else:
                    raise Exception('Block HeaderType reading error!')

                unionBytes = lambda byteArray: ((byteArray[1] << 8) | byteArray[0])

                if (typeHeader[0] == HEADER_ARCH_V3):

                    headerFlag = unionBytes(self.__ReadFileToByte(i, UINT16_SIZE))

                    if (headerFlag & 0x0080):
                        encryptType = 0
                        i += UINT16_SIZE
                    else:
                        encryptType = 1
                        i += UINT16_SIZE

                    sizeHeader = unionBytes(self.__ReadFileToByte(i, UINT16_SIZE))

                    if sizeHeader == 0:
                        raise Exception('Block SizeHeader reading error!')

                    elif sizeHeader > SIZE_HEADER_ARCH_V3:
                        numberOfReadBytes = i + (sizeHeader - SIZE_HEADER_ARCH_V3) + currentShift
                        i = currentShift + (sizeHeader - SIZE_HEADER_ARCH_V3)

                    else:
                        numberOfReadBytes = i + sizeHeader + currentShift

                        if(offset > 0):
                            i = offset + currentShift + sizeHeader
                        else:
                            i = currentShift + sizeHeader


                elif (typeHeader[0] == HEADER_FILE):

                    headerFlag = unionBytes(self.__ReadFileToByte(i, UINT16_SIZE))

                    if not(headerFlag & 0x8000):
                        raise Exception('Block HeaderFlag reading error!')
                    else:
                        i += UINT16_SIZE

                    sizeHeader = unionBytes(self.__ReadFileToByte(i, UINT16_SIZE))

                    if sizeHeader == 0:
                        raise Exception('Block SizeHeader reading error!')
                    else:
                        i += UINT16_SIZE

                    extTimeSize = sizeHeader - (numberOfReadBytes - offset)

                    if headerFlag == 0x10:
                        i = currentShift + sizeHeader
                        continue

                    compSize[0] = self.__ConvertInt8ToInt32(self.__ReadFileToByte(i, UINT32_SIZE))
                    i += UINT32_SIZE

                    uncompSize[0] = self.__ConvertInt8ToInt32(self.__ReadFileToByte(i, UINT32_SIZE))
                    i += UINT32_SIZE

                    fileCRC = self.__ReadFileToByte(i + 1, UINT32_SIZE)

                    if (len(fileCRC) == 0):
                        raise Exception('Block FileCRC reading error!')
                    else:
                        i += UINT32_SIZE + 1

                    nameLen[0] = self.__ConvertInt8ToInt16(self.__ReadFileToByte((i + BLOCK_FTIME_SIZE + BLOCK_UNP_VER_SIZE + BLOCK_METHOD_SIZE), UINT16_SIZE))

                    if (nameLen[0] == 0):
                        raise Exception('Block NameSize reading error!')
                    else:
                        i += BLOCK_FTIME_SIZE + BLOCK_UNP_VER_SIZE + BLOCK_METHOD_SIZE + UINT16_SIZE

                    extTimeSize -= nameLen[0]

                    if (((headerFlag & 0xe0) >> 5) == 7): #If directory
                        if (compSize[0] != 0 or uncompSize[0] != 0):
                            raise Exception('Block HeaderFlag reading error!')

                        if ((currentShift + sizeHeader + blockSize) < self.__fileSize):
                            i = currentShift + sizeHeader
                            continue

                    if (headerFlag & 0x400):
                        extTimeSize -= SIZE_SALT30
                        salt = self.__ReadFileToByte(currentShift + (numberOfReadBytes - offset) + nameLen[0], SIZE_SALT30)

                        if len(salt) == 0:
                            raise Exception('Block Salt reading error!')
                        else:
                            i = currentShift + sizeHeader + compSize[0]

                        compFile = self.__ReadFileToByte((currentShift + (numberOfReadBytes - offset) + nameLen[0] + SIZE_SALT30 + extTimeSize), compSize[0])
                        archive.append(StructArchV3(encryptType=encryptType, salt=salt, fileCRC=fileCRC, compSize=compSize[0], uncompSize=uncompSize[0], fileBytes=compFile))


                    if (currentShift + (numberOfReadBytes - offset) + nameLen[0] + SIZE_SALT30 + extTimeSize + compSize[0] + blockSize) >= self.__fileSize:

                        numCurrentArch = 0

                        if (len(archive) > 1):
                            i = 0

                            while i < (len(archive) / 2):
                                if (archive[numCurrentArch].compSize > archive[i + 1].compSize):
                                    i += 1
                                    numCurrentArch = i
                                else:
                                    i += 1

                        if (archive[numCurrentArch].compSize / 1024) > 300:
                            print("WARNING! The hash extracted from files larger than 300 KB cannot be matched "
                                    "in the Hashcat")

                        return "$RAR3$*{}*{}*{}*{}*{}*{}*{}*33".format(str(archive[numCurrentArch].encryptType), binascii.hexlify(archive[numCurrentArch].salt).decode("ascii"),
                                                                binascii.hexlify(archive[numCurrentArch].fileCRC).decode("ascii"), str(archive[numCurrentArch].compSize), str(archive[numCurrentArch].uncompSize),
                                                                str(archive[numCurrentArch].encryptType), binascii.hexlify(archive[numCurrentArch].fileBytes).decode("ascii"))


                elif(typeHeader[0] == HEADER_SUBBLOCK):
                    return hash

                elif(encryptType == 0):

                    salt = self.__ReadFileToByte(currentShift, SIZE_SALT30)

                    if(len(salt) == 0):
                        raise Exception('Block Salt reading error!')

                    blockBytes = self.__ReadFileToByte(self.__fileSize - SIZE_SALT50, SIZE_SALT50)

                    if(len(blockBytes) == 0):
                        raise Exception('Failed read the last 16 bytes the archive!')

                    return "$RAR3$*{}*{}*{}".format(str(encryptType), binascii.hexlify(salt).decode("ascii"), binascii.hexlify(blockBytes).decode("ascii"))


        return hash


if __name__ == '__main__':

    args = parser.parse_args()
    extractor = HashCatRarExtractor(args.pathToFile)

    listIsSupported = extractor.IsSupported()
    hash = "None"

    if (listIsSupported[0]):

        if (listIsSupported[1] == 3):
            print('Defined as RAR3 archive...')
            print('')

            hash = extractor.ExtractionHash(listIsSupported[1])

        elif (listIsSupported[1] == 5):
            print('Defined as RAR5 archive...')
            print('')

            hash = extractor.ExtractionHash(listIsSupported[1])

        if (hash == "None"):
            print('Hash extraction error, archive file may be corrupted!')
        else:
            if (args.pathToOutFile != "None"):
                extractor.RecordFile(args.pathToOutFile, hash)
                print('The extracted hash has been successfully saved to a file!')
            else:
                print(f'Extracted hash: {hash}')

    else:
        print('Files of this type are not supported!')