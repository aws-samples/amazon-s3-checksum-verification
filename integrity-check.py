#!/usr/bin/env python3

from operator import concat
import boto3
import botocore
import base64
import hashlib
import argparse
import crc32c
import zlib
import sys

parser = argparse.ArgumentParser(description='Options for integrity validation')
parser.add_argument('--bucketName', required=True,
                    help='Name of the S3 bucket storing the objects')
parser.add_argument('--objectName', required=True,
                    help='Name, including any prefxies, of the S3 object to validate the integrity of in S3')
parser.add_argument('--localFileName', required=True,
                    help='Name of the local file to validate S3 integrity hashes against')

args = parser.parse_args()

def whichChecksum(objectSummary):

    try:
        checksumHashes = objectSummary['Checksum']
        for checksum in checksumHashes:

            return checksum
    except KeyError:
        print("\nChecksum is not enabled on the object. Please add checksums using the copy-object operation before validating checksums. See this documentation for more details, https://aws.amazon.com/blogs/aws/new-additional-checksum-algorithms-for-amazon-s3/\n")
        sys.exit(1)

def getObjectAttributes():

    try:
        s3 = boto3.client('s3')

        objectSummary = s3.get_object_attributes(Bucket=args.bucketName,Key=args.objectName,
            ObjectAttributes=[ 'Checksum','ObjectParts'
            ])

        return objectSummary
    except ( botocore.exceptions.ClientError, botocore.exceptions.PartialCredentialsError ):
        print("\nYou must authenticate with credentials that are allowed to read objects in the bucket the data you wish to validate is stored in.\n")
        sys.exit(1)

def localChecksumValidation(objectSummary):

    checksumAlgo = whichChecksum(objectSummary)
    if 'SHA' in checksumAlgo:
        return shaChecksums(objectSummary)
    if 'CRC' in checksumAlgo:
        return crcChecksums(objectSummary)

def crcChecksums(objectSummary):

    partOneSize = objectSummary['ObjectParts']['Parts'][0]['Size']
    checksumAlgo = whichChecksum(objectSummary)

    CHUNK_SIZE = partOneSize
    file_number = 1
    partHashListBase64 = []

    with open(args.localFileName, "rb") as f:
        chunk = f.read(CHUNK_SIZE)

        if checksumAlgo == 'ChecksumCRC32':
            while chunk:
                checksum = 0
                m = zlib.crc32(chunk, checksum)
                m = m.to_bytes((m.bit_length() + 7) // 8, 'big') or b'\0'

                # To print out individual part hashes comment the following line
                # print(base64.b64encode(m))

                partHashListBase64.append(m)
                file_number += 1
                chunk = f.read(CHUNK_SIZE)

            concatStr = b''.join(partHashListBase64)
            m = zlib.crc32(concatStr, checksum)
            m = m.to_bytes((m.bit_length() + 7) // 8, 'big') or b'\0'

        if checksumAlgo == 'ChecksumCRC32C':

            while chunk:
                checksum = 0
                m = crc32c.crc32c(chunk)
                m = m.to_bytes((m.bit_length() + 7) // 8, 'big') or b'\0'

                # To print out individual part hashes comment the following line
                # print(base64.b64encode(m))

                partHashListBase64.append(m)
                file_number += 1
                chunk = f.read(CHUNK_SIZE)

            concatStr = b''.join(partHashListBase64)
            m = crc32c.crc32c(concatStr)
            m = m.to_bytes((m.bit_length() + 7) // 8, 'big') or b'\0'

    return base64.b64encode(m).decode('utf-8')

def shaChecksums(objectSummary):

    partOneSize = objectSummary['ObjectParts']['Parts'][0]['Size']
    checksumAlgo = whichChecksum(objectSummary)

    CHUNK_SIZE = partOneSize
    file_number = 1
    partHashListBase64 = []
    
    with open(args.localFileName, "rb") as f:
        chunk = f.read(CHUNK_SIZE)
        while chunk:
            if checksumAlgo == 'ChecksumSHA256':
                m = hashlib.sha256()
            if checksumAlgo == 'ChecksumSHA1':
                m = hashlib.sha1()
            m.update(chunk)
            partHashListBase64.append(base64.b64encode(m.digest()))
            file_number += 1
            chunk = f.read(CHUNK_SIZE)
    
    if checksumAlgo == 'ChecksumSHA256':
        m = hashlib.sha256()
    if checksumAlgo == 'ChecksumSHA1':
        m = hashlib.sha1()
    for line in partHashListBase64:
        m.update(base64.b64decode(line))
    
    return base64.b64encode(m.digest()).decode('utf-8')

def s3checksumResult(objectSummary):

    checksumAlgo = whichChecksum(objectSummary)

    return objectSummary['Checksum'][checksumAlgo]
    
def main():
    objectSummary = getObjectAttributes()
    s3Checksum = s3checksumResult(objectSummary)
    localChecksum = localChecksumValidation(objectSummary)

    if s3Checksum == localChecksum:
        print('PASS: ' + whichChecksum(objectSummary) + ' match! - s3Checksum: ' + s3Checksum + ' | localChecksum: ' + localChecksum)
    else:
        print('FAIL: ' + whichChecksum(objectSummary) + ' DO NOT MATCH!')

if __name__ == '__main__':
    main()
